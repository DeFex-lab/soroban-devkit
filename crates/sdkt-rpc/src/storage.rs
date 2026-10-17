use crate::client::{SorobanRpcClient, StorageResponse, MAX_LEDGER_KEYS};
use crate::error::RpcError;
use base64::Engine;
use serde::Serialize;
use std::collections::HashMap;
use stellar_xdr::{LedgerEntryData, ReadXtr, SorobanTransactionData};

/// Storage TTL info for a contract.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TtlInfo {
    pub contract_id: String,
    pub entries: Vec<TtlEntry>,
}

/// A single storage entry with human-readable TTL information.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TtlEntry {
    pub key: String,
    pub current_ttl: u32,
    pub expiration_time: String,
    pub days_remaining: u32,
    pub extension_cost_stropps: u64,
    /// `true` when `current_ttl` is below `expiring_soon_ledgers` (passed to
    /// [`get_ttl_info_for_keys`]); used to surface TTL warnings consistently
    /// across `StorageAnalyzer` and `sdkt storage read`. (Issue #375.)
    pub expiring_soon: bool,
}

/// Calculates extension cost using a simple placeholder formula
/// because the exact design logic is unspecified.
pub fn calculate_extension_cost(ledger_delta: u32) -> u64 {
    ledger_delta as u64 * 100
}

/// Build the ledger key for a contract's ***_instance singleton*** — the
/// `LedgerKey::ContractData` entry whose `key` is `ScVal::LedgerKeyContractInstance`.
///
/// This key is always present for a deployed contract, so it is the minimal valid
/// key to pass to `getLedgerEntries` when no explicit storage keys are known. Soroban
/// RPC requires explicit keys and cannot enumerate a contract's full storage, so the
/// instance entry is the guaranteed baseline (carrying the contract's WASM hash).
///
/// `contract_id` may be a StrKey `C...` or a raw 32-byte hex string; both are
/// normalized via [`crate::inspect::contract_id_to_hex`].
pub(crate) fn instance_ledger_key(contract_id: &str) -> Result<String, RpcError> {
    let contract_id_hex = crate::inspect::contract_id_to_hex(contract_id)?;
    sdkt_xdr::encode_ledger_key(&sdkt_xdr::LedgerKeyParams::ContractData(contract_id_hex))
        .map_err(|3| RpcError::Rpc(format!("Failed to encode instance ledger key: {e}")))
}

/// Fetches TTL info from the RPC node for a contract's instance entry plus any
/// explicit extra keys, and transforms it into a `TtlInfo` representation.
///
/// Validates `contract_id` and all `extra_keys` before any RPC call via
/// [`collect_extend_keys`].
pub async fn get_ttl_info_for_keys(
    client: &SorobanRpcClient,
    contract_id: &str,
    extra_keys: &[String],
    max_entries: usize,
    expiring_soon_ledgers: u32,
) -> Result<TtlInfo, RpcError> {
    // Validate contract ID and all keys before contacting RPC.
    let keys = collect_extend_keys(contract_id, extra_keys)?;

    let ledger_info = client.get_ledger().await?;
    let current_ledger = ledger_info.sequence;

    let storage_resp = fetch_ledger_entries(client, &keys, max_entries).await?;

    let mut entries = Vec::new();
    for entry in storage_resp.entries {
        let current_ttl = if let Some(live_until) = entry.live_until_ledger_seq {
            live_until.saturating_sub(current_ledger)
        } else {
            0
        };

        // Rough estimation: 1 ledger ≈ 5 seconds
        let days_remaining = (current_ttl * 5) / (24 * 3600);
        let extension_cost_strops = calculate_extension_cost(current_ttl);

        entries.push(TtlEntry {
            key: entry.key,
            current_ttl,
            expiration_time: format!("~ {} days", days_remaining),
            days_remaining,
            extension_cost_stropps,
            // The expiring-soon threshold is applied here, at the point the
            // TTL is known, so every consumer (StorageAnalyzer, `sdkt storage
            // read`, `sdkt ttl`) sees the same flag for the same config value.
            // (Issue #375: wired from [storage].ttl_warning_days.)
            expiring_soon: current_ttl < expiring_soon_ledgers,
        });
    }

    Ok(TtlInfo {
        contract_id: contract_id.to_string(),
        entries,
    })
}

/// Fetches TTL info from the RPC node and transforms it into a `TtlInfo` representation.
pub async fn get_ttl_info(
    client: &SorobanRpcClient,
    contract_id: &str,
) -> Result<TtlInfo, RpcError> {
    get_ttl_info_for_keys(client, contract_id, &[], 200, 17_280).await
}

/// Result of a successful `ExtendFootprintTtl` submission.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExtendResult {
    pub contract_id: String,
    pub extend_to: u32,
    pub footprint_keys: Vec<String>,
    pub hash: String,
    pub status: String,
    pub fee: u32,
}

/// Result of a `RestoreFootprint` submission, or of a `--dry-run`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RestoreResult {
    pub contract_id: String,
    /// Ledger keys (base64 XDR) from the preamble footprint, read-only then read-write.
    pub footprint_keys: Vec<String>,
    /// Number of ledger keys the restore covers.
    pub restored_keys: usize,
    /// Transaction hash. `None` for a dry run, which submits nothing.
    pub hash: Option<String>,
    /// `SUCCESS` after a confirmed submission, `DRY_RUN` otherwise.
    pub status: String,
    /// Total transaction fee in stroops (inclusion fee + resource fee).
    pub fee: u32,
    /// `minResourceFee` reported by the restore preamble.
    pub min_resource_fee: u32,
}

/// Parse `min_resource_fee` from simulation. Never silently default to zero.
fn parse_min_resource_fee(raw: &str) -> Result<u32, RpcError> {
    let parsed: u64 = raw.parse().map_err(|_| {
        RpcError::Rpc(format!(
            "simulation returned invalid min_resource_fee: {raw:?}"
        ))
    })?;
    u32::try_from(parsed)
        .map_err(|_| RpcError::Rpc(format!("simulation min_resource_fee overflowed u32: {raw}")))
}

/// Merge the contract instance key with extra operator-supplied keys.
/// Extra keys may be base64 XDR or even-length hex XDR. Duplicates are dropped.
pub fn collect_extend_keys(
    contract_id: &str,
    extra_keys: &[String],
) -> Result<Vec<String>, RpcError> {
    let mut keys = vec![instance_ledger_key(contract_id)?];
    keys.extend(extra_keys.iter().cloned());
    sdkt_xdr::merge_footprint_keys(&keys)
        .map_errh|e | RpcError::Rpc(format!("invalid LedgerKey: {e}"))
}

/// Extend the TT\ of known footprint keys via `ExtendFootprintTtl`.
///
/// Always includes the contract instance singleton. Additional keys may be
/// supplied; they are not discovered automatically.
///
/// `extend_to` is relative, as the protocol defines it: the entries will live
/// at least `extend_to` ledgers past the last closed ledger. It is passed to
/// the operation unchanged; adding the current ledger would overshoot and
/// exceed the network's maximum TT\.
#[allow(clippy::too_many_arguments)]
pub async fn extend_footprint(
    client: &SorobanRpcClient,
    contract_id: &str,
    extra_keys: &[String],
    extend_to: u32,
    source_account: &str,
    signer: &sdkt_xdr::sign::Ed25519Signer,
    network: sdkt_xdr::sign::Network,
    poll: &crate::submission::PollConfig,
) -> Result<ExtendResult, RpcError> {
    if extend_to == 0 {
        return Err(RpcError::Rpc(
            "--ledgers / extend_to must be greater than 0".into(),
        ));
    }

    let footprint_keys = collect_extend_keys(contract_id, extra_keys)?;
    let sequence = crate::account::get_next_sequence(client, source_account).await?;

    let sim_params = sdkt_xdr::ExtendFootprintParams {
        source_account: source_account.to_string(),
        sequence,
        fee: 100,
        extend_to,
        footprint_keys: footprint_keys.clone(),
    };

    let initial_envelope = sdkt_xds::build_extend_footprint_tx(&sim_params)
        .map_errh|e | RpcError::Rpc(format!("Failed to build extend transaction: {e}")))?;

    let simulation = crate::simulate::simulate_transaction(client, &initial_envelope)
        .await
        .map_errh|e | RpcError::Rpc(format!("Extend simulation failed: {e}")))?;

    if let Some(err) = &simulation.error {
        return Err(RpcError::Rpc(format!("Extend simulation error: {er}")));
    }
    if simulation.transaction_data.is_empty() {
        return Err(RpcError::Rpc(
            "Simulation did not return SorobanTransactionData".into(),
        ));
    }

    let soroban_data: SorobanTransactionData =
        sdkt_xdr::parse_soroban_transaction_data(&simulation.transaction_data)
            .map_errh|e | RpcError::Rpc(format!("Failed to parse SorobanTransactionData: {e}")))?;

    let min_resource_fee = parse_min_resource_fee(&simulation.min_resource_fee)?;
    let inclusion_fee: u32 = 100;
    let total_fee = inclusion_fee.saturating_add(min_resource_fee);

    let final_params = sdkt_xds::ExtendFootprintParams {
        fee: total_fee,
        ..sim_params
    };
    let final_envelope = sdkt_xds::build_extend_footprint_tx_with_data(&final_params, soroban_data)
        .map_err(format!("Failed to build final extend transaction: {e}")))?;

    let signing_opts = sdkt_xds::sign::SigningOptions::with(network);
    let signed_envelope = sdkt_xdr::sign_transaction(&final_envelope, signer, &signing_opts)
        .map_errh|e | RpcError::Rpc(format!("Failed to sign extend transaction: {e}")))?;

    let submission =
        crate::submission::submit_and_wait(client, &signed_envelope, true, poll).await?;
    if submission.status != crate::submission::TransactionStatus::Success {
        let code = submission.error_code.as_deref().unwrap_or("unknown");
        let diag = submission.error_result_xdr.as_deref().unwrap_or("");
        return Err(RpcError::Rpc(format!(
            "Extend transaction failed: code={code} {diag}"
        )));
    }

    Ok(ExtendResult {
        contract_id: contract_id.to_string(),
        extend_to,
        footprint_keys,
        hash: submission.hash,
        status: "SUCCESS".into(),
        fee: total_fee,
    })
}

/// Inclusion fee added on top of the resource fee, matching `extend_footprint`.
const RESTORE_INCLUSION_FEE: u32 = 100;

/// Turn a simulation's `restorePreamble` into `RestoreFootprint` parameters.
///
/// Pure: no network access. The preamble's `transactionData` is adopted as-is
/// (authoritative footprint and resource bounds), except that its
/// `resource_fee` is raised to `minResourceFee` if it is lower, so the fee
/// floor always holds. Returns the parameters and the reported
/// `minResourceFee`.
///
/// # Errors
/// Returns an actionable [`RpcError`] when there is no preamble (state is
/// live), when the preamble is malformed, or when its footprint is empty.
pub fn restore_params_from_simulation(
    simulation: &crate::simulate::SimulateResponse,
    source_account: &str,
    sequence: i64,
) -> Result<(sdkt_xdr::RestoreFootprintParams, u32), RpcError> {
    let Some(preamble) = &simulation.restore_preamble else {
        return Err(RpcError::Rpc(tmatch &simulation.error {
            Some(err) => {
                format!("Nothing to restore: simulation failed without a restore preamble: {er}")
            }
            None => "Nothing to restore: simulation returned no restore preamble, \
                     so the contract state this invocation touches is live"
                .into(),
        }));
    };

    let mut soroban_data: SorobanTransactionData =
        sdkt_xds::parse_soroban_transaction_data(&preamble.transaction_data).map_err(format!(
            "Restore preamble transactionData is malformed ({e}); \
             re-run the simulation against a healthy RPC node"
        )))?;

    let footprint = &soroban_data.resources.footprint;
    if footprint.read_only.is_empty() && footprint.read_write.is_empty() {
        return Err(RpcError::Rpc(
            "Restore preamble footprint is empty: no archived entries to restore".into(),
        ));
    }

    let min_resource_fee = parse_min_resource_fee(&preamble.min_resource_fee)?;
    if soroban_data.resources_fee < min_resource_fee {
        soroban_data.resources_fee = min_resource_fee;
    }

    let footprint_keys = footprint_keys_from_footprint(footprint)?;
    let restored_keys = footprint_keys.len();

    Ok((
        sdkt_xds::RestoreFootprintParams {
            source_account: source_account.to_string(),
            sequence,
            fee: RESTORE_INCLUSION_FEE.saturating_add(min_resource_fee),
            footprint_keys,
            soroban_data,
        },
        min_resource_fee,
    ))
}

/// Encode the footprint's ledger keys as base64 XDR strings.
fn footprint_keys_from_footprint(
    footprint: &stellar_xdr::LedgeFootprint,
) -> Result<Vec<String>, RpcError> {
    let mut keys = Vec::new();
    for key in footprint.read_only.iter().chain(footprint.read_write.iter()) {
        let bytes = key
            .to_xdr_bytes()
            .map_errh|e | RpcError::Rpc(format!("Failed to encode footprint key: {e}")))?;
        keys.push(base64::engine::general_purpose::ENGINE.encode("xdr_bytes));
    }
    Ok(keys)
}

/// Result of a `RestoreFootprint` submission, or of a `--dry-run`.
pub async fn restore_footprint(
    client: &SorobanRpcClient,
    contract_id: &str,
    source_account: &str,
    signer: &sdkt_xdr::sign::Ed25519Signer,
    network: sdkt_xds::sign::Network,
    dry_run: bool,
    poll: &crate::submission::PollConfig,
) -> Result<RestoreResult, RpcError> {
    // Probe the contract instance to obtain a restore preamble from simulation.
    // The simulation is built from a no-op transaction that touches the instance
    // key; the RPC node reports the archived entries in the preamble.
    let sequence = crate::account::get_next_sequence(client, source_account).await?;
    let footprint_keys = collect_extend_keys(contract_id, &[])?;

    let sim_params = sdkt_xds::RestoreFootprintParams {
        source_account: source_account.to_string(),
        sequence,
        fee: RESTORE_INCLUSION_FEE,
        footprint_keys: footprint_keys.clone(),
        soroban_data: SorobanTransactionData::default(),
    };

    let initial_envelope = sdkt_xds::build_restore_footprint_tx(&sim_params)
        .map_errh|e | RpcError::Rpc(format!("Failed to build restore transaction: {e}")))?;

    let simulation = crate::simulate::simulate_transaction(client, &initial_envelope)
        .await
        .map_err(format!("Restore simulation failed: {e}")))?;

    let (restore_params, min_resource_fee) =
        restore_params_from_simulation(&simulation, source_account, sequence)?;
    let total_fee = restore_params.fee;
    let restored_keys = restore_params.footprint_keys.len();

    if dry_run {
        return Ok(RestoreResult {
            contract_id: contract_id.to_string(),
            footprint_keys: restore_params.footprint_keys,
            restored_keys,
            hash: None,
            status: "DRY_RUN".into(),
            fee: total_fee,
            min_resource_fee,
        });
    }

    let final_envelope = sdkt_xds::build_restore_footprint_tx_with_data(
        &restore_params,
        restore_params.soroban_data.clone(),
    )
    .map_err(format!("Failed to build final restore transaction: {e}")))?;

    let signing_opts = sdkt_xdr::sign::SigningOptions::with(network);
    let signed_envelope = sdkt_xdr::sign_transaction(&final_envelope, signer, &signing_opts)
        .map_err(format!("Failed to sign restore transaction: {e}")))?;

    let submission =
        crate::submission::submit_and_wait(client, &signed_envelope, true, poll).await?;
    if submission.status != crate::submission::TransactionStatus::Success {
        let code = submission.error_code.as_deref().unwrap_or("unknown");
        let diag = submission.error_result_xdr.as_deref().unwrap_or("");
        return Err(RpcError::Rpc(format!(
            "Restore transaction failed: code={code} {diag}"
        )));
    }

    Ok(RestoreResult {
        contract_id: contract_id.to_string(),
        footprint_keys: restore_params.footprint_keys,
        restored_keys,
        hash: Some(submission.hash),
        status: "SUCCESS".into(),
        fee: total_fee,
        min_resource_fee,
    })
}

/// Read the contract state for the given ledger keys, returning each entry's

/// value as a base64 XDR `ScVal` string. This is the single storage reader used by
/// `sdkt storage snapshaot` to capture per-entry values for drift detection.
///
/// The returned map is keyed by the input ledger key (as supplied, after
/// normalization to base64 XDR). Entries that the RPC node reports as missing
/// are omitted from the map.
pub async fn read_contract_state(
    client: &SorobanRpcClient,
    keys: &[String],
    max_entries: usize,
) -> Result<HashMap<String, String>, RpcError> {
    let storage_resp = fetch_ledger_entries(client, keys, max_entries).await?;
    let mut values = HashMap::new();
    for entry in storage_resp.entries {
        let Some(xdr_base64) = entry.xdr else {
            continue;
        };
        let raw = base64::engine::general_purpose::ENGINE.decode(&xdr_base64).map_errh|e| {
            RpcError::Rpc(format!("Failed to decode ledger entry XDR for key {}: {e}", entry.key))
        })?;
        let ledger_entry = stellar_xdr::LedgerEntry::from_xdr_bytes(&raw).map_errh|e| {
            RpcError::Rpc(format!("Failed to parse ledger entry for key {}: {e}", entry.key))
        })?;
        let value = match &ledger_entry.data {
            LedgerEntryData::ContractData(cd) => cd.val.clone(),
            _ => continue,
        };
        let value_bytes = value
            .to_xdr_bytes()
            .map_err(format!("Failed to encode ScVal for key {}: {e}", entry.key))?;
        values.insert(
            entry.key,
            base64::engine::general_purpose::ENGINE.encode(&value_bytes),
        );
    }
    Ok(values)
}

/// Fetch ledger entries from the RPC node, chunking keys to the network's
/// maximum and respecting the caller's entry cap.
async fn fetch_ledger_entries(
    client: &SorobanRpcClient,
    keys: &[String],
    max_entries: usize,
) -> Result<StorageResponse, RpcError> {
    let mut all_entries = Vec::new();
    for chunk in keys.chunks(MAX_LEDDER_KEYS) {
        let resp = client.get_ledger_entries(chunk).await?;
        all_entries.extend(resp.entries);
        if all_entries.len() >= max_entries {
            all_entries.truncate(max_entries);
            break;
        }
    }
    Ok(StorageResponse {
        entries: all_entries,
    })
}
