//! edr-anchor: publishes the collector's periodic Merkle roots to a blockchain.
//!
//! What this buys, precisely: the collector is trusted today. Whoever operates
//! it can rewrite `events/*.ndjson` after the fact and re-run `verify` with a K0
//! they also hold. Putting a root on a public chain pins what the store
//! contained at a given time, to anyone, forever, without trusting the operator
//! and without revealing K0 or any log content.
//!
//! What it does NOT buy, and what must never be claimed for it:
//!
//!   * It does not prove a record is authentic. That is the HMAC under K0.
//!   * It does not stop the collector omitting a record before it is batched.
//!   * It does not prove when an event happened -- only when the commitment was
//!     published. The upper bound is the block timestamp; the lower bound is
//!     nothing at all.
//!
//! ## Why this is a separate binary
//!
//! The ingest-facing collector must not hold a funded private key and must not
//! depend on an RPC being up. So the collector only computes and stores roots;
//! this worker reads sealed roots, submits transactions, and appends receipts.
//! An anchoring outage is a monitoring event, not a data-loss event: roots keep
//! accumulating and anchor later.
//!
//! It reads `roots.ndjson` and appends to `anchors.ndjson`. It never opens
//! `hosts/`, and it does not depend on `edr-record`, so no code path in this
//! binary can reach K0 even by accident. Run it as its own unix user with read
//! on roots.ndjson and append on anchors.ndjson, and nothing else.
//!
//! ## What goes on chain
//!
//! A 0-value transaction from the anchor account **to itself**, with the
//! payload in calldata:
//!
//! ```text
//! calldata = "EDRMR1" (6 ASCII bytes) || root (32 bytes) || root_id (u64 big-endian)
//! ```
//!
//! No contract, no ABI, no deployment, no upgrade story, no contract risk.
//! Calldata is permanently retrievable through `eth_getTransactionByHash` on
//! any archive node and costs 16 gas per non-zero byte. A verifier fetches the
//! transaction and compares 32 bytes; `verify.py --proof --rpc-url` does
//! exactly that.
//!
//! Nothing but the root goes on chain. Everything on a public chain is public
//! forever: a root is 32 bytes of hash and reveals nothing, while a host name
//! would publish the fleet inventory.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::TxSignerSync;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(test)]
mod mock;

/// The six ASCII bytes every anchoring transaction's calldata starts with, so
/// an unrelated self-transfer cannot be mistaken for an anchor. Mirrored by
/// `CALLDATA_MAGIC` in verify.py and by `CALLDATA_RULE` in the collector.
const MAGIC: &[u8; 6] = b"EDRMR1";

/// 6 + 32 + 8. A transaction whose calldata is shorter than this is not one of
/// ours whatever else it looks like.
const CALLDATA_LEN: usize = 46;

/// Gas floor if the node will not estimate: 21,000 base plus 16 per non-zero
/// calldata byte and 4 per zero byte, rounded generously. A root is
/// indistinguishable from random, so nearly every byte is non-zero.
const GAS_FLOOR: u64 = 22_000;

#[derive(Parser)]
#[command(
    name = "edr-anchor",
    about = "Publish collector Merkle roots to a blockchain. Holds the wallet; never K0."
)]
struct Cli {
    /// The collector's data directory. Only roots.ndjson is read from it and
    /// only anchors.ndjson and anchor-status.json are written.
    #[arg(long, default_value = "/var/lib/edr-collector")]
    data_dir: PathBuf,

    /// JSON-RPC endpoint. Any provider for the chain will do -- a verifier can
    /// use a different one, which is the point of anchoring publicly.
    /// $EDR_ANCHOR_RPC is read when this is not given.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Expected chain id. Checked against the node before anything is signed:
    /// signing for the wrong chain is how a testnet key ends up broadcasting on
    /// mainnet.
    #[arg(long)]
    chain_id: Option<u64>,

    /// File holding the anchor account's private key, 64 hex characters, mode
    /// 0600. Never pass a key as an argument -- /proc/*/cmdline is world
    /// readable. $EDR_ANCHOR_KEY is the other accepted source.
    #[arg(long)]
    key_file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Anchor pending roots, then keep watching.
    Run {
        /// Seconds between passes. A pass is a handful of RPC calls, so this
        /// can be short; the cost that matters is one transaction per root.
        #[arg(long, default_value_t = 60)]
        interval_secs: u64,
        /// Blocks before an anchor is called confirmed. 12 on Ethereum L1; on a
        /// fast L2 use 20 or more -- cheap blocks are cheap to reorg.
        #[arg(long, default_value_t = 12)]
        confirmations: u64,
        /// How many of the newest confirmed anchors to re-check for a reorg
        /// each pass. Bounds RPC cost: an anchor buried under thousands of
        /// blocks is not coming back.
        #[arg(long, default_value_t = 8)]
        reorg_watch: usize,
        /// Refuse to submit above this fee, in gwei. A gas spike is a reason to
        /// wait: roots keep accumulating and anchor later, and a stuck queue is
        /// visible in the API.
        #[arg(long, default_value_t = 200)]
        max_fee_gwei: u64,
        /// Warn below this balance, in wei. Default 0.001 ETH.
        #[arg(long, default_value_t = 1_000_000_000_000_000)]
        min_balance_wei: u128,
        /// One pass, then exit. What a systemd timer or a cron job wants.
        #[arg(long)]
        once: bool,
    },
    /// Print the anchor account's address. No network, no transaction.
    ///
    /// This is the address to fund, and the address a verifier checks the
    /// anchoring transaction was sent from and to.
    Address,
    /// What is anchored and what is not, read from local files only.
    Status,
}

// ---------------------------------------------------------
// The two files
// ---------------------------------------------------------

/// One line of `roots.ndjson`, as far as this worker cares. Only the id and the
/// root are read: nothing else belongs on a chain.
#[derive(Deserialize)]
struct RootLine {
    root_id: u64,
    root: String,
    #[serde(default)]
    sealed_at: String,
}

/// One line of `anchors.ndjson`. Append-only, three phases, never an edit.
///
/// `edr-collector` parses this same shape (`AnchorLine` in its proof.rs) and
/// pins it in `anchor_line_shape_is_pinned`; the fixtures in the two tests are
/// deliberately identical so a change on either side fails a test rather than
/// silently producing bundles with no anchor.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct AnchorLine {
    v: u32,
    /// "submitted" | "confirmed" | "reorged".
    phase: String,
    root_id: u64,
    root: String,
    chain_id: u64,
    tx: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    /// The nonce this transaction was signed with. Load-bearing: a resubmission
    /// reuses it, which is what makes at most one of the two able to land.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submitted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmations: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn roots_path(dir: &Path) -> PathBuf {
    dir.join("roots.ndjson")
}

fn anchors_path(dir: &Path) -> PathBuf {
    dir.join("anchors.ndjson")
}

fn status_path(dir: &Path) -> PathBuf {
    dir.join("anchor-status.json")
}

fn read_roots(dir: &Path) -> Result<Vec<RootLine>, anyhow::Error> {
    let path = roots_path(dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        // No roots yet is normal on a fresh collector, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("cannot read {:?}: {}", path, e)),
    };
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RootLine>(line) {
            Ok(r) => out.push(r),
            Err(e) => eprintln!("CRITICAL: root line {} does not parse: {}", i + 1, e),
        }
    }
    Ok(out)
}

fn read_anchors(dir: &Path) -> Vec<AnchorLine> {
    let Ok(raw) = std::fs::read_to_string(anchors_path(dir)) else {
        return Vec::new();
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| match serde_json::from_str::<AnchorLine>(l) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("CRITICAL: anchor line does not parse: {}", e);
                None
            }
        })
        .collect()
}

/// Append one line and fsync it.
///
/// Every caller of this is on the crash-safety path: a `submitted` line MUST be
/// durable before the transaction is broadcast, or a crash in between anchors
/// the same root twice from two different nonces -- burning gas and producing
/// two conflicting anchors for one root.
fn append_anchor(dir: &Path, line: &AnchorLine) -> Result<(), anyhow::Error> {
    let mut encoded = serde_json::to_string(line)?;
    encoded.push('\n');
    let path = anchors_path(dir);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot append to {:?}", path))?;
    f.write_all(encoded.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Liveness and balance, rewritten in place each pass.
///
/// A separate file rather than a line in anchors.ndjson on purpose: that file is
/// evidence and is strictly append-only, and a heartbeat is neither. The
/// collector surfaces this at `/api/merkle/status` so a stuck worker or a
/// draining account is visible without shelling into the box.
fn write_status(dir: &Path, status: &serde_json::Value) {
    let path = status_path(dir);
    let tmp = path.with_extension("tmp");
    let Ok(text) = serde_json::to_string_pretty(status) else {
        return;
    };
    let written = std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, &path));
    if let Err(e) = written {
        eprintln!("WARNING: could not write {:?}: {}", path, e);
    }
}

// ---------------------------------------------------------
// The key
// ---------------------------------------------------------

/// Load the anchoring key from a file or the environment. Never from an
/// argument: `/proc/*/cmdline` is world-readable, and a key that reaches a
/// process list has to be considered spent.
///
/// The file checks mirror `prepare_wal_dir` in the agent: refuse a symlink,
/// refuse group- or world-readable, open with O_NOFOLLOW.
fn load_signer(key_file: Option<&Path>) -> Result<PrivateKeySigner, anyhow::Error> {
    let hex = match key_file {
        Some(path) => read_key_file(path)?,
        None => std::env::var("EDR_ANCHOR_KEY").map_err(|_| {
            anyhow::anyhow!(
                "no anchoring key. Pass --key-file <path> (mode 0600) or set \
                 $EDR_ANCHOR_KEY. A key must never be passed as a command-line \
                 argument: /proc/*/cmdline is world-readable."
            )
        })?,
    };
    let trimmed = hex.trim().trim_start_matches("0x");
    trimmed
        .parse::<PrivateKeySigner>()
        .map_err(|e| anyhow::anyhow!("the anchoring key is unusable: {}", e))
}

fn read_key_file(path: &Path) -> Result<String, anyhow::Error> {
    // Inspect before opening. symlink_metadata does not follow, so a planted
    // link is caught rather than read through.
    let md = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot stat key file {:?}", path))?;
    if md.file_type().is_symlink() {
        anyhow::bail!(
            "{:?} is a symlink. Refusing to start: following it would read a key from \
             wherever whoever created the link chose.",
            path
        );
    }
    if !md.is_file() {
        anyhow::bail!("{:?} is not a regular file", path);
    }
    if md.mode() & 0o077 != 0 {
        anyhow::bail!(
            "{:?} is readable or writable by group or others (mode {:o}). Refusing to \
             start; run `chmod 600` on it. A funded key readable by another account is \
             a funded key that account holds.",
            path,
            md.mode() & 0o777
        );
    }
    // O_NOFOLLOW closes the window between the stat above and this open.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)
        .with_context(|| format!("cannot open key file {:?}", path))?;
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut f, &mut buf)?;
    if buf.trim().is_empty() {
        anyhow::bail!("{:?} is empty", path);
    }
    Ok(buf)
}

/// O_NOFOLLOW without a libc dependency for one constant. It is 0o400000 on
/// Linux and has been for the life of the flag.
fn libc_o_nofollow() -> i32 {
    0o400_000
}

// ---------------------------------------------------------
// Calldata
// ---------------------------------------------------------

/// `"EDRMR1" || root(32) || root_id(u64 big-endian)`.
///
/// This is the format a verifier decodes, so it is pinned by
/// `calldata_is_the_documented_layout` and mirrored in verify.py. Changing it
/// invalidates every proof bundle ever issued against an anchored root.
fn calldata(root: &[u8; 32], root_id: u64) -> Bytes {
    let mut out = Vec::with_capacity(CALLDATA_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(root);
    out.extend_from_slice(&root_id.to_be_bytes());
    Bytes::from(out)
}

fn unhex32(h: &str) -> Option<[u8; 32]> {
    let h = h.trim().trim_start_matches("0x");
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------
// What is anchored, what is in flight
// ---------------------------------------------------------

/// Per-root view of `anchors.ndjson`.
struct AnchorState {
    /// Roots with a live `confirmed` line. Nothing more to do for these.
    confirmed: std::collections::HashMap<u64, AnchorLine>,
    /// Roots with a `submitted` line and no confirmation yet: in flight.
    in_flight: std::collections::HashMap<u64, Vec<AnchorLine>>,
}

/// A `reorged` line disowns one transaction, so resolving the current state
/// means reading a root's whole history rather than its last line.
fn anchor_state(lines: &[AnchorLine]) -> AnchorState {
    let dead: std::collections::HashSet<(u64, String)> = lines
        .iter()
        .filter(|l| l.phase == "reorged")
        .map(|l| (l.root_id, l.tx.clone()))
        .collect();

    let mut confirmed = std::collections::HashMap::new();
    let mut in_flight: std::collections::HashMap<u64, Vec<AnchorLine>> =
        std::collections::HashMap::new();
    for l in lines {
        if dead.contains(&(l.root_id, l.tx.clone())) {
            continue;
        }
        match l.phase.as_str() {
            "confirmed" => {
                confirmed.insert(l.root_id, l.clone());
            }
            "submitted" => in_flight.entry(l.root_id).or_default().push(l.clone()),
            _ => {}
        }
    }
    // A root that got confirmed is not in flight any more, whatever earlier
    // submissions are still sitting in the file.
    in_flight.retain(|root_id, _| !confirmed.contains_key(root_id));
    AnchorState {
        confirmed,
        in_flight,
    }
}

// ---------------------------------------------------------
// The chain
// ---------------------------------------------------------

struct Chain {
    provider: alloy::providers::RootProvider,
    signer: PrivateKeySigner,
    address: Address,
    chain_id: u64,
}

impl Chain {
    async fn connect(
        rpc_url: &str,
        signer: PrivateKeySigner,
        expect_chain_id: Option<u64>,
    ) -> Result<Self, anyhow::Error> {
        let url: alloy::transports::http::reqwest::Url = rpc_url
            .parse()
            .with_context(|| format!("{:?} is not a URL", rpc_url))?;
        let provider = ProviderBuilder::new().connect_http(url).root().clone();
        let chain_id = provider
            .get_chain_id()
            .await
            .context("the RPC endpoint did not answer eth_chainId")?;
        // Checked before anything is signed. A signature is chain-bound by
        // EIP-155, so signing for the wrong chain is how a testnet key ends up
        // broadcasting on mainnet -- or, more likely, how an operator spends an
        // afternoon wondering why nothing confirms.
        if let Some(want) = expect_chain_id {
            if want != chain_id {
                anyhow::bail!(
                    "--chain-id says {} but the RPC endpoint reports {}. Refusing to sign.",
                    want,
                    chain_id
                );
            }
        }
        let address = signer.address();
        Ok(Chain {
            provider,
            signer,
            address,
            chain_id,
        })
    }

    /// EIP-1559 fees, from the node rather than a guess.
    ///
    /// `max_fee = 2 * base_fee + tip` is the usual headroom: it survives a few
    /// blocks of base-fee growth, and anything unspent is refunded.
    async fn fees(&self, cap_gwei: u64) -> Result<(u128, u128), anyhow::Error> {
        let tip = self
            .provider
            .get_max_priority_fee_per_gas()
            .await
            .unwrap_or(1_000_000_000);
        let base = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .ok()
            .flatten()
            .and_then(|b| b.header.base_fee_per_gas)
            .map(u128::from)
            .unwrap_or(1_000_000_000);
        let max_fee = base.saturating_mul(2).saturating_add(tip);
        let cap = u128::from(cap_gwei).saturating_mul(1_000_000_000);
        if max_fee > cap {
            anyhow::bail!(
                "fees are {} wei/gas, above the --max-fee-gwei cap of {} gwei. Waiting: \
                 roots keep accumulating and anchor later, and the backlog is visible in \
                 the retrieval API.",
                max_fee,
                cap_gwei
            );
        }
        Ok((max_fee, tip))
    }

    /// Sign one anchoring transaction and return it with its hash.
    ///
    /// Signing locally, rather than letting a provider filler do it, is what
    /// makes the crash-safe protocol possible: the transaction hash is known
    /// BEFORE anything is broadcast, so it can be written down first.
    async fn build(
        &self,
        root: &[u8; 32],
        root_id: u64,
        nonce: u64,
        max_fee_gwei: u64,
    ) -> Result<(TxEnvelope, B256), anyhow::Error> {
        let input = calldata(root, root_id);
        let (max_fee_per_gas, max_priority_fee_per_gas) = self.fees(max_fee_gwei).await?;

        // Self-addressed and zero value: the transaction moves no funds, it
        // only carries 46 bytes. A verifier checks `to == from` as part of
        // recognising it as an anchor.
        let request = TransactionRequest::default()
            .to(self.address)
            .from(self.address)
            .value(U256::ZERO)
            .input(input.clone().into());
        let gas_limit = self
            .provider
            .estimate_gas(request)
            .await
            .map(|g| g.saturating_add(g / 4))
            .unwrap_or(GAS_FLOOR)
            .max(GAS_FLOOR);

        let mut tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: TxKind::Call(self.address),
            value: U256::ZERO,
            access_list: Default::default(),
            input,
        };
        let signature = self
            .signer
            .sign_transaction_sync(&mut tx)
            .context("signing the anchoring transaction failed")?;
        let envelope = TxEnvelope::Eip1559(tx.into_signed(signature));
        let hash = *envelope.tx_hash();
        Ok((envelope, hash))
    }
}

fn hex_tx(hash: &B256) -> String {
    format!("{:#x}", hash)
}

// ---------------------------------------------------------
// One pass
// ---------------------------------------------------------

struct PassOpts {
    confirmations: u64,
    reorg_watch: usize,
    max_fee_gwei: u64,
    min_balance_wei: u128,
}

/// Reconcile what is in flight, notice reorgs, then anchor at most one new root.
///
/// The order is the crash-safety argument and is not negotiable:
///
///   1. Anything `submitted` with no `confirmed` is in flight. Resolve it
///      first, before considering new work.
///   2. A transaction the chain does not know is resubmitted with the SAME
///      nonce -- never a fresh one. Same nonce means at most one of the two can
///      ever land, so a crash between signing and broadcasting cannot produce
///      two anchors for one root.
///   3. Only then look for an unanchored root, oldest first, one at a time.
///   4. The `submitted` line is written and fsynced BEFORE
///      eth_sendRawTransaction. A crash in the other order loses the tx hash
///      and re-anchors from a new nonce, burning gas and producing two
///      conflicting anchors.
async fn pass(dir: &Path, chain: &Chain, opts: &PassOpts) -> Result<(), anyhow::Error> {
    let roots = read_roots(dir)?;
    let state = anchor_state(&read_anchors(dir));
    let head = chain.provider.get_block_number().await.unwrap_or(0);

    // 1 + 2. In flight.
    for (root_id, submissions) in &state.in_flight {
        let Some(root) = roots.iter().find(|r| r.root_id == *root_id) else {
            eprintln!(
                "CRITICAL: anchors.ndjson has an in-flight transaction for root {}, but \
                 roots.ndjson has no such root. A root line was deleted.",
                root_id
            );
            continue;
        };
        let mut landed = false;
        for sub in submissions {
            match confirm(dir, chain, root_id, &root.root, sub, head, opts.confirmations).await {
                Ok(true) => {
                    landed = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => eprintln!("WARNING: checking {}: {}", sub.tx, e),
            }
        }
        if landed {
            continue;
        }
        // Nothing landed and nothing is pending in the mempool: resubmit at the
        // same nonce. The replacement gets a new hash (fees moved), so it is a
        // new `submitted` line -- but it cannot coexist with the original,
        // because they share a nonce.
        let unknown = submissions.iter().all(|s| s.block_number.is_none());
        if unknown {
            if let Some(sub) = submissions.last() {
                if let Some(nonce) = sub.nonce {
                    let known = chain
                        .provider
                        .get_transaction_by_hash(parse_hash(&sub.tx))
                        .await
                        .ok()
                        .flatten()
                        .is_some();
                    if !known {
                        eprintln!(
                            "WARNING: the chain does not know {} for root {}. Resubmitting \
                             at nonce {} -- never a fresh one, so at most one can land.",
                            sub.tx, root_id, nonce
                        );
                        submit(dir, chain, root, nonce, opts.max_fee_gwei).await?;
                    }
                }
            }
        }
    }

    // A previously confirmed anchor that no longer resolves was reorged out.
    // Only the newest few are re-checked: an anchor buried under thousands of
    // blocks is not coming back, and checking every one of them every pass
    // would be a linear RPC bill for nothing.
    let mut recent: Vec<&AnchorLine> = state.confirmed.values().collect();
    recent.sort_by_key(|a| std::cmp::Reverse(a.root_id));
    for anchor in recent.into_iter().take(opts.reorg_watch) {
        let known = chain
            .provider
            .get_transaction_by_hash(parse_hash(&anchor.tx))
            .await
            .ok()
            .flatten()
            .and_then(|tx| tx.block_number)
            .is_some();
        if !known {
            eprintln!(
                "CRITICAL: anchor {} for root {} no longer resolves on chain {}. It was \
                 reorged out. Recording it and re-anchoring.",
                anchor.tx, anchor.root_id, anchor.chain_id
            );
            append_anchor(
                dir,
                &AnchorLine {
                    v: 1,
                    phase: "reorged".to_string(),
                    root_id: anchor.root_id,
                    root: anchor.root.clone(),
                    chain_id: anchor.chain_id,
                    tx: anchor.tx.clone(),
                    detail: Some(
                        "the transaction no longer resolves on chain; the block that \
                         carried it was reorganised away"
                            .to_string(),
                    ),
                    ..blank()
                },
            )?;
        }
    }

    // 3. One new root per pass, oldest first. One at a time keeps the nonce
    // sequence unambiguous: there is never more than one new nonce in flight.
    let state = anchor_state(&read_anchors(dir));
    let next = roots
        .iter()
        .find(|r| !state.confirmed.contains_key(&r.root_id) && !state.in_flight.contains_key(&r.root_id));

    if let Some(root) = next {
        let nonce = chain
            .provider
            .get_transaction_count(chain.address)
            .pending()
            .await
            .context("cannot read the account nonce")?;
        submit(dir, chain, root, nonce, opts.max_fee_gwei).await?;
    }

    // 5. Liveness, for whatever is watching. Written last so it reflects the
    // pass that just happened.
    let balance = chain
        .provider
        .get_balance(chain.address)
        .await
        .unwrap_or(U256::ZERO);
    let balance_wei = balance.to_string();
    let low = balance < U256::from(opts.min_balance_wei);
    if low {
        eprintln!(
            "CRITICAL: the anchor account {} is down to {} wei. Below this it stops \
             anchoring, roots accumulate unpublished, and every proof issued meanwhile is \
             untimestamped.",
            chain.address, balance_wei
        );
    }
    let state = anchor_state(&read_anchors(dir));
    let unanchored = roots
        .iter()
        .filter(|r| !state.confirmed.contains_key(&r.root_id))
        .count();
    write_status(
        dir,
        &json!({
            "address": format!("{:?}", chain.address),
            "chain_id": chain.chain_id,
            "anchor_balance_wei": balance_wei,
            "balance_low": low,
            "roots_total": roots.len(),
            "roots_unanchored": unanchored,
            "in_flight": state.in_flight.len(),
            "head_block": head,
            "checked_at": Utc::now().to_rfc3339(),
        }),
    );
    Ok(())
}

fn blank() -> AnchorLine {
    AnchorLine {
        v: 1,
        phase: String::new(),
        root_id: 0,
        root: String::new(),
        chain_id: 0,
        tx: String::new(),
        from: None,
        nonce: None,
        submitted_at: None,
        block_number: None,
        block_hash: None,
        block_time: None,
        confirmations: None,
        confirmed_at: None,
        detail: None,
    }
}

fn parse_hash(tx: &str) -> B256 {
    tx.trim_start_matches("0x")
        .parse::<B256>()
        .unwrap_or(B256::ZERO)
}

/// Sign, write the intent down durably, then broadcast. Never the other order.
async fn submit(
    dir: &Path,
    chain: &Chain,
    root: &RootLine,
    nonce: u64,
    max_fee_gwei: u64,
) -> Result<(), anyhow::Error> {
    let Some(root_bytes) = unhex32(&root.root) else {
        anyhow::bail!(
            "root {} is not 64 hex characters, so there is nothing to anchor",
            root.root_id
        );
    };
    let (envelope, hash) = chain
        .build(&root_bytes, root.root_id, nonce, max_fee_gwei)
        .await?;

    // Durable BEFORE the broadcast. This is the whole crash-safety design: if
    // the process dies in the next microsecond, the restart finds this line,
    // asks the chain about this hash, and either confirms it or resubmits at
    // this same nonce. Written after broadcasting instead, a crash would lose
    // the hash and re-anchor from a fresh nonce -- two conflicting anchors for
    // one root and gas spent on both.
    append_anchor(
        dir,
        &AnchorLine {
            v: 1,
            phase: "submitted".to_string(),
            root_id: root.root_id,
            root: root.root.clone(),
            chain_id: chain.chain_id,
            tx: hex_tx(&hash),
            from: Some(format!("{:?}", chain.address)),
            nonce: Some(nonce),
            submitted_at: Some(Utc::now().to_rfc3339()),
            ..blank()
        },
    )?;

    let raw = envelope.encoded_2718();
    match chain.provider.send_raw_transaction(&raw).await {
        Ok(_) => {
            eprintln!(
                "submitted root {} as {} (nonce {}) on chain {}",
                root.root_id,
                hex_tx(&hash),
                nonce,
                chain.chain_id
            );
            Ok(())
        }
        Err(e) => {
            // The intent is already on disk, which is exactly right: the next
            // pass looks this hash up, finds the chain does not know it, and
            // resubmits at the same nonce.
            eprintln!(
                "CRITICAL: broadcasting root {} failed: {}. The submitted line is on disk; \
                 the next pass retries at nonce {}.",
                root.root_id, e, nonce
            );
            Ok(())
        }
    }
}

/// Has this submission reached the required depth? Appends `confirmed` if so.
async fn confirm(
    dir: &Path,
    chain: &Chain,
    root_id: &u64,
    root: &str,
    sub: &AnchorLine,
    head: u64,
    confirmations: u64,
) -> Result<bool, anyhow::Error> {
    let tx = chain
        .provider
        .get_transaction_by_hash(parse_hash(&sub.tx))
        .await?;
    let Some(tx) = tx else {
        return Ok(false);
    };
    let Some(block_number) = tx.block_number else {
        // Known to the node but not yet mined. Nothing to do but wait.
        return Ok(false);
    };
    let depth = head.saturating_sub(block_number).saturating_add(1);
    if depth < confirmations {
        return Ok(false);
    }

    let block = chain
        .provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Number(block_number))
        .await
        .ok()
        .flatten();
    let block_time = block.as_ref().and_then(|b| {
        chrono::DateTime::from_timestamp(b.header.timestamp as i64, 0).map(|t| t.to_rfc3339())
    });

    append_anchor(
        dir,
        &AnchorLine {
            v: 1,
            phase: "confirmed".to_string(),
            root_id: *root_id,
            root: root.to_string(),
            chain_id: chain.chain_id,
            tx: sub.tx.clone(),
            block_number: Some(block_number),
            block_hash: tx.block_hash.map(|h| format!("{:#x}", h)),
            block_time,
            confirmations: Some(depth),
            confirmed_at: Some(Utc::now().to_rfc3339()),
            ..blank()
        },
    )?;
    eprintln!(
        "root {} confirmed in block {} ({} confirmations) as {}",
        root_id, block_number, depth, sub.tx
    );
    Ok(true)
}

// ---------------------------------------------------------
// Subcommands
// ---------------------------------------------------------

fn cmd_status(dir: &Path) -> Result<(), anyhow::Error> {
    let roots = read_roots(dir)?;
    let state = anchor_state(&read_anchors(dir));

    println!("{:<8} {:<24} {:<12} {}", "ROOT", "SEALED AT", "STATUS", "TX");
    for r in &roots {
        let (status, tx) = match state.confirmed.get(&r.root_id) {
            Some(a) => ("confirmed".to_string(), a.tx.clone()),
            None => match state.in_flight.get(&r.root_id).and_then(|v| v.last()) {
                Some(a) => ("submitted".to_string(), a.tx.clone()),
                None => ("unanchored".to_string(), "-".to_string()),
            },
        };
        println!("{:<8} {:<24} {:<12} {}", r.root_id, r.sealed_at, status, tx);
    }
    let unanchored = roots
        .iter()
        .filter(|r| !state.confirmed.contains_key(&r.root_id))
        .count();
    println!();
    println!("roots         {}", roots.len());
    println!("unanchored    {}", unanchored);
    println!("in flight     {}", state.in_flight.len());
    println!();
    println!("An anchoring backlog is a monitoring event, not data loss: roots keep");
    println!("accumulating and anchor later. Proofs issued meanwhile are still valid");
    println!("commitments -- they are simply not yet independently timestamped.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Status => return cmd_status(&cli.data_dir),
        Command::Address => {
            let signer = load_signer(cli.key_file.as_deref())?;
            println!("{:?}", signer.address());
            println!();
            println!("Fund this address with a small float of gas and nothing else. It signs");
            println!("0-value self-transfers carrying 46 bytes of calldata; it never needs to");
            println!("hold value, and anything it does hold is at risk for no benefit.");
            return Ok(());
        }
        Command::Run {
            interval_secs,
            confirmations,
            reorg_watch,
            max_fee_gwei,
            min_balance_wei,
            once,
        } => {
            let Some(rpc_url) = cli
                .rpc_url
                .clone()
                .or_else(|| std::env::var("EDR_ANCHOR_RPC").ok())
            else {
                anyhow::bail!("--rpc-url (or $EDR_ANCHOR_RPC) is required to anchor");
            };
            let signer = load_signer(cli.key_file.as_deref())?;
            let chain = Chain::connect(&rpc_url, signer, cli.chain_id).await?;
            let opts = PassOpts {
                confirmations,
                reorg_watch,
                max_fee_gwei,
                min_balance_wei,
            };
            eprintln!(
                "edr-anchor on chain {} as {} | data {:?} | {} confirmations | never reads \
                 hosts/ and holds no K0",
                chain.chain_id, chain.address, cli.data_dir, confirmations
            );

            if once {
                return pass(&cli.data_dir, &chain, &opts).await;
            }
            // Backoff on sustained failure rather than hammering a dead RPC.
            // An outage here costs latency on proofs and nothing else.
            let mut backoff = 1u64;
            loop {
                match pass(&cli.data_dir, &chain, &opts).await {
                    Ok(()) => backoff = 1,
                    Err(e) => {
                        eprintln!("CRITICAL: anchoring pass failed: {}", e);
                        backoff = (backoff.saturating_mul(2)).min(32);
                    }
                }
                let wait = interval_secs.saturating_mul(backoff);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("shutting down");
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The exact bytes a verifier decodes. verify.py slices `input` as
    /// [0..6] magic, [6..38] root, [38..46] root_id, and this is the only
    /// place those offsets are produced.
    #[test]
    fn calldata_is_the_documented_layout() {
        let root = [0xabu8; 32];
        let data = calldata(&root, 88);
        assert_eq!(data.len(), CALLDATA_LEN);
        assert_eq!(data.get(..6), Some(b"EDRMR1".as_slice()));
        assert_eq!(data.get(6..38), Some(root.as_slice()));
        assert_eq!(data.get(38..46), Some(88u64.to_be_bytes().as_slice()));
        // The literal a verifier greps for.
        assert!(alloy::hex::encode(&data).starts_with("4544524d5231"));
    }

    /// The schema the collector parses. `anchor_line_shape_is_pinned` in
    /// edr-collector's proof.rs asserts the same fixture from the other side;
    /// a change to either that is not made to both fails a test here or there.
    #[test]
    fn anchor_line_shape_is_pinned() {
        let submitted = AnchorLine {
            v: 1,
            phase: "submitted".to_string(),
            root_id: 88,
            root: "7e91".to_string(),
            chain_id: 8453,
            tx: "0x5f".to_string(),
            from: Some("0xabc".to_string()),
            nonce: Some(1204),
            submitted_at: Some("2026-08-27T09:20:11Z".to_string()),
            ..blank()
        };
        let json = serde_json::to_value(&submitted).unwrap_or(serde_json::Value::Null);
        assert_eq!(json["phase"], "submitted");
        assert_eq!(json["root_id"], 88);
        assert_eq!(json["nonce"], 1204);
        // Absent, not null: the collector's reader treats a missing block as
        // "not mined", and a null would be indistinguishable from a bug.
        assert!(json.get("block_number").is_none());
        assert!(json.get("detail").is_none());

        let round: AnchorLine =
            serde_json::from_value(json).unwrap_or_else(|e| panic!("round trip: {}", e));
        assert_eq!(round.nonce, Some(1204));
    }

    fn line(phase: &str, root_id: u64, tx: &str) -> AnchorLine {
        AnchorLine {
            v: 1,
            phase: phase.to_string(),
            root_id,
            root: "aa".repeat(32),
            chain_id: 1,
            tx: tx.to_string(),
            ..blank()
        }
    }

    #[test]
    fn in_flight_is_submitted_without_a_confirmation() {
        let state = anchor_state(&[line("submitted", 1, "0xaa")]);
        assert_eq!(state.in_flight.len(), 1);
        assert!(state.confirmed.is_empty());

        let state = anchor_state(&[line("submitted", 1, "0xaa"), line("confirmed", 1, "0xaa")]);
        assert!(state.in_flight.is_empty(), "a confirmed root is not in flight");
        assert_eq!(state.confirmed.len(), 1);

        // A reorg puts the root back in the queue: neither confirmed nor in
        // flight, so the next pass anchors it again as new work.
        let state = anchor_state(&[
            line("submitted", 1, "0xaa"),
            line("confirmed", 1, "0xaa"),
            line("reorged", 1, "0xaa"),
        ]);
        assert!(state.confirmed.is_empty());
        assert!(state.in_flight.is_empty());

        // Two submissions at one nonce: still one root in flight, and either
        // hash landing confirms it.
        let state = anchor_state(&[line("submitted", 2, "0xaa"), line("submitted", 2, "0xbb")]);
        assert_eq!(state.in_flight.get(&2).map(Vec::len), Some(2));
    }

    #[test]
    fn a_root_that_is_not_64_hex_is_refused() {
        assert!(unhex32("zz".repeat(32).as_str()).is_none());
        assert!(unhex32("aa").is_none());
        assert!(unhex32(&format!("0x{}", "ab".repeat(32))).is_some());
    }

    /// A key file anyone else can read is a key anyone else holds.
    #[test]
    fn a_group_readable_key_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("edr-anchor-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}", e));
        let path = dir.join("key");
        std::fs::write(&path, "ab".repeat(32)).unwrap_or_else(|e| panic!("{}", e));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|e| panic!("{}", e));
        let err = read_key_file(&path).err().unwrap_or_else(|| panic!("0640 must be refused"));
        assert!(err.to_string().contains("readable or writable by group"), "{}", err);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("{}", e));
        assert!(read_key_file(&path).is_ok(), "0600 is the supported mode");

        // A symlink is refused rather than followed.
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&path, &link).unwrap_or_else(|e| panic!("{}", e));
        let err = read_key_file(&link).err().unwrap_or_else(|| panic!("a symlink must be refused"));
        assert!(err.to_string().contains("symlink"), "{}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------
// The protocol, against a node that can be made to misbehave
// ---------------------------------------------------------
//
// These drive the real `pass()` against `mock::MockNode`. That is the only way
// to exercise what actually matters here -- a crash between signing and
// broadcasting, a dropped transaction, a reorg -- because none of it can be
// arranged on a public testnet in CI.
//
// The end-to-end run against a real testnet is a separate, manual step and is
// written up in edr-anchor/README.md; it needs an RPC URL and a funded key,
// neither of which belongs in a test suite.
#[cfg(test)]
mod protocol_tests {
    use super::mock::MockNode;
    use super::*;
    use alloy::consensus::Transaction as _;
    use alloy::eips::eip2718::Decodable2718;

    const CHAIN_ID: u64 = 84532; // base-sepolia, the testnet this targets first.

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "edr-anchor-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&dir);
        TempDir(dir)
    }

    /// `roots.ndjson` as the collector writes it, reduced to what this worker
    /// reads.
    fn write_roots(dir: &Path, count: u64) {
        let mut out = String::new();
        for id in 0..count {
            let root = format!("{:02x}", id + 1).repeat(32);
            out.push_str(&json!({
                "v": 1, "root_id": id, "sealed_at": "2026-08-28T09:20:00+00:00",
                "root": root, "prev_root": "00".repeat(32), "leaf_count": 1, "covers": []
            }).to_string());
            out.push('\n');
        }
        std::fs::write(roots_path(dir), out).unwrap_or_else(|e| panic!("{}", e));
    }

    fn signer() -> PrivateKeySigner {
        "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            .parse()
            .unwrap_or_else(|e| panic!("test key parses: {}", e))
    }

    async fn chain_for(node: &MockNode) -> Chain {
        Chain::connect(&node.url, signer(), Some(CHAIN_ID))
            .await
            .unwrap_or_else(|e| panic!("connect: {}", e))
    }

    fn opts() -> PassOpts {
        PassOpts {
            confirmations: 3,
            reorg_watch: 8,
            max_fee_gwei: 200,
            min_balance_wei: 1,
        }
    }

    fn lines(dir: &Path) -> Vec<AnchorLine> {
        read_anchors(dir)
    }

    fn phases(dir: &Path) -> Vec<String> {
        lines(dir).into_iter().map(|l| l.phase).collect()
    }

    /// Submit, mine, confirm. The ordinary path, and the shape of every line
    /// the collector will later read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_is_submitted_then_confirmed() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;

        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0), vec!["submitted"]);
        let submitted = lines(&dir.0).into_iter().next().unwrap_or_else(|| panic!("one line"));
        assert_eq!(submitted.root_id, 0);
        assert_eq!(submitted.nonce, Some(0));
        assert_eq!(submitted.chain_id, CHAIN_ID);
        assert!(submitted.block_number.is_none());

        // The node has it, but it is not deep enough yet.
        node.mine();
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0), vec!["submitted"], "confirmed too early");

        node.advance(3);
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0), vec!["submitted", "confirmed"]);
        let confirmed = lines(&dir.0).pop().unwrap_or_else(|| panic!("two lines"));
        assert_eq!(confirmed.tx, submitted.tx, "confirmation names the same tx");
        assert!(confirmed.block_number.is_some());
        assert!(confirmed.block_time.is_some());
        assert!(confirmed.confirmations.unwrap_or(0) >= 3);

        // Nothing left to do, and no second anchor for a root already anchored.
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0).len(), 2);
    }

    /// Roots are anchored oldest first, one per pass, so there is never more
    /// than one new nonce in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roots_anchor_oldest_first_one_at_a_time() {
        let dir = temp_dir();
        write_roots(&dir.0, 3);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;

        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(lines(&dir.0).len(), 1, "one submission per pass");
        assert_eq!(lines(&dir.0).first().map(|l| l.root_id), Some(0));

        for expected in 1..3u64 {
            node.mine();
            node.advance(3);
            pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
            let submitted: Vec<u64> = lines(&dir.0)
                .into_iter()
                .filter(|l| l.phase == "submitted")
                .map(|l| l.root_id)
                .collect();
            assert_eq!(submitted.last(), Some(&expected), "oldest unanchored first");
        }

        let nonces: Vec<Option<u64>> = lines(&dir.0)
            .into_iter()
            .filter(|l| l.phase == "submitted")
            .map(|l| l.nonce)
            .collect();
        assert_eq!(nonces, vec![Some(0), Some(1), Some(2)], "one nonce per root");
    }

    /// THE crash test. The worker dies after writing `submitted` and before the
    /// broadcast lands; a fresh process must resume that transaction rather
    /// than anchor the same root again from a new nonce.
    ///
    /// Both failure modes it rules out cost real money: a duplicate anchor
    /// burns gas twice and leaves two conflicting claims for one root.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crash_between_signing_and_broadcasting_does_not_double_anchor() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;

        // The node rejects the send: the intent is on disk, nothing broadcast.
        // Byte for byte the state a kill -9 in between would leave.
        node.lock().reject_sends = true;
        let chain = chain_for(&node).await;
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0), vec!["submitted"]);
        assert!(node.lock().txs.is_empty(), "nothing reached the chain");
        let first = lines(&dir.0).into_iter().next().unwrap_or_else(|| panic!("one line"));

        // Restart: a new Chain, a new pass, the same files.
        node.lock().reject_sends = false;
        let chain = chain_for(&node).await;
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));

        let after = lines(&dir.0);
        assert!(after.iter().all(|l| l.root_id == 0), "no other root was touched");
        let nonces: Vec<Option<u64>> = after
            .iter()
            .filter(|l| l.phase == "submitted")
            .map(|l| l.nonce)
            .collect();
        assert!(
            nonces.iter().all(|n| *n == first.nonce),
            "a resubmission must reuse nonce {:?}, not mint a new one: {:?}",
            first.nonce,
            nonces
        );
        assert_eq!(node.lock().txs.len(), 1, "exactly one transaction reached the chain");

        // And it confirms exactly once.
        node.mine();
        node.advance(3);
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(
            phases(&dir.0).iter().filter(|p| *p == "confirmed").count(),
            1,
            "exactly one anchor lands for one root"
        );
    }

    /// A transaction the mempool dropped is resubmitted at the same nonce.
    /// Same nonce is what makes it a replacement rather than a second anchor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_transaction_is_resubmitted_at_the_same_nonce() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;

        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        let first = lines(&dir.0).into_iter().next().unwrap_or_else(|| panic!("one line"));
        node.forget(&first.tx);

        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        let submissions: Vec<AnchorLine> = lines(&dir.0)
            .into_iter()
            .filter(|l| l.phase == "submitted")
            .collect();
        assert_eq!(submissions.len(), 2, "the dropped transaction was not retried");
        assert!(
            submissions.iter().all(|s| s.nonce == first.nonce),
            "a replacement must share the nonce: {:?}",
            submissions.iter().map(|s| s.nonce).collect::<Vec<_>>()
        );
        assert_eq!(
            submissions.iter().filter(|s| s.root_id == 0).count(),
            2,
            "both submissions are for the same root"
        );
    }

    /// A confirmed anchor that stops resolving was reorged out. It is recorded
    /// as a new line -- never an edit -- and the root goes back in the queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reorged_anchor_is_recorded_and_re_anchored() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;

        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        node.mine();
        node.advance(3);
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(phases(&dir.0), vec!["submitted", "confirmed"]);
        let confirmed = lines(&dir.0).pop().unwrap_or_else(|| panic!("two lines"));

        // The block carrying it is gone.
        node.forget(&confirmed.tx);
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));

        let after = phases(&dir.0);
        assert_eq!(
            after.get(2).map(String::as_str),
            Some("reorged"),
            "a reorg must be appended, never patched in: {:?}",
            after
        );
        assert_eq!(
            after.get(3).map(String::as_str),
            Some("submitted"),
            "the root must be re-anchored after a reorg: {:?}",
            after
        );
        // Nothing was rewritten: the original lines are still there verbatim.
        assert_eq!(after.first().map(String::as_str), Some("submitted"));
        assert_eq!(after.get(1).map(String::as_str), Some("confirmed"));
    }

    /// The calldata that actually goes on the wire is what a verifier decodes:
    /// the magic, the root, the id -- and nothing else. Not a host name, not a
    /// count, not a timestamp. Everything on a public chain is public forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_the_root_reaches_the_chain() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));

        let raw = node.lock().received.first().cloned().unwrap_or_default();
        let decoded = TxEnvelope::decode_2718(&mut raw.as_slice())
            .unwrap_or_else(|e| panic!("the node received a decodable transaction: {}", e));
        let input = decoded.input();
        assert_eq!(input.len(), CALLDATA_LEN);
        assert_eq!(input.get(..6), Some(b"EDRMR1".as_slice()));
        assert_eq!(
            input.get(6..38).map(alloy::hex::encode),
            Some("01".repeat(32)),
            "the root itself, raw"
        );
        assert_eq!(input.get(38..46), Some(0u64.to_be_bytes().as_slice()));

        // Self-addressed, zero value: a verifier checks to == from.
        assert_eq!(decoded.to(), Some(chain.address));
        assert_eq!(decoded.value(), U256::ZERO);
        assert_eq!(decoded.chain_id(), Some(CHAIN_ID));

        // The hash the worker wrote down is the hash the node computed. If
        // those ever disagree, every confirmation lookup silently fails.
        let written = lines(&dir.0).into_iter().next().unwrap_or_else(|| panic!("one line"));
        assert!(
            node.lock().txs.contains_key(&written.tx.to_lowercase()),
            "the recorded tx hash {} is not the one the node computed",
            written.tx
        );
    }

    /// Signing for the wrong chain is refused before anything is signed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_chain_id_mismatch_refuses_to_sign() {
        let node = MockNode::start(CHAIN_ID).await;
        let err = Chain::connect(&node.url, signer(), Some(1))
            .await
            .err()
            .unwrap_or_else(|| panic!("a chain id mismatch must be refused"));
        assert!(err.to_string().contains("Refusing to sign"), "{}", err);
    }

    /// A fee spike is a reason to wait, not to overpay. The backlog is visible
    /// in the retrieval API and anchors later.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fee_above_the_cap_defers_rather_than_overpays() {
        let dir = temp_dir();
        write_roots(&dir.0, 1);
        let node = MockNode::start(CHAIN_ID).await;
        let chain = chain_for(&node).await;

        let capped = PassOpts {
            max_fee_gwei: 0,
            ..opts()
        };
        assert!(pass(&dir.0, &chain, &capped).await.is_err());
        assert!(
            !anchors_path(&dir.0).exists() || lines(&dir.0).is_empty(),
            "nothing may be written when nothing was submitted"
        );

        // The status file still gets written on the next ordinary pass, so a
        // deferring worker is not indistinguishable from a dead one.
        pass(&dir.0, &chain, &opts()).await.unwrap_or_else(|e| panic!("{}", e));
        let status: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(status_path(&dir.0)).unwrap_or_default(),
        )
        .unwrap_or(serde_json::Value::Null);
        assert_eq!(status["chain_id"], CHAIN_ID);
        assert_eq!(status["roots_unanchored"], 1);
        assert!(status["anchor_balance_wei"].is_string());
    }
}
