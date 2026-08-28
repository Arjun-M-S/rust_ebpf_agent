//! A JSON-RPC node, in about as few lines as one can be written.
//!
//! Test-only. It exists because the parts of this worker that matter -- the
//! crash-safe submit/confirm protocol, same-nonce resubmission, reorg handling
//! -- are exactly the parts that cannot be exercised against a real chain in
//! CI: they need a funded key, a live endpoint, and the ability to make a
//! transaction vanish on demand.
//!
//! It speaks enough of the protocol for `alloy` over HTTP: eth_chainId,
//! eth_blockNumber, eth_getBlockByNumber, eth_getTransactionCount,
//! eth_getBalance, eth_estimateGas, eth_maxPriorityFeePerGas,
//! eth_sendRawTransaction and eth_getTransactionByHash. A submitted transaction
//! is remembered by its keccak hash, exactly as a node would, so the worker's
//! own hash computation is checked against an independent one rather than
//! against itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::keccak256;

/// What the fake node knows.
#[derive(Default)]
pub struct ChainState {
    /// tx hash (0x-prefixed, lowercase) -> block number it was mined in, if any.
    pub txs: HashMap<String, Option<u64>>,
    pub head: u64,
    pub nonce: u64,
    pub balance: u128,
    /// Set to make every eth_sendRawTransaction fail, as an unreachable or
    /// rejecting node would.
    pub reject_sends: bool,
    /// Every raw transaction the node was handed, in order.
    pub received: Vec<Vec<u8>>,
}

pub struct MockNode {
    pub url: String,
    pub state: Arc<Mutex<ChainState>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl MockNode {
    pub async fn start(chain_id: u64) -> MockNode {
        let state = Arc::new(Mutex::new(ChainState {
            head: 100,
            balance: 1_000_000_000_000_000_000,
            ..Default::default()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("mock node cannot bind: {}", e));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("mock node has no address: {}", e))
            .port();

        let shared = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    serve_one(sock, shared, chain_id).await;
                });
            }
        });

        MockNode {
            url: format!("http://127.0.0.1:{}", port),
            state,
            handle,
        }
    }

    /// Mine everything currently in the mempool into the next block.
    pub fn mine(&self) {
        let mut s = self.lock();
        s.head += 1;
        let head = s.head;
        for slot in s.txs.values_mut() {
            if slot.is_none() {
                *slot = Some(head);
            }
        }
        // Every mined transaction consumed its nonce.
        s.nonce = s.txs.values().filter(|b| b.is_some()).count() as u64;
    }

    /// Advance the head without mining anything, to reach a confirmation depth.
    pub fn advance(&self, blocks: u64) {
        self.lock().head += blocks;
    }

    /// Make a transaction disappear, as a dropped mempool entry or a reorg
    /// would.
    pub fn forget(&self, tx: &str) {
        self.lock().txs.remove(&tx.to_lowercase());
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

async fn serve_one(mut sock: tokio::net::TcpStream, state: Arc<Mutex<ChainState>>, chain_id: u64) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read headers, then exactly Content-Length bytes of body.
    let body = loop {
        let Ok(n) = sock.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        let Some(split) = text.find("\r\n\r\n") else {
            continue;
        };
        let head = text[..split].to_lowercase();
        let len: usize = head
            .split("content-length:")
            .nth(1)
            .and_then(|rest| rest.split('\r').next())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let body_start = split + 4;
        if buf.len() >= body_start + len {
            break String::from_utf8_lossy(&buf[body_start..body_start + len]).to_string();
        }
    };

    let req: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let id = req.get("id").cloned().unwrap_or(serde_json::json!(1));
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req
        .get("params")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let result = handle(method, &params, &state, chain_id);
    let payload = match result {
        Ok(value) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": value}),
        Err(message) => serde_json::json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": -32000, "message": message}
        }),
    }
    .to_string();

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
}

fn hex_u64(v: u64) -> serde_json::Value {
    serde_json::json!(format!("{:#x}", v))
}

fn handle(
    method: &str,
    params: &[serde_json::Value],
    state: &Arc<Mutex<ChainState>>,
    chain_id: u64,
) -> Result<serde_json::Value, String> {
    let mut s = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match method {
        "eth_chainId" => Ok(hex_u64(chain_id)),
        "eth_blockNumber" => Ok(hex_u64(s.head)),
        "eth_getTransactionCount" => Ok(hex_u64(s.nonce)),
        "eth_getBalance" => Ok(serde_json::json!(format!("{:#x}", s.balance))),
        "eth_estimateGas" => Ok(hex_u64(22_000)),
        "eth_maxPriorityFeePerGas" => Ok(hex_u64(1_000_000)),
        "eth_gasPrice" => Ok(hex_u64(2_000_000)),
        "eth_getBlockByNumber" => {
            let number = match params.first().and_then(|p| p.as_str()) {
                Some("latest") | None => s.head,
                Some(hex) => u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(s.head),
            };
            Ok(block_json(number))
        }
        "eth_sendRawTransaction" => {
            if s.reject_sends {
                return Err("the node is refusing transactions".to_string());
            }
            let raw = params
                .first()
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .trim_start_matches("0x");
            let bytes = alloy::hex::decode(raw).map_err(|e| format!("bad raw tx: {}", e))?;
            // The hash a node computes, independently of the one the worker
            // computed -- so a mistake in either shows up as a mismatch.
            let hash = format!("{:#x}", keccak256(&bytes));
            s.received.push(bytes);
            s.txs.entry(hash.clone()).or_insert(None);
            Ok(serde_json::json!(hash))
        }
        "eth_getTransactionByHash" => {
            let want = params
                .first()
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_lowercase();
            match s.txs.get(&want) {
                None => Ok(serde_json::Value::Null),
                Some(block) => Ok(serde_json::json!({
                    "hash": want,
                    "nonce": "0x0",
                    "blockHash": block.map(|b| format!("{:#066x}", b)),
                    "blockNumber": block.map(hex_u64),
                    "transactionIndex": block.map(|_| "0x0"),
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000001",
                    "value": "0x0",
                    "gas": "0x5622",
                    "gasPrice": "0x1e8480",
                    "maxFeePerGas": "0x1e8480",
                    "maxPriorityFeePerGas": "0xf4240",
                    "input": "0x",
                    "chainId": hex_u64(chain_id),
                    "type": "0x2",
                    "accessList": [],
                    "v": "0x0",
                    "r": "0x1",
                    "s": "0x1",
                })),
            }
        }
        other => Err(format!("mock node does not implement {}", other)),
    }
}

fn block_json(number: u64) -> serde_json::Value {
    serde_json::json!({
        "number": hex_u64(number),
        "hash": format!("{:#066x}", number),
        "parentHash": format!("{:#066x}", number.saturating_sub(1)),
        "sha3Uncles": format!("{:#066x}", 0),
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "transactionsRoot": format!("{:#066x}", 0),
        "stateRoot": format!("{:#066x}", 0),
        "receiptsRoot": format!("{:#066x}", 0),
        "miner": "0x0000000000000000000000000000000000000000",
        "mixHash": format!("{:#066x}", 0),
        "nonce": "0x0000000000000000",
        "withdrawalsRoot": format!("{:#066x}", 0),
        "withdrawals": [],
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x100",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x5622",
        "timestamp": hex_u64(1_756_000_000 + number),
        "baseFeePerGas": "0x7",
        "transactions": [],
        "uncles": [],
    })
}
