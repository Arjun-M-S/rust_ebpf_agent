//! Read-only alert dashboard.
//!
//! This runs on its OWN listener, separate from /v1/ingest. That separation is
//! the point rather than tidiness: the ingest socket has to be reachable by the
//! proxy, and the proxy is not trusted (PRX-1/PRX-2). Serving the fleet's
//! telemetry from the same socket would hand every alert on every host to the
//! one component the threat model already assumes is hostile. Ingest is
//! write-only and authenticated by MAC; this is read-only and must never leave
//! the analyst network.
//!
//! Everything here reads what `ingest` already wrote. No second store, no
//! database, no cache to fall out of step with the event log.

use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::{events_path, App};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// The dashboard is a stored-XSS target: `process_name` and `filename` are
/// chosen by whoever executed the binary. The page renders with textContent
/// everywhere, and this is the second layer -- an injection that does land
/// still cannot load an external script or phone home, because `connect-src
/// 'self'` and `default-src 'none'` block it. Inline script/style are allowed
/// because the page is a single self-contained file with no CDN to trust.
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                   connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; \
                   frame-ancestors 'none'";

/// How much of the tail of one host's event log a single request will read.
///
/// ponytail: tail-scan, not an index. Event logs are append-only NDJSON and the
/// dashboard only ever wants the recent end, so seeking to `len - N` and
/// parsing forward is O(window) instead of O(file). If someone needs to query
/// six months back, that is a real index (sqlite over the same NDJSON), not a
/// bigger window.
const TAIL_BYTES: u64 = 4 * 1024 * 1024;

/// Per-host budget when scanning the whole fleet, so an "all hosts" view does
/// not read TAIL_BYTES * hosts on every poll.
const FLEET_TAIL_BYTES: u64 = 512 * 1024;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 2000;

pub fn routes(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/overview", get(overview))
        .route("/api/alerts", get(alerts))
        .route("/api/host/{host}", get(host_detail))
        .with_state(Arc::clone(&app))
        // Retrieval and proofs. On THIS socket and never the ingest one: these
        // enumerate records and hand out record content, and the ingest port is
        // reachable by a proxy the threat model already treats as hostile.
        .merge(crate::proof::routes(app))
}

async fn page() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(CSP),
            ),
            // The page ships inside the binary, so a cached copy is a copy of
            // an older build. Never keep it.
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
        ],
        DASHBOARD_HTML,
    )
}

// ---------------------------------------------------------
// Tail reading
// ---------------------------------------------------------

/// Read the last `max_bytes` of a file as whole lines.
///
/// Reads bytes rather than a String because the seek lands at an arbitrary
/// offset that can be mid-codepoint: serde_json emits raw UTF-8 for non-ASCII
/// process names, so `read_to_string` would fail on exactly the records most
/// worth looking at. The first line is dropped when we seeked, since it is a
/// fragment of whatever record straddled the boundary.
fn tail_lines(path: &std::path::Path, max_bytes: u64) -> Vec<String> {
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(meta) = f.metadata() else {
        return Vec::new();
    };
    let start = meta.len().saturating_sub(max_bytes);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }

    let mut buf = Vec::with_capacity(max_bytes.min(meta.len()) as usize + 1);
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Flatten a stored line into the one shape the UI renders.
///
/// Two kinds live in the same log: sealed records written by the agent, and
/// collector-generated markers (CHAIN_BREAK, BUILD_MISMATCH) which have no MAC
/// because the collector wrote them itself. Markers are always shown as
/// unverified and always CRITICAL -- they exist only to record that something
/// about the chain did not add up.
fn normalize(host: &str, v: &Value) -> Option<Value> {
    if let Some(kind) = v.get("collector_event").and_then(Value::as_str) {
        return Some(json!({
            "kind": "collector",
            "host": host,
            "severity": "CRITICAL",
            "received_at": v.get("received_at").and_then(Value::as_str).unwrap_or(""),
            "timestamp": v.get("received_at").and_then(Value::as_str).unwrap_or(""),
            "segment": v.get("segment").and_then(Value::as_u64).unwrap_or(0),
            "verified": false,
            "event_type": kind,
            "seq": v.get("at_seq").and_then(Value::as_u64).unwrap_or(0),
            "detail": v.get("detail").and_then(Value::as_str).unwrap_or(""),
            "expected_seq": v.get("expected_seq"),
            "expected_prev_hash": v.get("expected_prev_hash"),
            "expected_build": v.get("expected_build"),
            "reported_build": v.get("reported_build"),
        }));
    }

    let rec = v.get("record")?;
    let s = |k: &str| rec.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let n = |k: &str| rec.get(k).and_then(Value::as_u64).unwrap_or(0);

    Some(json!({
        "kind": "record",
        "host": host,
        "severity": s("severity"),
        "received_at": v.get("received_at").and_then(Value::as_str).unwrap_or(""),
        "segment": v.get("segment").and_then(Value::as_u64).unwrap_or(0),
        "verified": v.get("verified").and_then(Value::as_bool).unwrap_or(false),
        "seq": n("seq"),
        "epoch": n("epoch"),
        "timestamp": s("timestamp"),
        "event_type": s("event_type"),
        "uid": n("uid"),
        "pid": n("pid"),
        "ppid": n("ppid"),
        "cgroup_id": n("cgroup_id"),
        "process_name": s("process_name"),
        "parent_process_name": s("parent_process_name"),
        "filename": s("filename"),
        "binary_id": s("binary_id"),
        "hash": s("hash"),
        "prev_hash": s("prev_hash"),
    }))
}

fn is_alert(row: &Value) -> bool {
    if row.get("kind").and_then(Value::as_str) == Some("collector") {
        return true;
    }
    // An unverified record is an alert regardless of what severity the agent
    // assigned it: the severity field is part of what failed to verify.
    if row.get("verified").and_then(Value::as_bool) == Some(false) {
        return true;
    }
    !matches!(
        row.get("severity").and_then(Value::as_str),
        Some("INFO") | None
    )
}

// ---------------------------------------------------------
// /api/alerts
// ---------------------------------------------------------

#[derive(Deserialize)]
struct AlertQuery {
    host: Option<String>,
    severity: Option<String>,
    /// Include INFO-severity records, which are the overwhelming majority.
    #[serde(default)]
    all: bool,
    limit: Option<usize>,
}

async fn alerts(State(app): State<Arc<App>>, Query(q): Query<AlertQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    // Names only, under the registry guard, released immediately. The alert
    // data itself comes from tailing the events files, which needs no host
    // lock at all -- so a read here never sits behind an ingest fsync.
    let wanted: Vec<String> = {
        let hosts = app.hosts.lock().await;
        match q.host.as_deref() {
            Some(h) if !h.is_empty() => {
                if hosts.contains_key(h) {
                    vec![h.to_string()]
                } else {
                    Vec::new()
                }
            }
            _ => hosts.keys().cloned().collect(),
        }
    };

    let budget = if wanted.len() > 1 {
        FLEET_TAIL_BYTES
    } else {
        TAIL_BYTES
    };
    let dir = app.data_dir.clone();
    let severity = q.severity.clone().unwrap_or_default();
    let all = q.all;

    // Blocking file IO off the async threads. Same pattern the shipper uses for
    // its WAL reads.
    let rows = tokio::task::spawn_blocking(move || {
        let mut rows: Vec<Value> = Vec::new();
        for host in &wanted {
            let path = events_path(&dir, host);
            for line in tail_lines(&path, budget) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let Some(row) = normalize(host, &v) else {
                    continue;
                };
                if !all && !is_alert(&row) {
                    continue;
                }
                if !severity.is_empty()
                    && row.get("severity").and_then(Value::as_str) != Some(severity.as_str())
                {
                    continue;
                }
                rows.push(row);
            }
        }
        // Newest first. received_at is the collector's own clock, which is the
        // only timestamp in the record an attacker on the host cannot move
        // (NOW-7), so it is what we order by.
        rows.sort_by(|a, b| {
            let ka = a.get("received_at").and_then(Value::as_str).unwrap_or("");
            let kb = b.get("received_at").and_then(Value::as_str).unwrap_or("");
            kb.cmp(ka)
        });
        rows.truncate(limit);
        rows
    })
    .await
    .unwrap_or_default();

    Json(json!({ "alerts": rows, "count": rows.len() }))
}

// ---------------------------------------------------------
// /api/overview
// ---------------------------------------------------------

async fn overview(State(app): State<Arc<App>>) -> impl IntoResponse {
    // Registry guard released before any host lock (see LOCK ORDER on `App`).
    let hosts = app.host_snapshot().await;

    let mut list: Vec<Value> = Vec::with_capacity(hosts.len());
    let mut total_records = 0u64;
    let mut total_breaks = 0u64;
    let mut silent = 0u64;

    for (name, entry) in hosts.iter() {
        let h = entry.lock().await;
        total_records += h.state.total_records;
        total_breaks += h.state.breaks;
        if h.state.silent {
            silent += 1;
        }
        list.push(json!({
            "host": name,
            "high_seq": h.state.high_seq,
            "epoch": h.state.high_epoch,
            "records": h.state.total_records,
            "breaks": h.state.breaks,
            "segment": h.state.segment,
            "last_seen": h.state.last_seen,
            "silent": h.state.silent,
            "enrolled_at": h.enrollment.enrolled_at,
            "expected_build": h.enrollment.build_id,
            "reported_build": h.state.last_build,
            "build_mismatch": match (&h.enrollment.build_id, &h.state.last_build) {
                (Some(want), Some(got)) => want != got,
                _ => false,
            },
        }));
    }

    list.sort_by(|a, b| {
        let ka = a.get("host").and_then(Value::as_str).unwrap_or("");
        let kb = b.get("host").and_then(Value::as_str).unwrap_or("");
        ka.cmp(kb)
    });

    Json(json!({
        "hosts": list,
        "fleet": {
            "enrolled": list.len(),
            "silent": silent,
            "total_records": total_records,
            "total_breaks": total_breaks,
        }
    }))
}

// ---------------------------------------------------------
// /api/host/{host}
// ---------------------------------------------------------

async fn host_detail(
    State(app): State<Arc<App>>,
    UrlPath(host): UrlPath<String>,
) -> impl IntoResponse {
    let Some(entry) = app.hosts.lock().await.get(&host).map(Arc::clone) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such enrolled host"})),
        );
    };
    let h = entry.lock().await;
    (
        StatusCode::OK,
        Json(json!({
            "host": host,
            "high_seq": h.state.high_seq,
            "epoch": h.state.high_epoch,
            "records": h.state.total_records,
            "breaks": h.state.breaks,
            "segment": h.state.segment,
            "last_seen": h.state.last_seen,
            "silent": h.state.silent,
            "last_mac": h.state.last_mac,
            "enrolled_at": h.enrollment.enrolled_at,
            "expected_build": h.enrollment.build_id,
            "reported_build": h.state.last_build,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_and_records_both_normalize() {
        let marker = serde_json::json!({
            "received_at": "2026-08-17T10:00:00+00:00",
            "segment": 3,
            "collector_event": "CHAIN_BREAK",
            "at_seq": 99,
            "detail": "sequence gap",
        });
        let row = normalize("web-1", &marker).expect("marker normalizes");
        assert_eq!(row["kind"], "collector");
        assert_eq!(row["severity"], "CRITICAL");
        assert_eq!(row["verified"], false);
        assert!(is_alert(&row));

        let stored = serde_json::json!({
            "received_at": "2026-08-17T10:00:01+00:00",
            "segment": 0,
            "verified": true,
            "record": { "seq": 5, "severity": "INFO", "process_name": "bash" },
        });
        let row = normalize("web-1", &stored).expect("record normalizes");
        assert_eq!(row["kind"], "record");
        assert_eq!(row["process_name"], "bash");
        // A verified INFO record is noise, not an alert.
        assert!(!is_alert(&row));
    }

    /// The severity field is inside the MAC, so a record that failed to verify
    /// has a severity we cannot believe. It must surface regardless.
    #[test]
    fn unverified_info_record_is_still_an_alert() {
        let stored = serde_json::json!({
            "received_at": "2026-08-17T10:00:02+00:00",
            "segment": 1,
            "verified": false,
            "record": { "seq": 6, "severity": "INFO", "process_name": "bash" },
        });
        let row = normalize("web-1", &stored).unwrap();
        assert!(is_alert(&row));
    }

    #[test]
    fn tail_drops_the_partial_first_line() {
        let dir = std::env::temp_dir().join("edr-dash-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("tail.ndjson");
        std::fs::write(&p, "AAAAAAAAAA\nsecond\nthird\n").unwrap();

        // Whole file: nothing was skipped, so every line is intact.
        assert_eq!(tail_lines(&p, 1024).len(), 3);

        // Window lands mid-way through line one, so it is a fragment and goes.
        let got = tail_lines(&p, 14);
        assert!(!got.iter().any(|l| l.contains("AAAA")), "got {:?}", got);
        assert_eq!(got.last().map(String::as_str), Some("third"));
    }
}
