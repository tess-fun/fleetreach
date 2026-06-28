//! Env-gated micro-benchmark of the reach-side pipeline (parse → merge →
//! analyze) on a realistic graph. Point REACH_BENCH_FRAGS at a directory of
//! driver fragments and run with --ignored --nocapture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;

use fleetreach_reach::{analyze_paths, merge, parse_graph};

#[test]
#[ignore = "set REACH_BENCH_FRAGS and run with --ignored --nocapture"]
fn bench_reach_side() {
    let Ok(dir) = std::env::var("REACH_BENCH_FRAGS") else {
        eprintln!("set REACH_BENCH_FRAGS");
        return;
    };
    let t = Instant::now();
    let mut graphs = Vec::new();
    let mut bytes = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) == Some("json") {
            let s = std::fs::read_to_string(&p).unwrap();
            bytes += s.len();
            graphs.push(parse_graph(&s).unwrap());
        }
    }
    let parse = t.elapsed();
    let nodes: usize = graphs.iter().map(|g| g.nodes.len()).sum();
    let edges: usize = graphs.iter().map(|g| g.edges.len()).sum();

    let t = Instant::now();
    let whole = merge(&graphs).unwrap();
    let merge_t = t.elapsed();

    let sinks = vec![
        "serde_json::to_string".to_string(),
        "serde::de::Deserialize::deserialize".to_string(),
    ];
    let t = Instant::now();
    let v = analyze_paths(&whole, &sinks).unwrap();
    let analyze = t.elapsed();

    eprintln!(
        "BENCH  fragments={} nodes={} edges={} bytes={}KB | parse={:?} merge={:?} (->{} nodes,{} edges) analyze={:?} | verdicts={}",
        graphs.len(), nodes, edges, bytes/1024, parse, merge_t, whole.nodes.len(), whole.edges.len(), analyze, v.len()
    );
}
