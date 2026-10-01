//! AI inference gate probe - separates queue wait from real inference cost.
//!
//! The AI layer is wrapped in a bounded gate (`EVERBLOOM_AI_MAX_IN_FLIGHT`
//! permits, `EVERBLOOM_AI_QUEUE_TIMEOUT_MS` wait) and dispatches the actual
//! ONNX run through a dedicated rayon pool. A latency number taken from the
//! scanner therefore mixes three different things - queue wait, the pool hop,
//! and the model run - and cannot be attributed from the outside. This probe
//! reports them separately using the engine's own counters.
//!
//! Two modes matter:
//!
//! * `serial` calls `infer_path` from the main thread.
//! * `par` reproduces the scanner's real nesting: `rayon` `into_par_iter`
//!   (the scanner pins the global pool via `build_global()`) with
//!   `infer_path` called from inside each worker.
//!
//! The difference between the two is the whole point. On the shipped model and
//! a 7 KiB sample, `serial` measures ~4 ms per inference while `par` measured
//! 5-18 s before the cross-pool dispatch was removed - a mismatch that is
//! invisible from the scanner side and was mistaken for a slow model.
//!
//! Usage:
//!   cargo run --release --example ai_probe -- <model.onnx> <sample> <count> [serial|par]
//!
//! Environment: `EVERBLOOM_SCAN_THREADS` (global pool size, default 4),
//! `EVERBLOOM_AI_THREADS`, `EVERBLOOM_AI_MAX_IN_FLIGHT`,
//! `EVERBLOOM_AI_QUEUE_TIMEOUT_MS`.

use std::path::Path;
use std::time::Instant;

use everbloom_engine::layers::ai::{ai_runtime_metrics, AiModel, AiModelKind};
use rayon::prelude::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let model_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "everbloom_feature_cnn.onnx".to_string());
    let sample = args.get(2).cloned().unwrap_or_else(|| {
        "artifacts/ml-corpus/synthetic/samples/benign_like_000000_4433c92dceb6.bin".to_string()
    });
    let count: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(12);
    let mode = args.get(4).cloned().unwrap_or_else(|| "serial".to_string());

    // Mimic scanner.rs: it pins the *global* rayon pool via build_global().
    let scan_threads: usize = std::env::var("EVERBLOOM_SCAN_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(scan_threads)
        .build_global();
    println!(
        "mode={mode} scan_threads={scan_threads} available={:?}",
        std::thread::available_parallelism()
    );

    let t0 = Instant::now();
    let model = AiModel::new_with_kind(Path::new(&model_path), AiModelKind::CNN)
        .expect("model load")
        .with_ensemble(true);
    println!("model load wall = {} ms", t0.elapsed().as_millis());

    let before = ai_runtime_metrics();
    let started = Instant::now();

    if mode == "par" {
        let results: Vec<(usize, Result<f32, String>, u128)> = (0..count)
            .into_par_iter()
            .map(|i| {
                let s = Instant::now();
                let r = model
                    .infer_path(Path::new(&sample))
                    .map(|sc| sc.score)
                    .map_err(|e| e.to_string());
                (i, r, s.elapsed().as_millis())
            })
            .collect();
        let mut ok = 0;
        let mut errs: Vec<(usize, String, u128)> = Vec::new();
        for (i, r, ms) in results {
            match r {
                Ok(_) => ok += 1,
                Err(e) => errs.push((i, e, ms)),
            }
        }
        println!(
            "par: ok={ok} err={} wall={} ms",
            errs.len(),
            started.elapsed().as_millis()
        );
        for (i, e, ms) in errs.iter().take(5) {
            println!("   [{i}] {ms} ms {e}");
        }
    } else {
        let mut ok = 0usize;
        let mut err = 0usize;
        for i in 0..count {
            let s = Instant::now();
            match model.infer_path(Path::new(&sample)) {
                Ok(sc) => {
                    ok += 1;
                    if i < 3 || i + 1 == count {
                        println!(
                            "  [{i}] ok score={:.6} wall={} ms fallback={}",
                            sc.score,
                            s.elapsed().as_millis(),
                            sc.is_fallback
                        );
                    }
                }
                Err(e) => {
                    err += 1;
                    println!("  [{i}] ERR wall={} ms {e}", s.elapsed().as_millis());
                }
            }
        }
        println!(
            "serial: ok={ok} err={err} wall={} ms",
            started.elapsed().as_millis()
        );
    }

    let after = ai_runtime_metrics();
    let dn = after.inference_requests - before.inference_requests;
    let dq = after.queue_wait_us - before.queue_wait_us;
    let di = after.inference_time_us - before.inference_time_us;
    println!(
        "metrics: requests={dn} queue_wait_total={:.3} ms inference_total={:.3} ms rejections={}",
        dq as f64 / 1000.0,
        di as f64 / 1000.0,
        after.queue_rejections - before.queue_rejections
    );
    if dn > 0 {
        println!(
            "per-request: queue_wait={:.3} ms inference={:.3} ms",
            dq as f64 / 1000.0 / dn as f64,
            di as f64 / 1000.0 / dn as f64
        );
    }
}
