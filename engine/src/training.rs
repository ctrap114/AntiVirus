//! Native AI training pipeline for the EverbloomSecurity detector.
//!
//! Trains small MLP classifiers on the canonical 12-dimensional runtime
//! feature representation ([`AiModel::extract_features`]) using an inert
//! synthetic corpus produced by [`crate::layers::synthetic`]. The experiment
//! compares a *baseline* model trained on benign-like and packed-like
//! families against an *augmented* model that also sees every other family,
//! quantifying how family-diverse synthetic samples improve generalization.
//!
//! The winning model is exported as ONNX with the Rust-compatible
//! `[batch, 1, feature_dim]` layout plus a `model_contract.json` sidecar, so
//! it can be imported through the existing engine model registry.
//!
//! Everything here is defensive tooling: the corpus is inert by construction
//! (single-RET entry points, embedded safety markers), and no executable
//! payload is ever created.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::layers::ai::AiModel;
use crate::layers::synthetic::{
    self, FAMILY_NAMES, SYNTHETIC_MARKER,
};

// ---------------------------------------------------------------------------
// Options and progress reporting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TrainingOptions {
    pub corpus_dir: PathBuf,
    pub counts: Vec<(&'static str, usize)>,
    pub seed: u64,
    pub epochs: usize,
    pub batch_size: usize,
    pub hidden_dim: usize,
    pub learning_rate: f32,
    pub validation_fraction: f32,
    pub test_fraction: f32,
    pub threshold: f32,
    pub force: bool,
    pub skip_generation: bool,
    pub out_model: PathBuf,
    pub report_path: PathBuf,
}

impl Default for TrainingOptions {
    fn default() -> Self {
        Self {
            corpus_dir: PathBuf::from("artifacts/ml-corpus/synthetic"),
            counts: vec![
                ("benign_like", 400),
                ("packed_like", 280),
                ("api_heavy_like", 220),
                ("stealth_like", 200),
                ("credential_stealer_like", 200),
                ("downloader_like", 180),
                ("ransomware_like", 180),
            ],
            seed: 2026,
            epochs: 80,
            batch_size: 64,
            hidden_dim: 64,
            learning_rate: 1e-3,
            validation_fraction: 0.15,
            test_fraction: 0.20,
            threshold: 0.5,
            force: false,
            skip_generation: false,
            out_model: PathBuf::from(
                "artifacts/models/synthetic_experiment/everbloom_synthetic_rust.onnx",
            ),
            report_path: PathBuf::from(
                "artifacts/quality-baseline/synthetic_experiment_rust.json",
            ),
        }
    }
}

/// Progress events streamed to callers (the CLI prints them as NDJSON so the
/// GUI can render live status).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum TrainingProgress {
    #[serde(rename = "stage")]
    Stage { name: String },
    #[serde(rename = "progress")]
    Progress { percent: f32, message: String },
    #[serde(rename = "epoch")]
    Epoch {
        epoch: u32,
        total_epochs: u32,
        loss: f32,
        accuracy: f64,
        best_accuracy: f64,
        model: String,
    },
    #[serde(rename = "comparison")]
    Comparison {
        baseline_accuracy: f64,
        augmented_accuracy: f64,
        accuracy_gain: f64,
        recall_gain: f64,
        selected_model: String,
        train_samples: usize,
        valid_samples: usize,
        test_samples: usize,
        families: Vec<String>,
    },
}

fn emit(progress: &mut dyn FnMut(TrainingProgress), percent: f32, message: impl Into<String>) {
    progress(TrainingProgress::Progress {
        percent: percent.clamp(0.0, 100.0),
        message: message.into(),
    });
}

// ---------------------------------------------------------------------------
// Dataset
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Sample {
    pub features: [f32; 12],
    pub label: f32,
    pub family: String,
}

fn load_manifest_samples(manifest: &Path) -> Result<Vec<Sample>, String> {
    let root = manifest.parent().unwrap_or_else(|| Path::new("."));
    let content = fs::read_to_string(manifest)
        .map_err(|error| format!("read manifest {}: {error}", manifest.display()))?;
    let mut samples = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("manifest line {}: {error}", line_number + 1))?;
        let relative = record["path"]
            .as_str()
            .ok_or_else(|| format!("manifest line {} missing path", line_number + 1))?;
        let label = record["label"]
            .as_f64()
            .map(|value| value as f32)
            .unwrap_or_default();
        let family = record["family"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let blob = fs::read(root.join(relative))
            .map_err(|error| format!("read sample {relative}: {error}"))?;
        if !blob
            .windows(SYNTHETIC_MARKER.len())
            .any(|window| window == SYNTHETIC_MARKER)
        {
            return Err(format!("safety marker missing from {relative}"));
        }
        samples.push(Sample {
            features: AiModel::extract_features(&blob),
            label,
            family,
        });
    }
    Ok(samples)
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

fn binary_metrics(scores: &[f32], labels: &[f32], threshold: f32) -> BinaryMetrics {
    let mut tp = 0usize;
    let mut tn = 0usize;
    let mut fp = 0usize;
    let mut fn_count = 0usize;
    for (&score, &label) in scores.iter().zip(labels.iter()) {
        let predicted = score >= threshold;
        let positive = label > 0.5;
        match (predicted, positive) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (true, false) => fp += 1,
            (false, true) => fn_count += 1,
        }
    }
    let total = (scores.len()).max(1);
    BinaryMetrics {
        accuracy: (tp + tn) as f64 / total as f64,
        precision: tp as f64 / (tp + fp).max(1) as f64,
        recall: tp as f64 / (tp + fn_count).max(1) as f64,
        false_positive_rate: fp as f64 / (fp + tn).max(1) as f64,
        false_negative_rate: fn_count as f64 / (fn_count + tp).max(1) as f64,
    }
}

// ---------------------------------------------------------------------------
// Stratified splitting (local LCG keeps this dependency-free)
// ---------------------------------------------------------------------------

struct SplitRng(u64);

impl SplitRng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 33)
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for end in (1..items.len()).rev() {
            let pick = (self.next() % (end + 1) as u64) as usize;
            items.swap(pick, end);
        }
    }
}

/// Per-family/per-label stratified split into train, validation and test
/// index sets.
pub fn stratified_split(
    samples: &[Sample],
    validation_fraction: f32,
    test_fraction: f32,
    seed: u64,
) -> Result<(Vec<usize>, Vec<usize>, Vec<usize>), String> {
    let mut rng = SplitRng(seed.wrapping_mul(0x9E37_79B9).wrapping_add(7));
    let mut groups: std::collections::BTreeMap<(String, i64), Vec<usize>> =
        std::collections::BTreeMap::new();
    for (index, sample) in samples.iter().enumerate() {
        groups
            .entry((sample.family.clone(), sample.label as i64))
            .or_default()
            .push(index);
    }

    let mut train = Vec::new();
    let mut valid = Vec::new();
    let mut test = Vec::new();
    for ((family, label), mut indexes) in groups {
        if indexes.len() < 4 {
            return Err(format!(
                "group {family}/label {label} has too few samples ({})",
                indexes.len()
            ));
        }
        rng.shuffle(&mut indexes);
        let total = indexes.len();
        let test_count = ((total as f32 * test_fraction).round() as usize).clamp(1, total - 2);
        let valid_count =
            ((total as f32 * validation_fraction).round() as usize).clamp(1, total - test_count - 1);
        test.extend_from_slice(&indexes[..test_count]);
        valid.extend_from_slice(&indexes[test_count..test_count + valid_count]);
        train.extend_from_slice(&indexes[test_count + valid_count..]);
    }
    Ok((train, valid, test))
}

// ---------------------------------------------------------------------------
// Minimal MLP with manual backpropagation and AdamW updates
// ---------------------------------------------------------------------------

/// Three-layer perceptron: `input → hidden → hidden/2 → 1` with ReLU
/// activations and a single logit output.
pub struct Mlp {
    input_dim: usize,
    hidden: usize,
    hidden2: usize,
    w1: Vec<f32>,
    b1: Vec<f32>,
    w2: Vec<f32>,
    b2: Vec<f32>,
    w3: Vec<f32>,
    b3: f32,
}

struct AdamState {
    m: Vec<f32>,
    v: Vec<f32>,
    t: u64,
}

impl AdamState {
    fn new(size: usize) -> Self {
        Self {
            m: vec![0.0; size],
            v: vec![0.0; size],
            t: 0,
        }
    }

    fn update(&mut self, param: &mut [f32], grad: &[f32], lr: f32) {
        const BETA1: f32 = 0.9;
        const BETA2: f32 = 0.999;
        const EPS: f32 = 1e-8;
        const WEIGHT_DECAY: f32 = 1e-4;
        self.t += 1;
        let bias1 = 1.0 - BETA1.powi(self.t as i32);
        let bias2 = 1.0 - BETA2.powi(self.t as i32);
        for index in 0..param.len() {
            self.m[index] = BETA1 * self.m[index] + (1.0 - BETA1) * grad[index];
            self.v[index] = BETA2 * self.v[index] + (1.0 - BETA2) * grad[index] * grad[index];
            let m_hat = self.m[index] / bias1;
            let v_hat = self.v[index] / bias2;
            param[index] -= lr * (m_hat / (v_hat.sqrt() + EPS) + WEIGHT_DECAY * param[index]);
        }
    }
}

impl Mlp {
    fn new(input_dim: usize, hidden: usize, seed: u64) -> Self {
        // He initialization keeps early activations in a sane range.
        let mut rng = SplitRng(seed.wrapping_mul(0xD1B5_4A32).wrapping_add(13));
        let mut he = |fan_in: usize| -> Vec<f32> {
            let scale = (2.0 / fan_in as f32).sqrt();
            (0..fan_in)
                .map(|_| {
                    let draw = rng.next();
                    // Uniform(-1,1)*scale*sqrt(3) approximates He for ReLU.
                    let unit = ((draw % 20_000) as f32 / 10_000.0) - 1.0;
                    unit * scale * 1.732f32
                })
                .collect()
        };
        let hidden2 = (hidden / 2).max(4);
        Self {
            input_dim,
            hidden,
            hidden2,
            w1: he(input_dim * hidden),
            b1: vec![0.0; hidden],
            w2: he(hidden * hidden2),
            b2: vec![0.0; hidden2],
            w3: he(hidden2),
            b3: 0.0,
        }
    }

    /// Forward pass over a batch; returns per-sample logits.
    fn forward(&self, x: &[f32], count: usize) -> Vec<f32> {
        let dim = self.input_dim;
        let mut logits = Vec::with_capacity(count);
        for index in 0..count {
            let row = &x[index * dim..(index + 1) * dim];
            // Layer 1 + ReLU
            let mut h1 = vec![0.0f32; self.hidden];
            for unit in 0..self.hidden {
                let weights = &self.w1[unit * dim..(unit + 1) * dim];
                let z: f32 = weights.iter().zip(row.iter()).map(|(w, v)| w * v).sum::<f32>()
                    + self.b1[unit];
                h1[unit] = z.max(0.0);
            }
            // Layer 2 + ReLU
            let mut h2 = vec![0.0f32; self.hidden2];
            for unit in 0..self.hidden2 {
                let weights = &self.w2[unit * self.hidden..(unit + 1) * self.hidden];
                let z: f32 = weights
                    .iter()
                    .zip(h1.iter())
                    .map(|(w, v)| w * v)
                    .sum::<f32>()
                    + self.b2[unit];
                h2[unit] = z.max(0.0);
            }
            // Output layer
            let logit: f32 =
                self.w3.iter().zip(h2.iter()).map(|(w, v)| w * v).sum::<f32>() + self.b3;
            logits.push(logit);
        }
        logits
    }

    /// Compute the weighted BCE-with-logits loss and gradients over the full
    /// batch. Parameter updates happen separately via [`Trainer::step`] so the
    /// AdamW moment buffers survive across steps.
    fn compute_gradients(
        &self,
        x: &[f32],
        labels: &[f32],
        pos_weight: f32,
    ) -> (f32, Gradients) {
        let count = labels.len();
        let dim = self.input_dim;
        let logits = self.forward(x, count);

        // Gradient of weighted BCE-with-logits:
        // dL/dz = sigma(z) * (pos_weight*y + 1 - y) - pos_weight*y
        let mut dz = vec![0.0f32; count];
        let mut loss = 0.0f32;
        for index in 0..count {
            let z = logits[index];
            let y = labels[index];
            let sigma = 1.0 / (1.0 + (-z).exp());
            loss += z.max(0.0) - z * y + ((-z.abs()).exp() + 1.0).ln();
            dz[index] = sigma * (pos_weight * y + 1.0 - y) - pos_weight * y;
        }
        for value in dz.iter_mut() {
            *value /= count as f32;
        }
        loss /= count as f32;

        // Backpropagate.
        let mut dw3 = vec![0.0f32; self.hidden2];
        let mut db3 = 0.0f32;
        let mut dw2 = vec![0.0f32; self.hidden2 * self.hidden];
        let mut db2 = vec![0.0f32; self.hidden2];
        let mut dw1 = vec![0.0f32; self.hidden * dim];
        let mut db1 = vec![0.0f32; self.hidden];

        for index in 0..count {
            let row = &x[index * dim..(index + 1) * dim];
            // Recompute activations (cheap at this scale).
            let mut h1 = vec![0.0f32; self.hidden];
            for unit in 0..self.hidden {
                let weights = &self.w1[unit * dim..(unit + 1) * dim];
                let z: f32 = weights.iter().zip(row.iter()).map(|(w, v)| w * v).sum::<f32>()
                    + self.b1[unit];
                h1[unit] = z.max(0.0);
            }
            let mut h2pre = vec![0.0f32; self.hidden2];
            for unit in 0..self.hidden2 {
                let weights = &self.w2[unit * self.hidden..(unit + 1) * self.hidden];
                h2pre[unit] =
                    weights.iter().zip(h1.iter()).map(|(w, v)| w * v).sum::<f32>() + self.b2[unit];
            }
            let d = dz[index];
            db3 += d;
            for unit in 0..self.hidden2 {
                dw3[unit] += d * h2pre[unit].max(0.0);
            }
            // Layer 2
            for unit in 0..self.hidden2 {
                if h2pre[unit] <= 0.0 {
                    continue; // ReLU gate: zero gradient
                }
                let dh2 = d * self.w3[unit];
                db2[unit] += dh2;
                for inner in 0..self.hidden {
                    dw2[unit * self.hidden + inner] += dh2 * h1[inner];
                }
            }
            // Layer 1
            for inner in 0..self.hidden {
                let mut dh1 = 0.0f32;
                for unit in 0..self.hidden2 {
                    if h2pre[unit] > 0.0 {
                        dh1 += d * self.w3[unit] * self.w2[unit * self.hidden + inner];
                    }
                }
                if dh1 == 0.0 {
                    continue;
                }
                // ReLU gate on layer 1 needs the pre-activation sign.
                let z1: f32 = self.w1[inner * dim..(inner + 1) * dim]
                    .iter()
                    .zip(row.iter())
                    .map(|(w, v)| w * v)
                    .sum::<f32>()
                    + self.b1[inner];
                if z1 <= 0.0 {
                    continue;
                }
                db1[inner] += dh1;
                for feature in 0..dim {
                    dw1[inner * dim + feature] += dh1 * row[feature];
                }
            }
        }

        // Global gradient clipping.
        let norm: f32 = dw3
            .iter()
            .chain(std::iter::once(&db3))
            .chain(dw2.iter())
            .chain(db2.iter())
            .chain(dw1.iter())
            .chain(db1.iter())
            .map(|g| g * g)
            .sum::<f32>()
            .sqrt();
        let scale = if norm > 5.0 { 5.0 / norm } else { 1.0 };
        for g in dw3
            .iter_mut()
            .chain(std::iter::once(&mut db3))
            .chain(dw2.iter_mut())
            .chain(db2.iter_mut())
            .chain(dw1.iter_mut())
            .chain(db1.iter_mut())
        {
            *g *= scale;
        }

        (
            loss,
            Gradients {
                w1: dw1,
                b1: db1,
                w2: dw2,
                b2: db2,
                w3: dw3,
                b3: vec![db3],
            },
        )
    }
}

/// Flattened gradient buffers mirroring [`Mlp`] parameters.
pub struct Gradients {
    pub w1: Vec<f32>,
    pub b1: Vec<f32>,
    pub w2: Vec<f32>,
    pub b2: Vec<f32>,
    pub w3: Vec<f32>,
    pub b3: Vec<f32>,
}

/// Owns a model plus persistent AdamW moment buffers.
pub struct Trainer {
    model: Mlp,
    states: OptStates,
}

struct OptStates {
    w1: AdamState,
    b1: AdamState,
    w2: AdamState,
    b2: AdamState,
    w3: AdamState,
    b3: AdamState,
}

impl Trainer {
    pub fn new(input_dim: usize, hidden_dim: usize, seed: u64) -> Self {
        let model = Mlp::new(input_dim, hidden_dim, seed);
        Self {
            states: OptStates {
                w1: AdamState::new(model.w1.len()),
                b1: AdamState::new(model.b1.len()),
                w2: AdamState::new(model.w2.len()),
                b2: AdamState::new(model.b2.len()),
                w3: AdamState::new(model.w3.len()),
                b3: AdamState::new(1),
            },
            model,
        }
    }

    /// One optimization step; returns the pre-update loss.
    fn step(&mut self, x: &[f32], labels: &[f32], pos_weight: f32, lr: f32) -> f32 {
        let (loss, grads) = self.model.compute_gradients(x, labels, pos_weight);
        let model = &mut self.model;
        let states = &mut self.states;
        states.w1.update(&mut model.w1, &grads.w1, lr);
        states.b1.update(&mut model.b1, &grads.b1, lr);
        states.w2.update(&mut model.w2, &grads.w2, lr);
        states.b2.update(&mut model.b2, &grads.b2, lr);
        states.w3.update(&mut model.w3, &grads.w3, lr);
        states
            .b3
            .update(std::slice::from_mut(&mut model.b3), &grads.b3, lr);
        loss
    }

    fn logits(&self, x: &[f32], count: usize) -> Vec<f32> {
        self.model.forward(x, count)
    }

    fn probabilities(&self, x: &[f32], count: usize) -> Vec<f32> {
        self.logits(x, count)
            .into_iter()
            .map(|z| 1.0 / (1.0 + (-z).exp()))
            .collect()
    }

    /// ONNX graph payload describing this exact network.
    fn onnx_bytes(&self) -> Result<Vec<u8>, String> {
        crate::onnx_export::export_mlp(
            self.model.input_dim,
            self.model.hidden,
            self.model.hidden2,
            &self.model.w1,
            &self.model.b1,
            &self.model.w2,
            &self.model.b2,
            &self.model.w3,
            self.model.b3,
        )
    }
}

// ---------------------------------------------------------------------------
// Experiment orchestration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReport {
    pub name: String,
    pub families: Vec<String>,
    pub train_samples: usize,
    pub valid_samples: usize,
    pub test_samples: usize,
    pub epochs_trained: usize,
    pub best_valid_accuracy: f64,
    pub test_metrics: BinaryMetrics,
    /// Detection rate (recall) for families containing malicious-like
    /// samples; benign-only families report 1 - false-positive rate.
    pub per_family_recall: std::collections::BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentReport {
    pub corpus_dir: String,
    pub sample_count: usize,
    pub seed: u64,
    pub threshold: f32,
    pub baseline: ModelReport,
    pub augmented: ModelReport,
    pub accuracy_gain: f64,
    pub recall_gain: f64,
    pub selected_model: String,
    pub onnx_path: String,
}

const BASELINE_FAMILIES: [&str; 2] = ["benign_like", "packed_like"];

fn train_one(
    name: &'static str,
    all: &[Sample],
    allowed_families: Option<&[&str]>,
    options: &TrainingOptions,
    progress: &mut dyn FnMut(TrainingProgress),
) -> Result<(ModelReport, Trainer), String> {
    let pool: Vec<Sample> = match allowed_families {
        Some(families) => all
            .iter()
            .filter(|sample| families.contains(&sample.family.as_str()))
            .cloned()
            .collect(),
        None => all.to_vec(),
    };
    if pool.is_empty() {
        return Err(format!("no samples available for {name}"));
    }

    let (train_idx, valid_idx, test_idx) = stratified_split(
        &pool,
        options.validation_fraction,
        options.test_fraction,
        options.seed.wrapping_add(17),
    )?;

    // Deterministic feature matrix ordering.
    let mut x = Vec::with_capacity(train_idx.len() * 12);
    let mut y = Vec::with_capacity(train_idx.len());
    for index in &train_idx {
        x.extend_from_slice(&pool[*index].features);
        y.push(pool[*index].label);
    }
    let positives = y.iter().filter(|v| **v > 0.5).count();
    let negatives = y.len() - positives;
    let pos_weight = negatives as f32 / positives.max(1) as f32;

    let mut trainer = Trainer::new(12, options.hidden_dim, options.seed.wrapping_add(91));
    let mut vx = Vec::with_capacity(valid_idx.len() * 12);
    let mut vy = Vec::with_capacity(valid_idx.len());
    for index in &valid_idx {
        vx.extend_from_slice(&pool[*index].features);
        vy.push(pool[*index].label);
    }

    let mut best_valid = 0.0f64;
    for epoch in 1..=options.epochs {
        let loss = trainer.step(&x, &y, pos_weight, options.learning_rate);
        let probs = trainer.probabilities(&vx, valid_idx.len());
        let valid_acc = binary_metrics(&probs, &vy, options.threshold).accuracy;
        best_valid = best_valid.max(valid_acc);
        progress(TrainingProgress::Epoch {
            epoch: epoch as u32,
            total_epochs: options.epochs as u32,
            loss,
            accuracy: valid_acc,
            best_accuracy: best_valid,
            model: name.to_string(),
        });
        emit(
            progress,
            (epoch as f32 / options.epochs as f32) * 100.0,
            format!("{name} epoch {epoch}/{} loss={loss:.4} valid_acc={valid_acc:.3}", options.epochs),
        );
    }

    let mut tx = Vec::with_capacity(test_idx.len() * 12);
    let mut ty = Vec::with_capacity(test_idx.len());
    for index in &test_idx {
        tx.extend_from_slice(&pool[*index].features);
        ty.push(pool[*index].label);
    }
    let scores = trainer.probabilities(&tx, test_idx.len());
    let metrics = binary_metrics(&scores, &ty, options.threshold);

    let mut per_family: std::collections::BTreeMap<String, Vec<(f32, f32)>> =
        std::collections::BTreeMap::new();
    for position in 0..test_idx.len() {
        per_family
            .entry(pool[test_idx[position]].family.clone())
            .or_default()
            .push((scores[position], ty[position]));
    }
    // Malware-like families report detection rate (recall); purely benign
    // families have no positive class, so they report benign specificity
    // (1 - false-positive rate) instead.
    let per_family_recall: std::collections::BTreeMap<String, f64> = per_family
        .iter()
        .map(|(family, pairs)| {
            let family_scores: Vec<f32> = pairs.iter().map(|(s, _)| *s).collect();
            let family_labels: Vec<f32> = pairs.iter().map(|(_, l)| *l).collect();
            let has_positives = family_labels.iter().any(|label| *label > 0.5);
            let family_metrics =
                binary_metrics(&family_scores, &family_labels, options.threshold);
            let value = if has_positives {
                family_metrics.recall
            } else {
                1.0 - family_metrics.false_positive_rate
            };
            (family.clone(), value)
        })
        .collect();

    let report = ModelReport {
        name: name.to_string(),
        families: match allowed_families {
            Some(list) => list.iter().map(|s| s.to_string()).collect(),
            None => FAMILY_NAMES.iter().map(|s| s.to_string()).collect(),
        },
        train_samples: train_idx.len(),
        valid_samples: valid_idx.len(),
        test_samples: test_idx.len(),
        epochs_trained: options.epochs,
        best_valid_accuracy: best_valid,
        test_metrics: metrics,
        per_family_recall,
    };
    Ok((report, trainer))
}

/// Returns true when an existing manifest is complete and every referenced
/// sample file still exists on disk, i.e. the corpus can be reused safely.
/// A manifest that is corrupted or whose samples were partially deleted is
/// not reusable.
fn corpus_is_usable(manifest: &Path) -> bool {
    if !manifest.is_file() {
        return false;
    }
    let root = manifest.parent().unwrap_or_else(|| Path::new("."));
    let Ok(content) = fs::read_to_string(manifest) else {
        return false;
    };
    let mut seen: usize = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        let Some(relative) = value.get("path").and_then(|path| path.as_str()) else {
            return false;
        };
        if !root.join(relative).is_file() {
            return false;
        }
        seen += 1;
    }
    seen > 0
}

/// Runs the full baseline-vs-augmented experiment and writes the winning
/// model plus report artifacts.
pub fn run_training(
    options: &TrainingOptions,
    progress: &mut dyn FnMut(TrainingProgress),
) -> Result<ExperimentReport, String> {
    // 1. Corpus (generate unless skipped).
    let manifest = options.corpus_dir.join("manifest.jsonl");
    if !options.skip_generation {
        progress(TrainingProgress::Stage {
            name: "generation".into(),
        });
        emit(progress, 0.0, "generating synthetic corpus");
        let reusable = !options.force && corpus_is_usable(&manifest);
        let counts: Vec<(&str, usize)> = if reusable {
            Vec::new() // reuse a complete, on-disk corpus
        } else {
            options.counts.clone()
        };
        if !counts.is_empty() {
            // force clears any partially-written stale samples so a manifest
            // missing its sample files (or an abandoned samples dir) cannot
            // wedge future training runs.
            synthetic::generate_corpus(&options.corpus_dir, &counts, options.seed, true)?;
        }
    }
    if !manifest.exists() {
        return Err(format!(
            "corpus manifest missing at {}; generate first",
            manifest.display()
        ));
    }

    // 2. Load + split.
    progress(TrainingProgress::Stage {
        name: "loading".into(),
    });
    let samples = load_manifest_samples(&manifest)?;
    if samples.is_empty() {
        return Err("corpus contains no samples".into());
    }
    emit(
        progress,
        5.0,
        format!("loaded {} feature vectors from manifest", samples.len()),
    );

    // 3. Baseline vs augmented (identical seeds/splits apart from family
    // visibility, so the delta isolates the corpus-diversity effect).
    let (baseline, baseline_trainer) =
        train_one("baseline", &samples, Some(&BASELINE_FAMILIES), options, progress)?;
    let (augmented, augmented_trainer) = train_one("augmented", &samples, None, options, progress)?;

    let accuracy_gain = augmented.test_metrics.accuracy - baseline.test_metrics.accuracy;
    let recall_gain = augmented.test_metrics.recall - baseline.test_metrics.recall;
    let selected_model = if accuracy_gain >= 0.0 { "augmented" } else { "baseline" };

    progress(TrainingProgress::Comparison {
        baseline_accuracy: baseline.test_metrics.accuracy,
        augmented_accuracy: augmented.test_metrics.accuracy,
        accuracy_gain,
        recall_gain,
        selected_model: selected_model.to_string(),
        train_samples: baseline.train_samples,
        valid_samples: baseline.valid_samples,
        test_samples: baseline.test_samples,
        families: baseline.families.clone(),
    });

    progress(TrainingProgress::Stage {
        name: "export".into(),
    });

    let report = ExperimentReport {
        corpus_dir: options.corpus_dir.to_string_lossy().to_string(),
        sample_count: samples.len(),
        seed: options.seed,
        threshold: options.threshold,
        accuracy_gain,
        recall_gain,
        selected_model: selected_model.to_string(),
        onnx_path: options.out_model.to_string_lossy().to_string(),
        baseline,
        augmented,
    };

    // 4. Persist the evaluated winner's exact weights.
    if let Some(parent) = options.out_model.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let onnx_bytes = match selected_model {
        "baseline" => baseline_trainer.onnx_bytes(),
        _ => augmented_trainer.onnx_bytes(),
    }?;
    fs::write(&options.out_model, onnx_bytes).map_err(|error| error.to_string())?;
    let mut contract_path = options.out_model.clone();
    contract_path.set_extension("json");
    let contract = serde_json::json!({
        "output_kind": "logit",
        "input_layout": ["batch", 1, 12],
        "feature_dim": 12,
        "synthetic_corpus_training": true,
        "threshold": options.threshold,
    });
    fs::write(
        &contract_path,
        serde_json::to_string_pretty(&contract).map_err(|e| e.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    if let Some(parent) = options.report_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        &options.report_path,
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    Ok(report)
}

// ---------------------------------------------------------------------------
// CLI surface (consumed by main.rs before the IPC server boots)
// ---------------------------------------------------------------------------

/// Parses `--train-synthetic` style arguments and runs the pipeline, printing
/// NDJSON progress lines to stdout. Returns the final report JSON string.
pub fn run_training_cli(args: &[String]) -> Result<String, String> {
    let mut options = TrainingOptions::default();
    let mut seed_explicit = false;
    let mut index = 0usize;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = |index: &mut usize| -> Result<String, String> {
            *index += 1;
            match args.get(*index) {
                Some(v) => Ok(v.clone()),
                None => Err(format!("missing value for {}", args[*index - 1])),
            }
        };
        match flag {
            "--train-synthetic" => {}
            "--corpus-dir" => options.corpus_dir = PathBuf::from(value(&mut index)?),
            "--out" => options.out_model = PathBuf::from(value(&mut index)?),
            "--report" => options.report_path = PathBuf::from(value(&mut index)?),
            "--epochs" => {
                options.epochs = value(&mut index)?.parse::<usize>().map_err(|e| e.to_string())?
            }
            "--hidden" => {
                options.hidden_dim = value(&mut index)?
                    .parse::<usize>()
                    .map_err(|e| e.to_string())?
            }
            "--seed" => {
                seed_explicit = true;
                options.seed = value(&mut index)?
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?
            }
            "--threshold" => {
                options.threshold = value(&mut index)?
                    .parse::<f32>()
                    .map_err(|e| e.to_string())?
            }
            "--force" => options.force = true,
            "--skip-generation" => options.skip_generation = true,
            other => return Err(format!("unknown training flag: {other}")),
        }
        index += 1;
    }

    if !seed_explicit {
        // Derive a fresh seed so repeated runs produce different corpora,
        // splits and initializers instead of an identical, pre-baked corpus.
        use std::time::{SystemTime, UNIX_EPOCH};
        options.seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(2026);
    }

    let report = run_training(&options, &mut |event| {
        // NDJSON progress protocol consumed by the GUI training runner.
        if let Ok(line) = serde_json::to_string(&event) {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout(), "{line}");
            let _ = std::io::stdout().flush();
        }
    })?;
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_options(root: &Path) -> TrainingOptions {
        TrainingOptions {
            corpus_dir: root.join("corpus"),
            counts: vec![
                ("benign_like", 24),
                ("packed_like", 16),
                ("api_heavy_like", 12),
                ("stealth_like", 12),
            ],
            seed: 7,
            epochs: 8,
            batch_size: 32,
            hidden_dim: 16,
            learning_rate: 2e-3,
            validation_fraction: 0.25,
            test_fraction: 0.25,
            threshold: 0.5,
            force: false,
            skip_generation: false,
            out_model: root.join("model.onnx"),
            report_path: root.join("report.json"),
        }
    }

    #[test]
    fn metrics_are_exact_on_known_cases() {
        let scores = vec![0.9f32, 0.6, 0.3, 0.1];
        let labels = vec![1.0f32, 0.0, 1.0, 0.0];
        let metrics = binary_metrics(&scores, &labels, 0.5);
        assert!((metrics.accuracy - 0.5).abs() < 1e-9);
        assert!((metrics.precision - 0.5).abs() < 1e-9);
        assert!((metrics.recall - 0.5).abs() < 1e-9);
        assert!((metrics.false_positive_rate - 0.5).abs() < 1e-9);
        assert!((metrics.false_negative_rate - 0.5).abs() < 1e-9);
        let perfect = binary_metrics(&labels, &labels, 0.5);
        assert!((perfect.accuracy - 1.0).abs() < 1e-9);
    }

    #[test]
    fn split_is_stratified_and_disjoint() {
        let samples: Vec<Sample> = (0..40)
            .map(|index| Sample {
                features: [0.0; 12],
                label: (index % 2) as f32,
                family: if index % 2 == 0 { "a" } else { "b" }.to_string(),
            })
            .collect();
        let (train, valid, test) = stratified_split(&samples, 0.2, 0.2, 3).expect("split");
        let mut seen = std::collections::BTreeSet::new();
        for index in train.iter().chain(&valid).chain(&test) {
            assert!(seen.insert(*index), "duplicate index {index}");
        }
        // Both labels must appear in each partition.
        for group in [&train, &valid, &test] {
            assert!(group.iter().any(|i| samples[*i].label > 0.5));
            assert!(group.iter().any(|i| samples[*i].label <= 0.5));
        }
    }

    #[test]
    fn end_to_end_training_exports_loadable_model() -> Result<(), String> {
        let root = std::env::temp_dir().join(format!("everbloom_train_e2e_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let options = tiny_options(&root);

        let mut stages = Vec::new();
        let report = run_training(&options, &mut |event| match event {
            TrainingProgress::Stage { name } => stages.push(name),
            _ => {}
        })?;

        assert!(report.sample_count >= 48);
        assert_eq!(report.baseline.families.len(), 2);
        assert_eq!(report.augmented.families.len(), FAMILY_NAMES.len());
        assert!(report.baseline.test_metrics.accuracy >= 0.0);

        let onnx_bytes = fs::read(&options.out_model).map_err(|e| e.to_string())?;
        assert!(!onnx_bytes.is_empty());
        // The exported artifact must load in tract with the runtime layout.
        use tract_onnx::prelude::*;
        let model = tract_onnx::onnx()
            .model_for_read(&mut std::io::Cursor::new(onnx_bytes))
            .map_err(|e| e.to_string())?
            .into_optimized()
            .map_err(|e| e.to_string())?
            .into_runnable()
            .map_err(|e| e.to_string())?;
        let tensor = Tensor::from_shape(&[2, 1, 12], &[0.0f32; 24]).unwrap();
        model
            .run(tvec!(tensor.into_tvalue()))
            .map_err(|e| e.to_string())?;

        let contract: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(options.out_model.with_extension("json")).unwrap())
                .unwrap();
        assert_eq!(contract["output_kind"], "logit");
        assert_eq!(contract["feature_dim"], 12);

        let persisted: ExperimentReport = serde_json::from_str(
            &fs::read_to_string(&options.report_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(persisted.sample_count, report.sample_count);
        assert!(!stages.is_empty());

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
