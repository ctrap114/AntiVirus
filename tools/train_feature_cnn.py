#!/usr/bin/env python3
"""Train and export a PyTorch-based ONNX model for the 12-feature AI scanner.

This script produces an ONNX model that is compatible with the runtime loader in
`engine/src/layers/ai.rs`. The engine expects a float32 tensor of shape [1, 12]
containing the same feature layout defined by `AiModel::extract_features`.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

try:
    import pefile
except ImportError as exc:
    raise SystemExit(
        "pefile is required for feature extraction. Install it with `pip install pefile`."
    ) from exc

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
except ImportError as exc:
    raise SystemExit(
        "PyTorch is required to train and export the model. Install it with `pip install torch torchvision`."
    ) from exc


def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    total = len(data)
    for count in counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def timestamp_anomaly_score(timestamp: int) -> float:
    if timestamp == 0:
        return 1.0
    now = int(time.time())
    if timestamp > now + 60 * 60 * 24 * 30:
        return 1.0
    if timestamp < now - 60 * 60 * 24 * 365 * 20:
        return 0.75
    return 0.0


def extract_features(blob: bytes, file_size: int | None = None) -> torch.Tensor:
    """Extract the same bounded, normalized 12 features used by Rust."""
    features = [0.0] * 12
    file_size = max(file_size or len(blob), 1)
    features[0] = min(len(blob) / file_size, 1.0)

    try:
        pe = pefile.PE(data=blob, fast_load=True)
        # Collect section-based and PE-specific values.
        features[1] = min(float(len(pe.sections)) / 32.0, 1.0)

        imports = 0
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            if hasattr(entry, 'imports'):
                imports += len(entry.imports)
        features[2] = min(float(imports) / 256.0, 1.0)

        features[3] = 1.0 if getattr(pe, 'DIRECTORY_ENTRY_TLS', None) else 0.0
        features[4] = timestamp_anomaly_score(getattr(pe.FILE_HEADER, 'TimeDateStamp', 0))

        section_entropy = 0.0
        for section in pe.sections:
            try:
                raw = section.get_data()
            except Exception:
                raw = b''
            if raw:
                section_entropy = compute_entropy(raw)
                break
        features[5] = min(section_entropy / 8.0, 1.0)
    except Exception:
        # If the blob cannot be parsed as PE, leave the PE-specific values at 0.
        features[1] = 0.0
        features[2] = 0.0
        features[3] = 0.0
        features[4] = 0.0
        features[5] = 0.0

    printable = sum(1 for b in blob if 32 <= b <= 126 or b in (9, 10, 13))
    features[6] = printable / max(1, len(blob))
    features[7] = sum(1 for b in blob if b == 0) / max(1, len(blob))
    features[8] = len({b for b in blob}) / 256.0
    features[9] = sum(blob) / max(1, len(blob)) / 255.0
    features[10] = compute_entropy(blob) / 8.0
    features[11] = 1.0 if file_size > 1024 * 1024 else 0.0

    return torch.tensor(features, dtype=torch.float32)


@dataclass
class LabeledSample:
    path: Path
    label: int


class FeatureDataset(Dataset):
    def __init__(self, samples: Sequence[LabeledSample], max_bytes: int = 4096) -> None:
        self.samples = list(samples)
        self.max_bytes = max_bytes

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, index: int) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[index]
        blob, file_size = read_feature_sample(sample.path, self.max_bytes)
        features = extract_features(blob, file_size)
        label = torch.tensor(float(sample.label), dtype=torch.float32)
        return features, label


def read_feature_sample(path: Path, limit: int) -> Tuple[bytes, int]:
    file_size = path.stat().st_size
    if file_size <= limit:
        return path.read_bytes(), file_size
    half = limit // 2
    with path.open('rb') as handle:
        head = handle.read(half)
        handle.seek(-half, os.SEEK_END)
        tail = handle.read(half)
    return head + tail, file_size


class SmallCnn(nn.Module):
    def __init__(self, input_dim: int = 12, channels: int = 8, hidden_dim: int = 32) -> None:
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels=1, out_channels=channels, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv1d(in_channels=channels, out_channels=channels, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool1d(1),
        )
        self.fc = nn.Sequential(
            nn.Flatten(),
            nn.Linear(channels, hidden_dim),
            nn.ReLU(inplace=True),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Expected input shape: [batch, 12]
        x = x.unsqueeze(1)
        x = self.conv(x)
        x = self.fc(x)
        return x.squeeze(-1)


def load_labels(labels_path: Path, corpus_dir: Path) -> List[LabeledSample]:
    if not labels_path.exists():
        raise FileNotFoundError(f"Labels file not found: {labels_path}")
    samples: List[LabeledSample] = []
    with labels_path.open('r', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            if len(row) < 2:
                raise ValueError(f"Invalid labels row: {row}")
            filename = row[0].strip()
            label = int(row[1].strip())
            path = corpus_dir / filename
            if not path.exists():
                raise FileNotFoundError(f"Corpus file not found: {path}")
            samples.append(LabeledSample(path=path, label=label))
    return samples


def train_model(
    model: nn.Module,
    dataset: FeatureDataset,
    lr: float,
    epochs: int,
    batch_size: int,
    device: torch.device,
    val_split: float = 0.2,
) -> nn.Module:
    samples = list(dataset.samples)
    random.shuffle(samples)
    split = int(len(samples) * (1.0 - val_split))
    train_samples = samples[:split]
    val_samples = samples[split:]

    train_loader = DataLoader(FeatureDataset(train_samples), batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(FeatureDataset(val_samples), batch_size=batch_size, shuffle=False)

    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    model.to(device)
    best_val = float('inf')
    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        for features, label in train_loader:
            features = features.to(device)
            label = label.to(device)
            optimizer.zero_grad()
            output = model(features)
            loss = criterion(output, label)
            loss.backward()
            optimizer.step()
            running_loss += loss.item() * features.size(0)
        train_loss = running_loss / max(1, len(train_loader.dataset))

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for features, label in val_loader:
                features = features.to(device)
                label = label.to(device)
                output = model(features)
                loss = criterion(output, label)
                val_loss += loss.item() * features.size(0)
        val_loss /= max(1, len(val_loader.dataset))

        if val_loss < best_val:
            best_val = val_loss

        print(f"Epoch {epoch}/{epochs}  train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

    return model


def export_onnx(model: nn.Module, output_path: Path) -> None:
    model.eval()
    example_input = torch.randn(1, 12, dtype=torch.float32)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        example_input,
        str(output_path),
        export_params=True,
        opset_version=18,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}},
        do_constant_folding=True,
    )
    print(f"Exported ONNX model to {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a small CNN and export an ONNX model for EverbloomSecurity.")
    parser.add_argument('--corpus', type=Path, required=True, help='Path to directory containing labeled samples.')
    parser.add_argument('--labels', type=Path, required=True, help='CSV labels file with `filename,label` rows.')
    parser.add_argument('--out', type=Path, default=Path('everbloom_feature_cnn.onnx'), help='ONNX output path.')
    parser.add_argument('--epochs', type=int, default=20, help='Number of training epochs.')
    parser.add_argument('--batch-size', type=int, default=32, help='Mini-batch size.')
    parser.add_argument('--lr', type=float, default=1e-3, help='Learning rate.')
    parser.add_argument('--seed', type=int, default=42, help='Random seed.')
    parser.add_argument('--device', type=str, default='cpu', help='Torch device, e.g. cpu or cuda.')
    parser.add_argument('--val-split', type=float, default=0.2, help='Fraction of samples held out for validation.')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    random.seed(args.seed)
    torch.manual_seed(args.seed)

    samples = load_labels(args.labels, args.corpus)
    if len(samples) == 0:
        raise SystemExit('No labeled samples found. Create a labels CSV with `filename,label` rows.')

    dataset = FeatureDataset(samples)
    model = SmallCnn()
    model = train_model(
        model=model,
        dataset=dataset,
        lr=args.lr,
        epochs=args.epochs,
        batch_size=args.batch_size,
        device=torch.device(args.device),
        val_split=args.val_split,
    )
    export_onnx(model, args.out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
