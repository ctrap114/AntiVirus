"""EMBER-2025 训练脚本（LightGBM 二分类 + 特征选择）

输入：恶意/良性样本目录
输出：训练好的 LightGBM 模型 + 特征重要性报告
- 使用 scipy.sparse CSR 存储特征矩阵（不存原始样本）
- 严格特征选择（基于 LightGBM feature_importance）
- 模型导出为 .txt（EMBER 风格）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

# 尝试导入 LightGBM
try:
    import lightgbm as lgb
except ImportError:
    print("lightgbm required. Install with: pip install lightgbm", file=sys.stderr)
    sys.exit(1)

# 尝试导入 scipy
try:
    from scipy import sparse
    from scipy.sparse import csr_matrix, save_npz, load_npz
except ImportError:
    print("scipy required. Install with: pip install scipy", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
from extract_features import (
    extract_features_from_file,
    extract_features_batch,
    save_features_sparse,
    load_features_sparse,
    EMBER_2025_TOTAL,
    BYTE_HISTOGRAM_DIM,
    PE_STRUCTURE_DIM,
    SECTION_INFO_DIM,
    PE_IAT_API_DIM,
    PE_EAT_API_DIM,
    DATA_DIRECTORIES_DIM,
    GENERAL_FILE_INFO_DIM,
    STRING_FEATURES_DIM,
    RESOURCE_METADATA_DIM,
)


def collect_samples(malware_dir: str, benign_dir: str, limit: int = None):
    """从目录收集样本路径。"""
    samples = []
    if malware_dir and Path(malware_dir).exists():
        for fp in sorted(Path(malware_dir).rglob('*')):
            if fp.is_file() and fp.suffix.lower() in ['.exe', '.dll', '.scr', '.cpl', '.com', '.bin']:
                samples.append((str(fp), 1))
                if limit and len(samples) >= limit:
                    break
    if benign_dir and Path(benign_dir).exists():
        for fp in sorted(Path(benign_dir).rglob('*')):
            if fp.is_file() and fp.suffix.lower() in ['.exe', '.dll', '.scr', '.cpl', '.com', '.bin']:
                samples.append((str(fp), 0))
                if limit and len(samples) >= limit * 2:
                    break
    return samples


def train_lightgbm(X_train, y_train, X_val=None, y_val=None, num_boost_round=300):
    """训练 LightGBM 二分类模型。"""
    params = {
        'objective': 'binary',
        'metric': 'auc',
        'boosting_type': 'gbdt',
        'num_leaves': 63,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_child_samples': 20,
        'verbose': -1,
        'num_threads': -1,
    }
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_sets = [train_data]
    valid_names = ['train']
    if X_val is not None and y_val is not None:
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        valid_sets.append(val_data)
        valid_names.append('val')
        params['metric'] = 'auc'
    model = lgb.train(
        params,
        train_data,
        num_boost_round=num_boost_round,
        valid_sets=valid_sets,
        valid_names=valid_names,
        callbacks=[lgb.early_stopping(stopping_rounds=30)] if X_val is not None else None,
    )
    return model


def select_features(model, feature_matrix, importance_threshold=0.0):
    """基于 LightGBM 特征重要性做严格特征选择。

    importance_threshold: 重要性低于此值（gain）会被剔除（默认 0 表示剔除所有 gain=0 的特征）。
    """
    importance = model.feature_importance(importance_type='gain')
    selected = importance > importance_threshold
    return selected, importance


def main():
    parser = argparse.ArgumentParser(description='Train EMBER-2025 model on collected samples')
    parser.add_argument('--malware', '-m', required=True, help='恶意软件样本目录')
    parser.add_argument('--benign', '-b', required=True, help='良性样本目录')
    parser.add_argument('--output', '-o', default='artifacts/features/ember_model_v1',
                        help='输出目录（特征和模型）')
    parser.add_argument('--limit', '-l', type=int, default=None, help='每个类别的最大样本数')
    parser.add_argument('--val-split', type=float, default=0.2, help='验证集比例')
    parser.add_argument('--boost-rounds', type=int, default=300, help='LightGBM 提升轮数')
    parser.add_argument('--top-k', type=int, default=2000, help='训练后保留 top-k 特征')
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f'收集样本 (恶意: {args.malware}, 良性: {args.benign})...')
    samples = collect_samples(args.malware, args.benign, args.limit)
    print(f'找到 {len(samples)} 个样本 (恶意: {sum(1 for _, l in samples if l == 1)}, 良性: {sum(1 for _, l in samples if l == 0)})')

    if len(samples) == 0:
        print('未找到样本。请提供包含 PE 文件的恶意/良性目录。', file=sys.stderr)
        sys.exit(1)

    # 提取特征
    print('提取特征 (EMBER-2025 2381 维)...')
    file_paths = [fp for fp, _ in samples]
    labels = np.array([l for _, l in samples], dtype=np.int32)
    feature_matrix, metadata = extract_features_batch(file_paths, label=0)  # 标签在 metadata 中
    if feature_matrix.shape[0] == 0:
        print('特征提取失败。', file=sys.stderr)
        sys.exit(1)

    # 修复 metadata 中的标签
    for i, (_, label) in enumerate(samples):
        if i < len(metadata):
            metadata[i]['label'] = int(label)

    # 划分训练/验证集
    n = feature_matrix.shape[0]
    n_val = max(1, int(n * args.val_split))
    indices = np.random.permutation(n)
    val_indices = indices[:n_val]
    train_indices = indices[n_val:]

    X_train = feature_matrix[train_indices]
    y_train = labels[train_indices]
    X_val = feature_matrix[val_indices] if n_val > 0 else None
    y_val = labels[val_indices] if n_val > 0 else None

    print(f'训练: {len(train_indices)} 样本, 验证: {len(val_indices)} 样本')

    # 训练 LightGBM
    print(f'训练 LightGBM (boost_rounds={args.boost_rounds})...')
    model = train_lightgbm(X_train, y_train, X_val, y_val, args.boost_rounds)
    print(f'训练完成。最佳迭代: {model.best_iteration if X_val is not None else "N/A"}')

    # 特征选择
    print('特征选择 (gain > 0)...')
    selected, importance = select_features(model, feature_matrix, importance_threshold=0.0)
    n_selected = int(selected.sum())
    print(f'原始特征: {EMBER_2025_TOTAL}, 非零重要性: {n_selected}')

    # Top-k 截断
    if n_selected > args.top_k:
        top_k_idx = np.argsort(importance)[-args.top_k:]
        selected = np.zeros(EMBER_2025_TOTAL, dtype=bool)
        selected[top_k_idx] = True
        n_selected = args.top_k
        print(f'截断到 top-{args.top_k}: 保留 {n_selected} 特征')

    # 保存特征选择掩码
    feature_mask = selected.astype(bool)
    np.savez_compressed(
        output_dir / 'feature_selection.npz',
        mask=feature_mask,
        importance=importance.astype(np.float32),
    )
    print(f'特征选择保存到: {output_dir / "feature_selection.npz"}')

    # 训练最终模型（使用选中的特征）
    print('使用选中特征训练最终模型...')
    X_train_sel = X_train[:, feature_mask]
    X_val_sel = X_val[:, feature_mask] if X_val is not None else None
    final_model = train_lightgbm(X_train_sel, y_train, X_val_sel, y_val, args.boost_rounds)

    # 保存 LightGBM 模型（EMBER 风格 .txt 格式）
    model_path = output_dir / 'ember_2025_v1.txt'
    final_model.save_model(str(model_path))
    print(f'LightGBM 模型保存到: {model_path}')

    # 保存特征矩阵（CSR 稀疏，不存原始样本）
    feature_csr = csr_matrix(feature_matrix.astype(np.float32))
    save_npz(output_dir / 'features_csr.npz', feature_csr)
    meta_path = output_dir / 'features_meta.json'
    meta = {
        'feature_dim': EMBER_2025_TOTAL,
        'selected_feature_dim': n_selected,
        'sample_count': n,
        'malware_count': int((labels == 1).sum()),
        'benign_count': int((labels == 0).sum()),
        'metadata': metadata,
    }
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    print(f'CSR 特征矩阵保存到: {output_dir / "features_csr.npz"}')
    print(f'特征元数据保存到: {meta_path}')

    # 验证集评估
    if X_val is not None and y_val is not None:
        from sklearn.metrics import roc_auc_score, accuracy_score
        y_pred = final_model.predict(X_val_sel)
        auc = roc_auc_score(y_val, y_pred)
        acc = accuracy_score(y_val, (y_pred > 0.5).astype(int))
        print(f'验证集 AUC: {auc:.4f}, 准确率: {acc:.4f}')

    print('\n✓ EMBER-2025 第一版模型训练完成。')
    print(f'  模型: {model_path}')
    print(f'  CSR 特征矩阵: {output_dir / "features_csr.npz"}')
    print(f'  特征选择: {output_dir / "feature_selection.npz"}')


if __name__ == '__main__':
    main()
