"""生成合成 EMBER 训练样本（用于第一版模型训练验证）

策略：
- 良性样本：真实的 Windows 系统 DLL（kernel32, user32, advapi32 等）和本地 everbloom_engine.exe
- 恶意样本：通过对良性样本的特征向量添加"恶意指纹"扰动生成
  - 扰动模式：增加 API 调用频率（CreateRemoteThread、VirtualAllocEx、WriteProcessMemory 等）
  - 增强字符串特征（URL、IP、注册表路径、PowerShell、cmd 等）
  - 提升 section 熵值（模拟加壳）
  - 调整 PE 头（缺少数字签名、可疑时间戳、Subsystem 不常见）

输出：CSV 格式的特征矩阵 + 标签（不存原始样本，只存特征向量）
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import sys
import time
from pathlib import Path
from typing import List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from extract_features import (
    extract_features_batch,
    extract_features_from_file,
    EMBER_2025_TOTAL,
    save_features_sparse,
    DANGEROUS_APIS,
    SUSPICIOUS_KEYWORDS,
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


def safe_hash32(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode('utf-8', errors='replace')).digest()[:4], 'big')


def generate_malicious_perturbation(benign_features: np.ndarray) -> np.ndarray:
    """基于良性样本特征生成恶意扰动（模拟典型恶意行为模式）。"""
    perturbed = benign_features.copy()

    # 1. 增强字节直方图熵（模拟加壳）
    byte_hist = perturbed[:BYTE_HISTOGRAM_DIM].copy()
    # 加壳文件的熵通常接近 8.0
    byte_hist = byte_hist / (byte_hist.sum() + 1e-9)
    byte_hist = byte_hist * 0.3  # 降低均匀性，模拟高熵区段
    byte_hist = byte_hist + 0.7 / BYTE_HISTOGRAM_DIM  # 加上均匀分布
    perturbed[:BYTE_HISTOGRAM_DIM] = byte_hist

    # 2. 增加危险 API 计数（注入到 imports 部分）
    for api in DANGEROUS_APIS[:30]:  # 选前 30 个最危险的 API
        bucket = safe_hash32(api) % PE_IAT_API_DIM
        # 随机增加 1-3 次
        perturbed[BYTE_HISTOGRAM_DIM + PE_STRUCTURE_DIM + SECTION_INFO_DIM + bucket] += float(random.randint(1, 3))

    # 3. 增强字符串特征中的可疑关键字
    for keyword in SUSPICIOUS_KEYWORDS[:50]:  # 选前 50 个关键字
        bucket = safe_hash32(keyword) % STRING_FEATURES_DIM
        # 随机增加计数
        string_offset = (
            BYTE_HISTOGRAM_DIM + PE_STRUCTURE_DIM + SECTION_INFO_DIM + PE_IAT_API_DIM +
            PE_EAT_API_DIM + DATA_DIRECTORIES_DIM + GENERAL_FILE_INFO_DIM
        )
        perturbed[string_offset + bucket] += float(random.randint(1, 5))

    # 4. 调整 PE 头（增加可疑特征）
    pe_offset = BYTE_HISTOGRAM_DIM
    # TimeDateStamp 设置为异常值（0 或未来时间）
    perturbed[pe_offset + 2] = float(random.choice([0, int(time.time()) + 86400 * 365]))
    # DllCharacteristics 设置为 0（缺少 DllCharacteristics 标志）
    perturbed[pe_offset + 26] = 0.0
    # 缺少数字签名（General file info 中的特定位）
    general_offset = (
        BYTE_HISTOGRAM_DIM + PE_STRUCTURE_DIM + SECTION_INFO_DIM + PE_IAT_API_DIM +
        PE_EAT_API_DIM + DATA_DIRECTORIES_DIM
    )
    # 没有数字签名
    perturbed[general_offset + 3] = 0.0

    # 5. 提高节区熵（模拟加壳）
    section_offset = BYTE_HISTOGRAM_DIM + PE_STRUCTURE_DIM
    for i in range(min(3, SECTION_INFO_DIM // 22)):
        base = section_offset + 10 + i * 22 + 5  # entropy field
        perturbed[base] = 7.5 + random.random() * 0.5  # 接近 8.0 的高熵

    # 6. 调整 section 名称 hash（模拟可疑节区名）
    for i in range(min(5, 10)):
        bucket = safe_hash32(f".packed_{i}") % (SECTION_INFO_DIM - 230)
        perturbed[section_offset + 230 + bucket] += 1.0

    return perturbed


def collect_benign_samples(benign_dir: str, max_samples: int = 200) -> List[Tuple[str, int]]:
    """从真实 Windows 系统目录和本地构建目录收集良性 PE 样本。"""
    samples = []
    search_paths = [
        benign_dir,
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
        r'C:\Windows\System',
    ]
    for search_path in search_paths:
        if not Path(search_path).exists():
            continue
        for fp in Path(search_path).rglob('*.dll'):
            if fp.is_file() and fp.stat().st_size > 50_000 and fp.stat().st_size < 50_000_000:
                samples.append((str(fp), 0))
                if len(samples) >= max_samples:
                    break
        for fp in Path(search_path).rglob('*.exe'):
            if fp.is_file() and fp.stat().st_size > 100_000 and fp.stat().st_size < 100_000_000:
                samples.append((str(fp), 0))
                if len(samples) >= max_samples:
                    break
        if len(samples) >= max_samples:
            break
    return samples


def main():
    """生成合成训练数据并训练第一版 EMBER-2025 模型。"""
    parser = argparse.ArgumentParser(description='Generate synthetic EMBER-2025 training data and train v1 model')
    parser.add_argument('--benign-dir', '-b', default='E:\\EverbloomSecurity\\EverbloomSecurity\\artifacts\\gui\\bin',
                        help='本地良性样本目录（everbloom_engine.exe 等）')
    parser.add_argument('--max-samples', '-m', type=int, default=200,
                        help='最多收集的良性样本数')
    parser.add_argument('--malware-multiplier', '-k', type=int, default=2,
                        help='每个良性样本生成的恶意变体数（默认 2）')
    parser.add_argument('--output', '-o', default='artifacts/features/ember_2025_v1',
                        help='输出目录（特征和模型）')
    parser.add_argument('--seed', '-s', type=int, default=42, help='随机种子')
    parser.add_argument('--val-split', type=float, default=0.2, help='验证集比例')
    parser.add_argument('--boost-rounds', type=int, default=300, help='LightGBM 提升轮数')
    parser.add_argument('--top-k', type=int, default=2000, help='训练后保留 top-k 特征')
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. 收集良性样本
    print('=== 第一步: 收集良性样本 ===')
    benign_samples = collect_benign_samples(args.benign_dir, max_samples=args.max_samples)
    if not benign_samples:
        print(f'未在 {args.benign_dir} 或 C:\\Windows\\System32 找到良性样本', file=sys.stderr)
        return
    print(f'找到 {len(benign_samples)} 个良性样本')

    # 2. 提取良性样本特征
    print('\n=== 第二步: 提取良性样本特征 ===')
    benign_features, benign_meta = extract_features_batch(
        [fp for fp, _ in benign_samples], label=0
    )
    # 修正 metadata 中的 label
    for i, (_, label) in enumerate(benign_samples):
        if i < len(benign_meta):
            benign_meta[i]['label'] = int(label)
    print(f'提取了 {benign_features.shape[0]} 个良性样本特征 (维度: {EMBER_2025_TOTAL})')

    if benign_features.shape[0] == 0:
        print('特征提取失败。', file=sys.stderr)
        return

    # 3. 生成恶意变体
    print('\n=== 第三步: 生成恶意变体 ===')
    malware_features = []
    malware_meta = []
    for i, ((benign_fp, _), benign_feature_row) in enumerate(zip(benign_samples, benign_features)):
        for k in range(args.malware_multiplier):
            perturbed = generate_malicious_perturbation(benign_feature_row)
            malware_features.append(perturbed)
            sha = hashlib.sha256(open(benign_fp, 'rb').read() if Path(benign_fp).exists() else b'').hexdigest()
            malware_meta.append({
                'sha256': sha,
                'label': 1,  # 恶意
                'family': f'synthetic_perturbation_{k}',
                'file_size': 0,
                'timestamp': int(time.time()),
                'file_path': f'synthetic:{benign_fp}#variant_{k}',
            })
    malware_features = np.stack(malware_features, axis=0)
    print(f'生成 {malware_features.shape[0]} 个恶意变体')

    # 4. 合并数据
    print('\n=== 第四步: 合并数据 ===')
    all_features = np.concatenate([benign_features, malware_features], axis=0)
    all_labels = np.concatenate([
        np.zeros(len(benign_features), dtype=np.int32),
        np.ones(len(malware_features), dtype=np.int32),
    ], axis=0)
    all_meta = benign_meta + malware_meta
    print(f'总样本: {len(all_labels)} (良性: {len(benign_features)}, 恶意: {len(malware_features)})')

    # 5. 划分训练/验证集
    n = len(all_labels)
    n_val = max(1, int(n * args.val_split))
    indices = np.random.permutation(n)
    val_indices = indices[:n_val]
    train_indices = indices[n_val:]
    X_train = all_features[train_indices]
    y_train = all_labels[train_indices]
    X_val = all_features[val_indices]
    y_val = all_labels[val_indices]
    print(f'训练集: {len(train_indices)} 样本, 验证集: {len(val_indices)} 样本')

    # 6. 训练 LightGBM
    print(f'\n=== 第五步: 训练 LightGBM (boost_rounds={args.boost_rounds}) ===')
    import lightgbm as lgb
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
    }
    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
    model = lgb.train(
        params, train_data, num_boost_round=args.boost_rounds,
        valid_sets=[train_data, val_data], valid_names=['train', 'val'],
        callbacks=[lgb.early_stopping(stopping_rounds=30)],
    )
    print(f'训练完成，最佳迭代: {model.best_iteration}')

    # 7. 特征选择（严格）
    print('\n=== 第六步: 特征选择 ===')
    importance = model.feature_importance(importance_type='gain')
    # 使用相对阈值：保留重要性 >= 最高重要性 * 1% 的特征
    # 这样可以保留更多有效特征，而不是只用 0 阈值
    max_importance = importance.max()
    threshold = max_importance * 0.001  # 保留重要性 >= 0.1% 最高值的特征
    selected = importance >= threshold
    n_selected = int(selected.sum())
    print(f'保留重要性 >= {threshold:.4f} 的特征: {n_selected} / {EMBER_2025_TOTAL}')

    # Top-k 截断
    if n_selected > args.top_k:
        top_k_idx = np.argsort(importance)[-args.top_k:]
        selected = np.zeros(EMBER_2025_TOTAL, dtype=bool)
        selected[top_k_idx] = True
        n_selected = args.top_k
        print(f'截断到 top-{args.top_k}')

    # 8. 用选中特征训练最终模型
    print(f'\n=== 第七步: 用选中特征训练最终模型 ===')
    X_train_sel = X_train[:, selected]
    X_val_sel = X_val[:, selected]
    final_model = lgb.train(
        params, lgb.Dataset(X_train_sel, label=y_train), num_boost_round=args.boost_rounds,
        valid_sets=[lgb.Dataset(X_val_sel, label=y_val)], valid_names=['val'],
        callbacks=[lgb.early_stopping(stopping_rounds=30)],
    )
    print(f'最终模型最佳迭代: {final_model.best_iteration}')

    # 9. 评估
    from sklearn.metrics import roc_auc_score, accuracy_score, f1_score
    y_pred_proba = final_model.predict(X_val_sel)
    y_pred = (y_pred_proba > 0.5).astype(int)
    auc = roc_auc_score(y_val, y_pred_proba)
    acc = accuracy_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred, zero_division=0)
    print(f'\n=== 评估指标 ===')
    print(f'  AUC: {auc:.4f}')
    print(f'  Accuracy: {acc:.4f}')
    print(f'  F1: {f1:.4f}')

    # 10. 保存
    print(f'\n=== 第八步: 保存 ===')
    # 保存模型
    model_path = output_dir / 'ember_2025_v1.txt'
    final_model.save_model(str(model_path))
    print(f'  LightGBM 模型: {model_path}')

    # 保存 CSR 特征矩阵
    save_features_sparse(all_features, all_meta, str(output_dir / 'features_csr.npz'))
    print(f'  CSR 特征矩阵: {output_dir / "features_csr.npz"}')

    # 保存特征选择
    np.savez_compressed(
        output_dir / 'feature_selection.npz',
        mask=selected.astype(bool),
        importance=importance.astype(np.float32),
    )
    print(f'  特征选择: {output_dir / "feature_selection.npz"}')

    # 保存评估报告
    report = {
        'model_version': 'ember_2025_v1',
        'feature_dim': EMBER_2025_TOTAL,
        'selected_feature_dim': n_selected,
        'sample_count': n,
        'benign_count': int((all_labels == 0).sum()),
        'malware_count': int((all_labels == 1).sum()),
        'train_count': len(train_indices),
        'val_count': len(val_indices),
        'val_auc': float(auc),
        'val_accuracy': float(acc),
        'val_f1': float(f1),
        'best_iteration': int(final_model.best_iteration),
    }
    with open(output_dir / 'training_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f'  训练报告: {output_dir / "training_report.json"}')

    print(f'\n[OK] EMBER-2025 first version model training complete!')
    print(f'  模型: {model_path}')
    print(f'  特征矩阵: {output_dir / "features_csr.npz"}')
    print(f'  评估 AUC: {auc:.4f}')


if __name__ == '__main__':
    import argparse
    main()
