"""EMBER 真实数据集训练脚本（LightGBM 二分类 + 严格特征选择）

输入：E:\\EMBER2018_2\\ember2018\\ 下的 train_features_*.jsonl（EMBER 原始特征，dict 格式）
- 每行包含 sha256, md5, appeared, label(-1/0/1), avclass, histogram, byteentropy,
  strings, general, header, section, imports, exports, datadirectories（原始 dict，非处理后向量）

核心设计（训练/推理一致性）：
- 将原始 dict 映射到 HeliosAV 运行时 2381 维布局（与 tools/extract_features.py 逐维一致）：
    byte_histogram   [0,    256)   运行时=前1024字节直方图；jsonl 只有全文件直方图 → 置 0（无 split，无偏斜）
    pe_header        [256,  318)   可精确/近似重建（缺失字段置 0）
    section_info     [318,  573)   size/vsize/entropy/名字hash/props 精确；VA/PtrRaw 缺失置 0
    imports          [573,  1853)  函数名 hash 桶 + 危险 API 桶，精确重建
    exports          [1853, 1981)  导出名 hash 桶，精确重建
    data_directories [1981, 2081)  名字 hash（按位置取 DATA_DIRECTORY_NAMES）+ 在用标志，精确重建
    general          [2081, 2091)  size/has_debug/has_resources/has_signature 精确；overlay 缺失置 0
    string_features  [2091, 2291)  需要原始字符串内容，jsonl 不可重建 → 置 0
    resource_metadata[2291, 2381)  jsonl 不可重建 → 置 0
- 置 0 的维度在训练中不会产生任何 split，因此不会引入训练/推理分布偏斜；
  运行时提取器仍计算这些组，供后续用真实二进制微调。

- 训练集内部划分 train/val（test_features.jsonl 的 label 全为 -1，不可用作评估）
- 输出：LightGBM 模型（.txt）+ 特征选择掩码 + 评估报告
"""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path
from typing import List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from extract_features import (
    BYTE_HISTOGRAM_DIM,
    DATA_DIRECTORIES_DIM,
    DANGEROUS_APIS,
    DATA_DIRECTORY_NAMES,
    EMBER_2025_TOTAL,
    GENERAL_FILE_INFO_DIM,
    PE_EAT_API_DIM,
    PE_IAT_API_DIM,
    PE_STRUCTURE_DIM,
    SECTION_INFO_DIM,
    STRING_FEATURES_DIM,
    safe_hash32,
)

try:
    import lightgbm as lgb
except ImportError:
    print("lightgbm required. Install: pip install lightgbm", file=sys.stderr)
    sys.exit(1)

try:
    from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
except ImportError:
    print("scikit-learn required. Install: pip install scikit-learn", file=sys.stderr)
    sys.exit(1)

try:
    import orjson  # 快速 JSON 解析（可选）
    def _loads(line: bytes):
        return orjson.loads(line)
except ImportError:
    def _loads(line: bytes):
        return json.loads(line)

# 组偏移
OFF_HEADER = BYTE_HISTOGRAM_DIM                      # 256
OFF_SECTION = OFF_HEADER + PE_STRUCTURE_DIM          # 318
OFF_IMPORTS = OFF_SECTION + SECTION_INFO_DIM         # 573
OFF_EXPORTS = OFF_IMPORTS + PE_IAT_API_DIM           # 1853
OFF_DATADIRS = OFF_EXPORTS + PE_EAT_API_DIM          # 1981
OFF_GENERAL = OFF_DATADIRS + DATA_DIRECTORIES_DIM    # 2081
OFF_STRINGS = OFF_GENERAL + GENERAL_FILE_INFO_DIM    # 2091
OFF_RESOURCES = OFF_STRINGS + STRING_FEATURES_DIM    # 2291

# ---- 枚举名 -> 数值映射（lief 风格命名） ----
MACHINE_MAP = {
    'UNKNOWN': 0x0, 'I386': 0x014c, 'R4000': 0x0166, 'ARMNT': 0x01c4,
    'THUMB': 0x01c0, 'IA64': 0x0200, 'AMD64': 0x8664, 'ARM64': 0xaa64,
}
CHARA_MAP = {
    'CHARA_RELOCS_STRIPPED': 0x0001,
    'CHARA_EXECUTABLE_IMAGE': 0x0002,
    'CHARA_LINE_NUMS_STRIPPED': 0x0004,
    'CHARA_LOCAL_SYMS_STRIPPED': 0x0008,
    'CHARA_AGGRESIVE_WS_TRIM': 0x0010,
    'CHARA_LARGE_ADDRESS_AWARE': 0x0020,
    'CHARA_BYTES_REVERSED_LO': 0x0080,
    'CHARA_32BIT_MACHINE': 0x0100,
    'CHARA_DEBUG_STRIPPED': 0x0200,
    'CHARA_REMOVABLE_RUN_FROM_SWAP': 0x0400,
    'CHARA_NET_RUN_FROM_SWAP': 0x0800,
    'CHARA_SYSTEM': 0x1000,
    'CHARA_DLL': 0x2000,
    'CHARA_UP_SYSTEM_ONLY': 0x4000,
    'CHARA_BYTES_REVERSED_HI': 0x8000,
}
SUBSYSTEM_MAP = {
    'UNKNOWN': 0, 'NATIVE': 1, 'WINDOWS_GUI': 2, 'WINDOWS_CUI': 3,
    'OS2_CUI': 5, 'POSIX_CUI': 7, 'NATIVE_WINDOWS': 8, 'WINDOWS_CE_GUI': 9,
    'EFI_APPLICATION': 10, 'EFI_BOOT_SERVICE_DRIVER': 11,
    'EFI_RUNTIME_DRIVER': 12, 'EFI_ROM': 13, 'XBOX': 14,
    'WINDOWS_BOOT_APPLICATION': 16,
}
MAGIC_MAP = {'PE32': 0x10b, 'PE32_PLUS': 0x20b, 'PE32+': 0x20b}
DLLCHAR_MAP = {
    'HIGH_ENTROPY_VA': 0x0020, 'DYNAMIC_BASE': 0x0040, 'FORCE_INTEGRITY': 0x0080,
    'NX_COMPAT': 0x0100, 'NO_ISOLATION': 0x0200, 'NO_SEH': 0x0400,
    'NO_BIND': 0x0800, 'APPCONTAINER': 0x1000, 'WDM_DRIVER': 0x2000,
    'GUARD_CF': 0x4000, 'TERMINAL_SERVER_AWARE': 0x8000,
}
SECTION_PROPS_MAP = {
    'CNT_CODE': 0x00000020,
    'CNT_INITIALIZED_DATA': 0x00000040,
    'CNT_UNINITIALIZED_DATA': 0x00000080,
    'CNT_DISCARDABLE': 0x02000000,
    'CNT_NOT_CACHED': 0x04000000,
    'CNT_NOT_PAGED': 0x08000000,
    'CNT_SHAREABLE': 0x10000000,
    'CNT_EXECUTE': 0x20000000,
    'CNT_READ': 0x40000000,
    'CNT_WRITE': 0x80000000,
    'MEM_EXECUTE': 0x20000000,
    'MEM_READ': 0x40000000,
    'MEM_WRITE': 0x80000000,
    'MEM_SHARED': 0x10000000,
}

# 危险 API 小写缓存（与 extract_features.extract_imports 完全一致的行为）
_DANGEROUS_LOWER = [(api, api.lower()) for api in DANGEROUS_APIS]
_EXT_MZ_HASH = float(safe_hash32('MZ') & 0xFF)  # 所有 PE 的 ext_guess 都是 'MZ'


def _map_flags(names, table) -> float:
    v = 0
    for n in names or []:
        v += table.get(n, 0)
    return float(v & 0xFFFFFFFF)


def raw_to_vector(obj: dict) -> np.ndarray:
    """EMBER 原始特征 dict -> HeliosAV 2381 维向量（不可重建组置 0）。"""
    vec = np.zeros(EMBER_2025_TOTAL, dtype=np.float32)
    # 组 1 byte_histogram [0,256)：jsonl 直方图为全文件统计，与运行时(前1024字节)语义不同 → 置 0

    # 组 2 pe_header [256,318)
    header = obj.get('header') or {}
    coff = header.get('coff') or {}
    opt = header.get('optional') or {}
    base = OFF_HEADER
    machine = coff.get('machine')
    if isinstance(machine, str):
        vec[base + 0] = float(MACHINE_MAP.get(machine, 0))
    sections = (obj.get('section') or {}).get('sections') or []
    vec[base + 1] = float(len(sections))
    ts = coff.get('timestamp')
    if isinstance(ts, (int, float)):
        vec[base + 2] = float(int(ts) & 0xFFFFFFFF)
    magic = opt.get('magic')
    if isinstance(magic, str):
        vec[base + 3] = 224.0 if MAGIC_MAP.get(magic, 0x10b) == 0x10b else 240.0  # SizeOfOptionalHeader 近似
        vec[base + 5] = float(MAGIC_MAP.get(magic, 0))
    vec[base + 4] = _map_flags(coff.get('characteristics'), CHARA_MAP)
    vec[base + 6] = float(opt.get('major_linker_version') or 0)
    vec[base + 7] = float(opt.get('minor_linker_version') or 0)
    vec[base + 8] = float(opt.get('sizeof_code') or 0)
    # [9] sizeofinitializeddata / [10] uninitialized / [11] entrypoint / [12] baseofcode /
    # [13] imagebase / [14] sectionalignment / [15] filealignment / [22] sizeofimage /
    # [24] checksum / [27-29] stack/heap reserve / [31] loaderflags：jsonl 缺失 → 0
    vec[base + 16] = float(opt.get('major_operating_system_version') or 0)
    vec[base + 17] = float(opt.get('minor_operating_system_version') or 0)
    vec[base + 18] = float(opt.get('major_image_version') or 0)
    vec[base + 19] = float(opt.get('minor_image_version') or 0)
    vec[base + 20] = float(opt.get('major_subsystem_version') or 0)
    vec[base + 21] = float(opt.get('minor_subsystem_version') or 0)
    vec[base + 23] = float(opt.get('sizeof_headers') or 0)
    sub = opt.get('subsystem')
    if isinstance(sub, str):
        vec[base + 25] = float(SUBSYSTEM_MAP.get(sub, 0))
    vec[base + 26] = _map_flags(opt.get('dll_characteristics'), DLLCHAR_MAP)
    vec[base + 30] = float(opt.get('sizeof_heap_commit') or 0)
    vec[base + 32] = 16.0  # NumberOfRvaAndSizes 标准值
    dds = obj.get('datadirectories') or []
    for i, dd in enumerate(dds[:16]):
        rva = int(dd.get('virtual_address') or 0) & 0xFFFFFFFF
        size = int(dd.get('size') or 0) & 0xFFFFFFFF
        vec[base + 33 + i * 2] = float(rva)
        vec[base + 34 + i * 2] = float(size)

    # 组 3 section_info [318,573)
    base = OFF_SECTION
    if sections:
        vec[base + 0] = float(len(sections))
        vec[base + 1] = float(sum(int(s.get('size') or 0) for s in sections))
        vec[base + 2] = float(sum(int(s.get('vsize') or 0) for s in sections))
        for s in sections[:32]:
            name = str(s.get('name') or '').rstrip('\x00')
            if name:
                vec[base + 3 + (safe_hash32(name) % 32)] += 1.0
        for i, s in enumerate(sections[:10]):
            b = base + 10 + i * 22
            vec[b + 0] = float(int(s.get('size') or 0))
            vec[b + 1] = float(int(s.get('vsize') or 0))
            # [2] VirtualAddress / [3] PointerToRawData：jsonl 缺失 → 0
            vec[b + 4] = _map_flags(s.get('props'), SECTION_PROPS_MAP)
            vec[b + 5] = float(s.get('entropy') or 0)
            name = str(s.get('name') or '').rstrip('\x00')
            if name:
                nh = safe_hash32(name)
                vec[b + 6] = float(nh & 0xFFFF)
                vec[b + 7] = float(nh >> 16)
                vec[base + 230 + (nh % (SECTION_INFO_DIM - 230))] += 1.0

    # 组 4 imports [573,1853)（与 extract_imports 行为逐行一致）
    base = OFF_IMPORTS
    imports = obj.get('imports') or {}
    for _dll, funcs in imports.items():
        for fn in funcs or []:
            if not isinstance(fn, str) or not fn:
                continue
            h = safe_hash32(fn)
            vec[base + (h % PE_IAT_API_DIM)] += 1.0
            fnl = fn.lower()
            for _api, apil in _DANGEROUS_LOWER:
                if apil in fnl:
                    vec[base + 1180 + (h % 100)] += 1.0
                    break

    # 组 5 exports [1853,1981)（与 extract_exports 一致）
    base = OFF_EXPORTS
    for name in obj.get('exports') or []:
        if isinstance(name, str) and name:
            vec[base + (safe_hash32(name) % PE_EAT_API_DIM)] += 1.0

    # 组 6 data_directories [1981,2081)（与 extract_data_directories 一致，按位置取标准名）
    base = OFF_DATADIRS
    for i in range(min(16, len(dds))):
        name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"DIR_{i}"
        vec[base + (safe_hash32(name) % (DATA_DIRECTORIES_DIM - 16))] += 1.0
        dd = dds[i]
        rva = int(dd.get('virtual_address') or 0)
        size = int(dd.get('size') or 0)
        vec[base + 84 + i] = float((rva > 0)) + float((size > 0))

    # 组 7 general [2081,2091)
    base = OFF_GENERAL
    g = obj.get('general') or {}
    vec[base + 0] = float(int(g.get('size') or 0))
    vec[base + 1] = float(bool(g.get('has_debug')))
    vec[base + 2] = float(bool(g.get('has_resources')))
    vec[base + 3] = float(bool(g.get('has_signature')))
    # [4] overlay：jsonl 缺失 → 0
    vec[base + 5] = 1.0  # MZ（全样本均为 PE）
    vec[base + 6] = 1.0  # PE\0\0
    vec[base + 7] = _EXT_MZ_HASH

    # 组 8 strings [2091,2291) 与 组 9 resources [2291,2381)：不可重建 → 置 0
    return vec


def load_shards(data_dir: Path, shards: List[Path], cap_per_shard: int):
    """流式加载（只保留 label in {0,1}），预分配大矩阵避免反复拷贝。"""
    total_cap = cap_per_shard * len(shards)
    X = np.zeros((total_cap, EMBER_2025_TOTAL), dtype=np.float32)
    y = np.zeros(total_cap, dtype=np.int32)
    meta: List[dict] = []
    n_total = 0
    for shard in shards:
        n_shard = 0
        n_unlabeled = 0
        t0 = time.time()
        print(f'  加载: {shard.name} (cap={cap_per_shard})...', flush=True)
        with open(shard, 'rb') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _loads(line)
                except Exception:
                    continue
                lab = obj.get('label')
                if lab not in (0, 1):
                    n_unlabeled += 1
                    continue
                X[n_total] = raw_to_vector(obj)
                y[n_total] = int(lab)
                meta.append({
                    'sha256': obj.get('sha256', ''),
                    'appeared': obj.get('appeared', ''),
                    'avclass': obj.get('avclass', ''),
                    'source': shard.name,
                })
                n_total += 1
                n_shard += 1
                if n_shard >= cap_per_shard:
                    break
        print(f'    OK: {n_shard} labeled ({n_unlabeled} unlabeled skipped, {time.time() - t0:.0f}s)', flush=True)
        if n_total >= total_cap:
            break
    return X[:n_total], y[:n_total], meta


def main():
    parser = argparse.ArgumentParser(description='Train on EMBER real dataset (raw jsonl -> 2381-dim)')
    parser.add_argument('--data-dir', '-d', default='E:\\EMBER2018_2\\ember2018',
                        help='EMBER jsonl 目录')
    parser.add_argument('--output', '-o', default='artifacts/features/ember_2018_v1',
                        help='输出目录')
    parser.add_argument('--rows-per-shard', '-r', type=int, default=50000,
                        help='每个训练 shard 最多保留的 labeled 样本数（控制内存）')
    parser.add_argument('--val-split', type=float, default=0.1)
    parser.add_argument('--boost-rounds', type=int, default=300)
    parser.add_argument('--top-k', type=int, default=2000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--save-csr', action='store_true', help='保存 CSR 特征矩阵（占用磁盘较大）')
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f'数据目录不存在: {data_dir}', file=sys.stderr)
        return 1

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    np.random.seed(args.seed)

    shards = sorted(data_dir.glob('train_features_*.jsonl'))
    if not shards:
        print('未找到 train_features_*.jsonl', file=sys.stderr)
        return 1

    print('=' * 60)
    print('EMBER 真实数据集训练（2381 维 HeliosAV 布局）')
    print('=' * 60)

    # 1. 加载数据
    print('\n=== 第一步: 流式加载 labeled 样本 ===')
    t0 = time.time()
    X, y, meta = load_shards(data_dir, shards, args.rows_per_shard)
    if X.shape[0] == 0:
        print('未加载到数据。', file=sys.stderr)
        return 1
    n_benign = int((y == 0).sum())
    n_mal = int((y == 1).sum())
    print(f'总样本: {X.shape[0]} (良性: {n_benign}, 恶意: {n_mal}) 加载耗时 {time.time() - t0:.0f}s')

    # 2. 划分 train/val（分层随机）
    print('\n=== 第二步: 划分 train/val ===')
    rng = np.random.RandomState(args.seed)
    idx_benign = np.where(y == 0)[0]
    idx_mal = np.where(y == 1)[0]
    rng.shuffle(idx_benign)
    rng.shuffle(idx_mal)
    n_val_b = max(1, int(len(idx_benign) * args.val_split))
    n_val_m = max(1, int(len(idx_mal) * args.val_split))
    val_idx = np.concatenate([idx_benign[:n_val_b], idx_mal[:n_val_m]])
    train_idx = np.concatenate([idx_benign[n_val_b:], idx_mal[n_val_m:]])
    rng.shuffle(val_idx)
    rng.shuffle(train_idx)
    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]
    print(f'训练集: {len(train_idx)}, 验证集: {len(val_idx)}')

    params = {
        'objective': 'binary',
        'metric': 'auc',
        'boosting_type': 'gbdt',
        'num_leaves': 63,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_child_samples': 100,
        'verbose': -1,
        'seed': args.seed,
        'num_threads': 0,
    }

    # 3. 训练第一轮模型（用于特征选择）
    print(f'\n=== 第三步: 训练第一轮 LightGBM (rounds={args.boost_rounds}) ===')
    feature_names = [f'f{i}' for i in range(EMBER_2025_TOTAL)]
    train_data = lgb.Dataset(X_train, label=y_train, feature_name=feature_names)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data, feature_name=feature_names)
    model = lgb.train(
        params, train_data, num_boost_round=args.boost_rounds,
        valid_sets=[train_data, val_data], valid_names=['train', 'val'],
        callbacks=[lgb.early_stopping(stopping_rounds=30), lgb.log_evaluation(50)],
    )
    best_iter = model.best_iteration or args.boost_rounds
    print(f'第一轮最佳迭代: {best_iter}')

    # 4. 特征选择（gain 阈值 + top-k）
    print('\n=== 第四步: 特征选择 ===')
    importance = model.feature_importance(importance_type='gain')
    nonzero_cols = np.where(X.sum(axis=0) > 0)[0]  # 剔除全零列（置 0 的不可重建组）
    max_imp = importance.max()
    threshold = max_imp * 0.001
    selected = (importance >= threshold)
    selected &= np.isin(np.arange(EMBER_2025_TOTAL), nonzero_cols)
    n_selected = int(selected.sum())
    print(f'非零列: {len(nonzero_cols)}, gain>阈值({threshold:.4f}): {n_selected}')
    if n_selected > args.top_k:
        top_k_idx = np.argsort(importance)[-args.top_k:]
        selected = np.zeros(EMBER_2025_TOTAL, dtype=bool)
        selected[top_k_idx] = True
        n_selected = args.top_k
        print(f'截断到 top-{args.top_k}')

    # 5. 最终模型
    print(f'\n=== 第五步: 用 {n_selected} 个选中特征训练最终模型 ===')
    X_train_sel = X_train[:, selected]
    X_val_sel = X_val[:, selected]
    final_model = lgb.train(
        params, lgb.Dataset(X_train_sel, label=y_train),
        num_boost_round=best_iter,
        valid_sets=[lgb.Dataset(X_val_sel, label=y_val)], valid_names=['val'],
        callbacks=[lgb.early_stopping(stopping_rounds=30), lgb.log_evaluation(50)],
    )

    # 6. 评估
    print('\n=== 第六步: 评估 ===')
    proba = final_model.predict(X_val_sel)
    pred = (proba > 0.5).astype(int)
    auc = float(roc_auc_score(y_val, proba))
    acc = float(accuracy_score(y_val, pred))
    f1 = float(f1_score(y_val, pred, zero_division=0))
    # TPR @ FPR=1%
    order = np.argsort(-proba)
    y_sorted = y_val[order]
    n_fp_limit = max(1, int(0.01 * (y_val == 0).sum()))
    fp = 0
    tp = 0
    tpr_at_fpr1 = 0.0
    for i in range(len(y_sorted)):
        if y_sorted[i] == 1:
            tp += 1
        else:
            fp += 1
            if fp >= n_fp_limit:
                tpr_at_fpr1 = tp / max(1, (y_val == 1).sum())
                break
    print(f'  AUC: {auc:.4f}')
    print(f'  Accuracy: {acc:.4f}')
    print(f'  F1: {f1:.4f}')
    print(f'  TPR@FPR=1%: {tpr_at_fpr1:.4f}')

    # 7. 保存
    print('\n=== 第七步: 保存 ===')
    model_path = output_dir / 'ember_2018_v1.txt'
    final_model.save_model(str(model_path))
    print(f'  LightGBM 模型: {model_path}')
    np.savez_compressed(
        output_dir / 'feature_selection.npz',
        mask=selected.astype(bool),
        importance=importance.astype(np.float32),
    )
    print(f'  特征选择: {output_dir / "feature_selection.npz"}')
    if args.save_csr:
        from scipy.sparse import csr_matrix
        from scipy.sparse import save_npz
        save_npz(str(output_dir / 'train_features_csr.npz'), csr_matrix(X_train))
        save_npz(str(output_dir / 'val_features_csr.npz'), csr_matrix(X_val))
        print('  CSR 特征矩阵已保存')
    else:
        print('  (跳过 CSR 保存，使用 --save-csr 启用)')

    report = {
        'model_version': 'ember_2018_v1',
        'feature_dim': EMBER_2025_TOTAL,
        'selected_feature_dim': n_selected,
        'nonzero_dim': int(len(nonzero_cols)),
        'train_count': int(len(train_idx)),
        'val_count': int(len(val_idx)),
        'benign_count': int(n_benign),
        'malware_count': int(n_mal),
        'val_auc': auc,
        'val_accuracy': acc,
        'val_f1': f1,
        'val_tpr_at_fpr_1pct': float(tpr_at_fpr1),
        'best_iteration': int(final_model.best_iteration or best_iter),
        'rows_per_shard': args.rows_per_shard,
        'shards': [s.name for s in shards],
        'note': 'histogram/strings/resources 组与 header 缺失字段置 0（jsonl 不可重建），模型不依赖这些维度',
    }
    with open(output_dir / 'training_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f'  训练报告: {output_dir / "training_report.json"}')

    print(f'\n[OK] EMBER 真实数据集模型训练完成')
    print(f'  模型: {model_path}')
    print(f'  AUC: {auc:.4f}  TPR@FPR=1%: {tpr_at_fpr1:.4f}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
