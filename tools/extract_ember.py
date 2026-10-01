"""流式解压 EMBER 2018 v2 数据集（直接 bz2 -> tar stream）"""
import bz2
import os
import sys
import tarfile
import time

BZ2_PATH = r"E:\EMBER_dataset_2018_2.tar.bz2"
OUT_DIR = r"E:\EMBER2018_2"
PROGRESS_FILE = r"E:\extract_progress.log"

# EMBER 2018 v2 包含的文件（从 elastic/ember README 知道结构）：
# - test_features.dat
# - train_features_0.dat ... train_features_10.dat
# - test_labels.jsonl
# - train_labels.jsonl
# - test_metadata.jsonl
# - train_metadata.jsonl
# 加上 sha256 目录里的 hash 数据

# 我们只需要训练 + 测试的特征和标签，metadata 可选
FILES_TO_EXTRACT = [
    "ember2018/train_features_0.jsonl",
    "ember2018/train_features_3.jsonl",
    "ember2018/train_features_5.jsonl",
    "ember2018/train_labels.jsonl",
    "ember2018/test_features.jsonl",
    "ember2018/test_labels.jsonl",
]


def log_progress(msg):
    with open(PROGRESS_FILE, "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    print(msg)


def main():
    if os.path.exists(OUT_DIR):
        import shutil
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)

    log_progress(f"Opening {BZ2_PATH}...")
    extracted = []
    skipped = []
    t0 = time.time()
    with bz2.open(BZ2_PATH, "rb") as bz:
        with tarfile.open(fileobj=bz, mode="r|") as tar:
            for member in tar:
                if member.isfile():
                    if member.name in FILES_TO_EXTRACT:
                        out_path = os.path.join(OUT_DIR, member.name)
                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                        with open(out_path, "wb") as f:
                            shutil.copyfileobj(tar.extractfile(member), f)
                        size_mb = member.size / 1024 / 1024
                        log_progress(f"  OK: {member.name} ({size_mb:.1f} MB)")
                        extracted.append(member.name)
                    else:
                        skipped.append(member.name)
                if len(extracted) == len(FILES_TO_EXTRACT):
                    break
    elapsed = time.time() - t0
    log_progress(f"\nExtract done in {elapsed:.1f}s: {len(extracted)} files")
    log_progress(f"Skipped: {skipped}")


if __name__ == "__main__":
    main()
