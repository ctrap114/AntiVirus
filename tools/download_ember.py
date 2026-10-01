"""下载 EMBER 2018 v2 数据集（带断点续传和 SHA-256 校验）"""
import hashlib
import os
import shutil
import sys
import urllib.request
from pathlib import Path

URL = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EXPECTED_SHA = "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
OUTPUT = Path("E:/EMBER_dataset_2018_2.tar.bz2")
CHUNK_SIZE = 1024 * 1024  # 1MB chunks


def download_with_resume(url: str, output: Path, chunk_size: int = CHUNK_SIZE) -> bool:
    """下载文件，支持断点续传。"""
    existing = 0
    mode = "wb"
    if output.exists():
        existing = output.stat().st_size
        mode = "ab"
        print(f"Resuming from {existing / 1024 / 1024:.1f} MB")

    headers = {"Range": f"bytes={existing}-"} if existing > 0 else {}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as response:
            content_length = response.headers.get("Content-Length")
            if content_length:
                total = existing + int(content_length)
                print(f"Total size: {total / 1024 / 1024:.1f} MB")

            with open(output, mode) as f:
                downloaded = existing
                last_print = 0
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded - last_print >= 10 * 1024 * 1024:  # 每 10MB 打印
                        pct = (downloaded / total * 100) if total else 0
                        print(f"  {downloaded / 1024 / 1024:.1f} MB / {total / 1024 / 1024:.1f} MB ({pct:.1f}%)")
                        last_print = downloaded
            return True
    except Exception as e:
        print(f"Download error: {e}", file=sys.stderr)
        return False


def verify_sha(file: Path, expected: str) -> bool:
    """验证文件 SHA-256。"""
    print(f"Verifying SHA-256 of {file.name}...")
    sha = hashlib.sha256()
    with open(file, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    actual = sha.hexdigest()
    print(f"  Expected: {expected}")
    print(f"  Actual:   {actual}")
    return actual == expected


def main():
    print("=== EMBER 2018 v2 数据集下载器 ===")
    print(f"URL: {URL}")
    print(f"Output: {OUTPUT}")
    print(f"Expected SHA-256: {EXPECTED_SHA}")

    if OUTPUT.exists():
        size = OUTPUT.stat().st_size
        print(f"File exists, size: {size / 1024 / 1024:.1f} MB")

    print("\n开始下载...")
    success = download_with_resume(URL, OUTPUT)
    if not success:
        print("下载失败，可重试此脚本。", file=sys.stderr)
        return 1

    if not OUTPUT.exists() or OUTPUT.stat().st_size == 0:
        print("下载的文件无效。", file=sys.stderr)
        return 1

    print(f"\n下载完成: {OUTPUT.stat().st_size / 1024 / 1024:.1f} MB")

    if not verify_sha(OUTPUT, EXPECTED_SHA):
        print("SHA-256 校验失败，文件可能已损坏。", file=sys.stderr)
        return 1

    print("\n[OK] EMBER 2018 v2 数据集下载并校验成功！")
    return 0


if __name__ == "__main__":
    sys.exit(main())
