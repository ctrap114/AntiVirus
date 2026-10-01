# libeverbloom_rs

Rust accelerated core library for Everbloom Security.

## 目标

- 高性能 PE 解析与特征提取
- 多线程哈希/熵计算
- YARA-X 规则引擎
- Aho-Corasick 模式匹配
- 线程安全 LRU 缓存
- 文件系统事件监控
- Windows API 安全调用
- 异步任务队列

## 目录结构

- `src/lib.rs`：PyO3 绑定和模块注册
- `src/rust_pe_parser.rs`：PE 文件结构化解析
- `src/rust_feature_extractor.rs`：并行特征计算
- `src/rust_rule_engine.rs`：YARA 规则加载与匹配
- `src/rust_pattern_matcher.rs`：Aho-Corasick 字符串模式匹配
- `src/rust_cache.rs`：分片线程安全 LRU 缓存
- `src/rust_fs_monitor.rs`：文件事件监听
- `src/rust_win_api.rs`：Windows 注册表/服务/进程调用
- `src/rust_scan_pipeline.rs`：扫描流水线编排
- `src/rust_sandbox_queue.rs`：Tokio 异步任务队列

## 构建

建议使用 `maturin` 或 `setuptools-rust` 将本库编译为 Python 扩展：

```bash
cd libeverbloom_rs
cargo build --release
```

如需启用 YARA 支持：

```bash
cargo build --release --features with_yara
```

## Python 绑定示例

```python
import libeverbloom_rs
parser = libeverbloom_rs.PeParser()
metadata = parser.parse_file('samples/test.exe')
```
