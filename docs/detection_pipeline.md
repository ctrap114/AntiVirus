# 检测流水线改进说明

## 标准 ssdeep 模糊签名

`engine/src/layers/hash.rs` 流式计算 MD5、SHA-1、SHA-256，并对完整文件计算标准
spamsum/ssdeep 签名：

```text
<blocksize>:<hash1>:<hash2>
```

新签名可以与标准 ssdeep/libfuzzy 数据交换。实现包含标准的滚动哈希、分块边界、
块大小兼容比较、编辑距离和 7 字节公共子串门槛；模糊命中阈值当前为 `85`，只允许
恶意记录触发恶意结论。数据库中的 clean 模糊记录不会把未知文件判为干净。

旧版本生成的 `ssdeep-lite:<block>:<primary>:<secondary>` 仍可读取，用于平滑迁移，
但新版本不再生成该格式。CSV 示例：

```csv
hash,algorithm,is_malicious
3:aNRn:aNRn,ssdeep,true
<sha256>,sha256,false
```

SQLite 的 `hashes` 表支持 `md5`、`sha1`、`sha256`、`ssdeep` 和旧的 `ssdeep-lite`。

## 威胁情报更新链路

`tools/build_local_hashdb.py` 将来源数据写入同一 SQLite 数据库：

- MalwareBazaar：收录近期样本的 MD5/SHA-1/SHA-256；
- URLhaus：只收录近期 CSV 中状态为 `online` 的恶意下载 URL，并派生公共 IP 或域名；
- ThreatFox：可选，需要 `THREATFOX_AUTH_KEY`，用于补充域名/IP/URL IOC；
- 每条 IOC 保存 `source`、`confidence`、首末次出现、`reference`、标签、元数据和
  `expires_at`。

推荐的更新命令：

```powershell
python tools/build_local_hashdb.py `
  --out data/local_hashes.sqlite `
  --malwarebazaar --mb-limit 500 `
  --urlhaus-recent --urlhaus-limit 500

$env:THREATFOX_AUTH_KEY = "<ThreatFox Auth-Key>"
python tools/build_local_hashdb.py `
  --out data/local_hashes.sqlite `
  --threatfox --threatfox-days 7 --threatfox-limit 500
```

引擎启动时加载 `iocs` 表，只接受置信度至少 `70` 且尚未过期的记录。扫描期间不主动
联网、不修改防火墙，也不把 IOC 当作“访问即阻断”规则；只有沙箱观察到对应 IP、域名
或 URL 时，才把命中交给行为融合层。

## 可信来源和边界

- [ssdeep API](https://ssdeep-project.github.io/ssdeep/doc/api/html/fuzzy_8h_source.html)
  定义了标准模糊哈希/比较 API；项目使用纯 Rust 实现以避免运行时依赖 native wrapper。
- [MalwareBazaar API](https://bazaar.abuse.ch/api/) 提供样本哈希和样本元数据接口。
- [URLhaus API 与下载页](https://urlhaus.abuse.ch/api/) 提供恶意 URL 和网络威胁情报。
- [ThreatFox API](https://threatfox.abuse.ch/api/) 提供带置信度、时间和恶意软件标签的 IOC；
  其接口需要 Auth-Key。

这些源是威胁情报补充源，不等同于完整商业病毒库。更新结果必须保留来源和时间，
并通过过期策略、回滚数据库和误报回归测试后再投入生产。
