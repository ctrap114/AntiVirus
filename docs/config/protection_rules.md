# Protection rules

Everbloom Security accepts an explicit JSON policy file through the `EVERBLOOM_POLICY_RULES` environment variable. The file is validated before any rule is sent to the driver.

In addition to JSON, `.hpol` files are supported. JSON accepts the English and Simplified Chinese aliases `process/进程`, `file/文件`, `network/网络`, and `block/阻断/拦截/禁止`. The `.hpol` format uses the same bilingual keywords and is easier to edit by hand. See `data/policy_rules.hpol` for an example.

The repository includes a safe smoke-test profile at `data/policy_rules.json`. It blocks only an exact Everbloom Security quarantine sample path and the documentation-only IPv4 address `192.0.2.1:443`; it does not block normal Windows executables or live threat-intelligence addresses.

```powershell
$env:EVERBLOOM_POLICY_RULES = "E:\EverbloomSecurity\EverbloomSecurity\data\policy_rules.json"
```

For production, copy `data/policy_rules.example.json` to a deployment-owned, ACL-protected path and set only the rules that are intentionally managed. The example is disabled by design. The sample profile above is suitable for driver smoke tests, not as a threat-intelligence feed.

Supported kinds are:

- `process`: exact image path matching.
- `file`: exact file path matching for create/write/set-information enforcement.
- `network`: IPv4 address matching, with an optional destination port. Omitting `port` blocks every destination port for that address.

Rules are limited to 64 per kind, use the `block` action, and do not accept wildcards. The driver keeps the policy in non-paged memory and applies it at the process, minifilter, and WFP enforcement points. A missing driver is reported as `unsupported`; it does not make the scanner fail.

Use reserved documentation addresses such as `192.0.2.1` only for tests. Real threat-intelligence indicators should be imported through the signed/local threat-intel database workflow rather than copied into a source file.
