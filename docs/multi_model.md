# Multi-model ONNX inference

Everbloom Security supports a primary model, the legacy fallback model, and an arbitrary
number of user-managed models. When ensemble mode is enabled, these models are
evaluated concurrently and combined using one of:

- `weighted_mean`: weighted score average;
- `max_risk`: highest model score;
- `majority_vote`: weighted vote at the `0.5` threshold.

Each model may have its own `features.json` and `model_contract.json`. Models
with different input widths must be kept in separate directories so their
sidecars cannot be confused.

## User import

The WinUI Settings page has an **Import ONNX model** action. Imported models
are copied to the per-user model directory:

```text
%LOCALAPPDATA%\EverbloomSecurity\models\imported\<model-id>\model.onnx
```

If the source directory contains `features.json` or `model_contract.json`, the
sidecars are copied with the model. The engine validates the extension, file
size (1 byte to 512 MiB), sidecar parsing, and ONNX graph loading before adding
the model. Failed imports are rolled back.

The IPC import command is also available to the GUI bridge:

```text
import_model:<absolute-path-to-model.onnx>
set_ai_strategy:weighted_mean|max_risk|majority_vote
```

For automation, the authenticated admin HTTP interface exposes:

```text
GET  /admin/ai/models
POST /admin/ai/models/import
POST /admin/ai/models/update
POST /admin/ai/models/remove
```

Example import body:

```json
{
  "source_path": "C:/Models/custom.onnx",
  "id": "custom-detector",
  "kind": "cnn",
  "weight": 0.25,
  "enabled": true
}
```

The admin HTTP server remains disabled unless both
`EVERBLOOM_ADMIN_HTTP_ADDR` and a non-empty `EVERBLOOM_ADMIN_TOKEN` are set.

## Persistent registry

The user registry is stored as `models.json` in
`%LOCALAPPDATA%\EverbloomSecurity\models`. A compatible manual configuration is:

```json
{
  "strategy": "weighted_mean",
  "models": [
    {
      "id": "advanced",
      "path": "imported/advanced/model.onnx",
      "kind": "cnn",
      "weight": 0.3,
      "enabled": true
    }
  ]
}
```

The registry is loaded at engine startup and can be reloaded through the
existing configuration watcher. A model that fails validation is skipped and
does not prevent other registered models from running.

## Runtime isolation and degraded AI state

ONNX execution uses a dedicated, bounded Rayon pool so model inference does not
share the scanner's lightweight hash/YARA worker pool. The default pool size is
the smaller of two threads and the available CPU count; it can be adjusted with
`EVERBLOOM_AI_THREADS` (limited to four threads). Feature vectors are cached by
the sampled content SHA-256, file size, and feature-map digest, with a bounded
1024-entry generation.

Model hot reload compiles off the inference read path and atomically swaps the
runnable plan. Model files are limited to 512 MiB and compilation returns after
`EVERBLOOM_AI_MODEL_LOAD_TIMEOUT_MS` (default 30 seconds, bounded to 1--120
seconds). A timed-out native graph compiler worker may finish in the background;
the old runnable remains active and no partially compiled plan is published.

Inference failures are not silent: the returned `AiScore` carries
`is_fallback=true` and a reason, and the process maintains the monotonic
`ai_inference_error_count()` counter. The current scan-result cache stores only
small reusable evidence (file context, heuristic score, and raw per-model AI
scores) separately from the final decision. Changing AI blend/ensemble settings
advances only the decision generation; an unchanged clean file can be
re-decided without re-running ONNX, hash, YARA, or sandbox. Model imports,
layer-switch changes, rule changes, and kernel policy changes still invalidate
the relevant evidence or full cache.
If a re-decision becomes positive or suspicious, the engine deliberately falls
back to the complete pipeline so enforcement and rollback cannot be skipped.
