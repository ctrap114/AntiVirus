# Everbloom Security Visualization Helpers

This package provides lightweight Mermaid graph generation helpers for threat-chain visualization.

## Example

```python
from everbloom_viz.mermaid import ThreatNode, Severity, render_mermaid

nodes = [
    ThreatNode(id="file_1", label="suspicious.exe", node_type="file", severity=Severity.SUSPICIOUS),
    ThreatNode(id="proc_1", label="suspicious.exe", node_type="process", severity=Severity.MALICIOUS),
]
edges = [("file_1", "proc_1")]
print(render_mermaid(nodes, edges, layout="TD"))
```
