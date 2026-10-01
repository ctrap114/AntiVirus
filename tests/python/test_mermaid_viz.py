import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# ensure python package path (repo-root/python)
sys.path.insert(0, str(ROOT / "python"))

from everbloom_viz.mermaid import ThreatNode, Severity, render_mermaid, render_mermaid_markdown


def sample_chain():
    nodes = [
        ThreatNode(id="file_1", label="suspicious.exe", node_type="file", severity=Severity.SUSPICIOUS),
        ThreatNode(id="proc_1", label="suspicious.exe -> child", node_type="process", severity=Severity.SUSPICIOUS),
        ThreatNode(id="net_1", label="C2: 192.168.1.10:443", node_type="network", severity=Severity.MALICIOUS),
        ThreatNode(id="reg_1", label="HKCU\\Software\\Bad", node_type="registry", severity=Severity.SUSPICIOUS),
    ]
    edges = [("file_1", "proc_1"), ("proc_1", "net_1"), ("proc_1", "reg_1")]
    return nodes, edges


def test_render_mermaid_td():
    nodes, edges = sample_chain()
    mermaid = render_mermaid(nodes, edges, layout="TD")
    assert "flowchart TD" in mermaid
    assert "file_1" in mermaid
    assert "proc_1 --> net_1" in mermaid
    assert "style net_1 fill:#ff4d4f" in mermaid


def test_render_mermaid_lr():
    nodes, edges = sample_chain()
    mermaid = render_mermaid(nodes, edges, layout="LR")
    assert "flowchart LR" in mermaid
    assert "file_1 --> proc_1" in mermaid


def test_render_markdown_block():
    nodes, edges = sample_chain()
    md = render_mermaid_markdown(nodes, edges)
    assert md.startswith("```mermaid")
    assert md.strip().endswith("```")
