"""Mermaid graph generation utilities for threat chain visualization.

This module exposes a small data-holder `ThreatNode` and rendering helpers that
produce Mermaid flowchart syntax suitable for embedding in markdown or sending
as raw syntax to a renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional


class Severity(Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NEUTRAL = "neutral"


@dataclass
class ThreatNode:
    """Represents an event or entity in a threat chain.

    Attributes:
        id: Unique identifier for the node within the graph (no whitespace).
        label: Human readable label to display.
        node_type: One of 'file', 'process', 'network', 'registry' to control iconography.
        severity: Severity enum indicating color coding.
        details: Optional short details to include in tooltip/label.
    """

    id: str
    label: str
    node_type: str = "file"
    severity: Severity = Severity.NEUTRAL
    details: Optional[str] = None


_NODE_SHAPE_FOR_TYPE = {
    "file": "[",       # rectangle
    "process": ")",    # rounded
    "network": ">",    # rhombus-like (via >)
    "registry": "[",   # rectangle
}

_COLOR_FOR_SEVERITY = {
    Severity.MALICIOUS: "#ff4d4f",   # red
    Severity.SUSPICIOUS: "#faad14",  # yellow/orange
    Severity.NEUTRAL: "#8c8c8c",     # gray
}


def _sanitize_id(node_id: str) -> str:
    return node_id.replace(" ", "_").replace("-", "_")


def render_mermaid(nodes: Iterable[ThreatNode], edges: Iterable[tuple[str, str]] | None = None, layout: str = "TD") -> str:
    """Render a Mermaid flowchart string from nodes and edges.

    Args:
        nodes: Iterable of ThreatNode instances.
        edges: Iterable of (from_id, to_id) pairs defining directed edges.
        layout: Mermaid flow direction; 'TD' (top-down) or 'LR' (left-right).

    Returns:
        A string containing the Mermaid flowchart DSL.
    """
    if layout not in ("TD", "LR"):
        raise ValueError("layout must be 'TD' or 'LR'")

    node_map = {n.id: n for n in nodes}
    lines: List[str] = [f"flowchart {layout}"]

    # Emit node definitions with style
    for node in node_map.values():
        nid = _sanitize_id(node.id)
        shape = _NODE_SHAPE_FOR_TYPE.get(node.node_type, "[")
        # Mermaid: id[label]
        label = node.label.replace("\n", "\\n")
        lines.append(f"    {nid}{shape}{label}{shape}")
        color = _COLOR_FOR_SEVERITY.get(node.severity, _COLOR_FOR_SEVERITY[Severity.NEUTRAL])
        # style line: style id fill:<color>,stroke:#333,stroke-width:1px
        lines.append(f"    style {nid} fill:{color},stroke:#333,stroke-width:1px")

    # Emit edges
    if edges:
        for src, dst in edges:
            s = _sanitize_id(src)
            d = _sanitize_id(dst)
            lines.append(f"    {s} --> {d}")

    return "\n".join(lines)


def render_mermaid_markdown(nodes: Iterable[ThreatNode], edges: Iterable[tuple[str, str]] | None = None, layout: str = "TD") -> str:
    """Return a fenced Mermaid markdown block for the graph.

    Args:
        nodes: Iterable of ThreatNode instances.
        edges: Optional iterable of (from, to) tuples.
        layout: 'TD' or 'LR'.

    Returns:
        A markdown string like ```mermaid\n...```.
    """
    mermaid = render_mermaid(nodes, edges, layout)
    return f"```mermaid\n{mermaid}\n```\n"


__all__ = ["ThreatNode", "Severity", "render_mermaid", "render_mermaid_markdown"]
