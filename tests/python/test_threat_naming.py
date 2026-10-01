import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from everbloom_viz.threat_naming import ThreatNameFormat


def test_is_valid_threat_name():
    assert ThreatNameFormat.is_valid_threat_name("Trojan.Win32/Emotet.A")
    assert ThreatNameFormat.is_valid_threat_name("Backdoor.Linux/AgentTesla.gen")
    assert ThreatNameFormat.is_valid_threat_name("Exploit.JS/StealKit.generic")
    assert not ThreatNameFormat.is_valid_threat_name("Suspicious Loader")


def test_normalize_threat_name_canonicalizes_known_components():
    assert ThreatNameFormat.normalize_threat_name("trojan.win32/emotet.a") == "Trojan.Win32/Emotet.a"
    assert ThreatNameFormat.normalize_threat_name("Backdoor.Linux/AgentTesla.GEN") == "Backdoor.Linux/AgentTesla.gen"


def test_format_threat_name_builds_standard_string():
    assert (
        ThreatNameFormat.format_threat_name("Trojan", "Win32", "Emotet", "A")
        == "Trojan.Win32/Emotet.A"
    )
    assert (
        ThreatNameFormat.format_threat_name("Spyware", "AndroidOS", "Stealer")
        == "Spyware.AndroidOS/Stealer"
    )
