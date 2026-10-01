import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from everbloom_viz.report import ReportGenerator


SAMPLE_RESULTS = [
    {
        "file_path": "C:/tmp/a.exe",
        "threat_name": "Suspicious Loader",
        "threat_level": "malicious",
        "engine": "yara",
        "date": "2026-07-24 10:00:00",
        "hash_score": 0.9,
        "yara_score": 0.8,
        "heuristic_score": 0.7,
        "ai_score": 0.6,
        "action": "quarantine",
    },
    {
        "file_path": "C:/tmp/b.exe",
        "threat_name": "Unknown",
        "threat_level": "suspicious",
        "engine": "ai",
        "date": "2026-07-24 11:00:00",
        "hash_score": 0.4,
        "yara_score": 0.1,
        "heuristic_score": 0.6,
        "ai_score": 0.7,
        "action": "review",
    },
]


def test_to_csv_contains_expected_columns_and_rows():
    csv_text = ReportGenerator.to_csv(SAMPLE_RESULTS)
    assert "File Path" in csv_text
    assert "Threat Name" in csv_text
    assert "Hash Score" in csv_text
    assert "AI Score" in csv_text
    assert "C:/tmp/a.exe" in csv_text


def test_to_json_contains_metadata_and_results():
    payload = ReportGenerator.to_json(SAMPLE_RESULTS)
    assert '"metadata"' in payload
    assert '"results"' in payload
    assert '"file_path": "C:/tmp/a.exe"' in payload


def test_to_text_summary_lists_filtered_results():
    text = ReportGenerator.to_text_summary(SAMPLE_RESULTS, threat_level="malicious")
    assert "EverbloomSecurity Scan Report" in text
    assert "C:/tmp/a.exe" in text
    assert "C:/tmp/b.exe" not in text


def test_filter_results_by_engine_and_date_range():
    filtered = ReportGenerator.filter_results(
        SAMPLE_RESULTS,
        engine="ai",
        start_date="2026-07-24 10:30:00",
        end_date="2026-07-24 12:00:00",
    )
    assert len(filtered) == 1
    assert filtered[0]["file_path"] == "C:/tmp/b.exe"


def test_report_generator_normalizes_threat_name_to_standard_format():
    sample = {
        "file_path": "C:/tmp/c.exe",
        "threat_name": "trojan.win32/emotet.a",
        "threat_level": "malicious",
        "engine": "ai",
        "date": "2026-07-24 12:00:00",
        "hash_score": 0.5,
        "yara_score": 0.2,
        "heuristic_score": 0.4,
        "ai_score": 0.8,
        "action": "quarantine",
    }
    csv_text = ReportGenerator.to_csv([sample])
    assert "Trojan.Win32/Emotet.a" in csv_text
