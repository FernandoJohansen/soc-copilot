import json

import pytest

from app.core.config import settings
from app.services import llm
from app.services.llm import LLMError, _parse_response, format_events, get_llm_provider

VALID = {
    "is_incident": True,
    "severity": 4,
    "summary": "40 long TXT queries from 10.0.3.21.",
    "mitre_tactic": "Exfiltration",
    "mitre_technique_id": "t1048",
    "mitre_technique_name": "Exfiltration Over Alternative Protocol",
    "suggested_actions": ["Isolate 10.0.3.21."],
    "confidence": 0.9,
}


def test_parses_plain_json():
    result = _parse_response(json.dumps(VALID))
    assert result.severity == 4
    assert result.mitre_technique_id == "T1048"
    assert result.suggested_actions == ["Isolate 10.0.3.21."]


def test_strips_markdown_fences():
    assert _parse_response(f"```json\n{json.dumps(VALID)}\n```").mitre_tactic == "Exfiltration"


def test_extracts_json_surrounded_by_prose():
    assert _parse_response(f"Here is the analysis: {json.dumps(VALID)} Done.").severity == 4


def test_unparseable_answer_falls_back_to_severity_3():
    result = _parse_response("I could not decide.")
    assert (result.severity, result.confidence) == (3, 0.0)


def test_benign_answer_gets_severity_1_and_no_technique():
    benign = VALID | {
        "is_incident": False,
        "severity": 3,
        "mitre_tactic": "",
        "mitre_technique_id": "",
        "mitre_technique_name": "",
    }
    result = _parse_response(json.dumps(benign))
    assert (result.is_incident, result.severity, result.mitre_technique_id) == (False, 1, None)


def test_format_events_says_what_was_left_out():
    events = [
        {"source": "dns", "event_type": "query", "timestamp": f"t{i}", "raw_data": {"n": i}}
        for i in range(llm.MAX_EVENTS_IN_PROMPT + 5)
    ]
    lines = format_events(events).splitlines()
    assert len(lines) == llm.MAX_EVENTS_IN_PROMPT + 1
    assert "5 later events not shown: 5 dns/query" in lines[-1]


def test_unknown_provider_is_an_llm_error(monkeypatch):
    monkeypatch.setattr(llm, "_instance", None)
    monkeypatch.setattr(settings, "llm_provider", "nope")
    with pytest.raises(LLMError, match="Unknown LLM_PROVIDER"):
        get_llm_provider()


def test_missing_key_is_an_llm_error(monkeypatch):
    monkeypatch.setattr(llm, "_instance", None)
    monkeypatch.setattr(settings, "llm_provider", "claude")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    with pytest.raises(LLMError, match="No API key"):
        get_llm_provider()


def test_ollama_provider_needs_no_key(monkeypatch):
    monkeypatch.setattr(llm, "_instance", None)
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "ollama_model", "qwen2.5:14b")
    provider = get_llm_provider()
    assert (provider.name, provider._model) == ("ollama", "qwen2.5:14b")
    assert str(provider._client.base_url).startswith(settings.ollama_base_url)
    monkeypatch.setattr(llm, "_instance", None)
