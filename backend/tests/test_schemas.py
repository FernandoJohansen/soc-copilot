import pytest
from pydantic import ValidationError

from app.schemas.analysis import AnalysisResult, AnalyzeRequest
from app.schemas.event import EventCreate
from app.schemas.incident import IncidentCreate


def test_event_defaults_timestamp_and_raw_data():
    event = EventCreate(source="auth.log", event_type="authentication_failure")
    assert event.raw_data == {}
    assert event.timestamp.tzinfo is not None


def test_event_rejects_empty_source():
    with pytest.raises(ValidationError):
        EventCreate(source="", event_type="x")


@pytest.mark.parametrize("given, expected", [(0, 1), (9, 4), ("2", 2), ("high", 3), (None, 3)])
def test_analysis_severity_is_clamped(given, expected):
    assert AnalysisResult(severity=given).severity == expected


def test_analysis_confidence_is_clamped():
    assert AnalysisResult(confidence=7).confidence == 1.0
    assert AnalysisResult(confidence="n/a").confidence == 0.5


def test_analyze_request_needs_exactly_one_event_source():
    inline = [{"source": "dns", "event_type": "query"}]
    assert AnalyzeRequest(event_ids=[1, 2]).events is None
    assert len(AnalyzeRequest(events=inline).events) == 1
    with pytest.raises(ValidationError):
        AnalyzeRequest()
    with pytest.raises(ValidationError):
        AnalyzeRequest(event_ids=[1], events=inline)


def test_incident_severity_range():
    with pytest.raises(ValidationError):
        IncidentCreate(title="x", severity=5)
