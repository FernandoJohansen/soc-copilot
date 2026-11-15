"""Pluggable LLM providers. The rest of the app only sees LLMProvider.analyze()."""

import json
import os
import re
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.schemas.analysis import AnalysisResult, LLMUsage
from app.services.severity import SEVERITY_POLICY

MAX_EVENTS_IN_PROMPT = 300

SYSTEM_PROMPT = f"""\
You are a SOC triage analyst. You receive a group of related security log events that were \
already correlated by source IP, user and time, plus a few MITRE ATT&CK techniques retrieved \
as candidates. Decide whether the group is a security incident, and classify it.

Many groups are benign: a user mistyping a password, a monitoring system polling ports, a \
backup job touching file shares, a CDN with long hostnames. Judge from what the events show, \
not from volume alone, and set is_incident to false when the activity has an ordinary \
explanation.

Severity policy (use it exactly):
{SEVERITY_POLICY}

Rules for the answer:
- mitre_tactic is the ATT&CK tactic name (for example "Credential Access"). \
mitre_technique_id is the technique ID (for example "T1110"); use the parent technique, not \
a sub-technique. Prefer one of the candidate techniques when it fits; pick another only if \
none of them does.
- When is_incident is false, set severity to 1 and leave the three mitre fields empty.
- summary: at most 5 lines, plain language, citing the concrete IPs, users, hosts and counts \
that support the conclusion.
- suggested_actions: 2 to 4 concrete next steps for the analyst. You only suggest; nothing is \
executed automatically.
- confidence: 0 to 1.
"""

ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_incident": {"type": "boolean"},
        "severity": {"type": "integer", "enum": [1, 2, 3, 4]},
        "summary": {"type": "string"},
        "mitre_tactic": {"type": "string"},
        "mitre_technique_id": {"type": "string"},
        "mitre_technique_name": {"type": "string"},
        "suggested_actions": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    },
    "required": [
        "is_incident",
        "severity",
        "summary",
        "mitre_tactic",
        "mitre_technique_id",
        "mitre_technique_name",
        "suggested_actions",
        "confidence",
    ],
    "additionalProperties": False,
}


class LLMError(Exception):
    """The provider could not produce an analysis (no key, network, rate limit, refusal)."""


@dataclass
class LLMResponse:
    result: AnalysisResult
    usage: LLMUsage


def format_events(events: Sequence[dict[str, Any]]) -> str:
    """One line per event. Past MAX_EVENTS_IN_PROMPT, say what was left out."""
    lines = []
    for event in events[:MAX_EVENTS_IN_PROMPT]:
        raw = event.get("raw_data") or {}
        fields = " ".join(f"{k}={json.dumps(v, default=str)}" for k, v in raw.items())
        lines.append(
            f"{event.get('timestamp')} {event.get('source')} {event.get('event_type')} {fields}"
        )
    omitted = events[MAX_EVENTS_IN_PROMPT:]
    if omitted:
        kinds = Counter(f"{e.get('source')}/{e.get('event_type')}" for e in omitted)
        breakdown = ", ".join(f"{n} {kind}" for kind, n in kinds.most_common())
        lines.append(f"[{len(omitted)} later events not shown: {breakdown}]")
    return "\n".join(lines)


def format_mitre_context(techniques: Sequence[dict[str, Any]]) -> str:
    if not techniques:
        return "(no candidate techniques retrieved)"
    return "\n".join(
        f"- {t['technique_id']} {t['name']} (tactic: {t['tactic']}): {t['description']} "
        f"Detection: {t.get('detection_hints', '')}"
        for t in techniques
    )


def build_user_prompt(events_text: str, mitre_context: str) -> str:
    return (
        "Candidate MITRE ATT&CK techniques:\n"
        f"{mitre_context}\n\n"
        "Events:\n"
        f"{events_text}\n\n"
        "Return the analysis as a JSON object with the keys is_incident, severity, summary, "
        "mitre_tactic, mitre_technique_id, mitre_technique_name, suggested_actions, confidence."
    )


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def _parse_response(raw: str) -> AnalysisResult:
    """Parse the model's JSON. On anything unparseable, fall back to a severity-3 result."""
    text = _FENCE.sub("", raw.strip()).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        try:
            data = json.loads(text[start : end + 1]) if start >= 0 and end > start else None
        except json.JSONDecodeError:
            data = None
    if not isinstance(data, dict):
        return AnalysisResult(
            severity=3,
            summary="The model's answer could not be parsed; review the events manually.",
            confidence=0.0,
        )
    for key in ("mitre_tactic", "mitre_technique_id", "mitre_technique_name"):
        if not data.get(key):
            data[key] = None
    if data.get("mitre_technique_id"):
        data["mitre_technique_id"] = str(data["mitre_technique_id"]).strip().upper()
    if not isinstance(data.get("suggested_actions"), list):
        data["suggested_actions"] = []
    known = AnalysisResult.model_fields.keys()
    result = AnalysisResult(**{k: v for k, v in data.items() if k in known})
    if not result.is_incident:
        result.severity = 1
    return result


class LLMProvider(ABC):
    name: str

    @abstractmethod
    async def analyze(self, events_text: str, mitre_context: str) -> LLMResponse: ...


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(self) -> None:
        import anthropic

        self._anthropic = anthropic
        # With no explicit key the SDK resolves credentials from the environment.
        self._client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key or None, timeout=90.0
        )

    async def analyze(self, events_text: str, mitre_context: str) -> LLMResponse:
        anthropic = self._anthropic
        try:
            # Security logs can trip the model's safety classifiers; the server-side
            # fallback re-runs a declined request on another model inside the same call.
            response = await self._client.beta.messages.create(
                model=settings.anthropic_model,
                max_tokens=settings.llm_max_tokens,
                system=SYSTEM_PROMPT,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                output_config={
                    "effort": settings.anthropic_effort,
                    "format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA},
                },
                messages=[
                    {"role": "user", "content": build_user_prompt(events_text, mitre_context)}
                ],
            )
        except anthropic.AuthenticationError as e:
            raise LLMError("Anthropic rejected the API key.") from e
        except anthropic.RateLimitError as e:
            raise LLMError("Anthropic rate limit reached.") from e
        except anthropic.APIStatusError as e:
            raise LLMError(f"Anthropic API error {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:
            raise LLMError("Could not reach the Anthropic API.") from e
        except anthropic.AnthropicError as e:  # e.g. no credentials configured
            raise LLMError(str(e)) from e

        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            raise LLMError(f"The model declined to analyze these events (category: {category}).")
        if response.stop_reason == "max_tokens":
            raise LLMError("The model ran out of output tokens; raise LLM_MAX_TOKENS.")
        text = next((b.text for b in response.content if b.type == "text"), "")
        usage = LLMUsage(
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )
        return LLMResponse(result=_parse_response(text), usage=usage)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self) -> None:
        import openai

        self._openai = openai
        self._client = openai.AsyncOpenAI(api_key=settings.openai_api_key or None, timeout=90.0)

    async def analyze(self, events_text: str, mitre_context: str) -> LLMResponse:
        openai = self._openai
        try:
            response = await self._client.chat.completions.create(
                model=settings.openai_model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(events_text, mitre_context)},
                ],
            )
        except openai.AuthenticationError as e:
            raise LLMError("OpenAI rejected the API key.") from e
        except openai.RateLimitError as e:
            raise LLMError("OpenAI rate limit reached.") from e
        except openai.APIStatusError as e:
            raise LLMError(f"OpenAI API error {e.status_code}: {e.message}") from e
        except openai.APIConnectionError as e:
            raise LLMError("Could not reach the OpenAI API.") from e
        except openai.OpenAIError as e:
            raise LLMError(str(e)) from e

        usage = LLMUsage(
            model=response.model,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
        )
        return LLMResponse(
            result=_parse_response(response.choices[0].message.content or ""), usage=usage
        )


_PROVIDERS: dict[str, type[LLMProvider]] = {"claude": ClaudeProvider, "openai": OpenAIProvider}
_instance: LLMProvider | None = None


def llm_configured() -> bool:
    """True when credentials for the selected provider are present."""
    if settings.llm_provider == "openai":
        return bool(settings.openai_api_key or os.getenv("OPENAI_API_KEY"))
    return bool(
        settings.anthropic_api_key
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("ANTHROPIC_AUTH_TOKEN")
    )


def get_llm_provider() -> LLMProvider:
    """Singleton for the provider named by LLM_PROVIDER."""
    global _instance
    if _instance is None:
        try:
            provider_cls = _PROVIDERS[settings.llm_provider]
        except KeyError:
            raise LLMError(
                f"Unknown LLM_PROVIDER {settings.llm_provider!r}; use one of {sorted(_PROVIDERS)}."
            ) from None
        if not llm_configured():
            raise LLMError(f"No API key configured for the {settings.llm_provider} provider.")
        try:
            _instance = provider_cls()
        except Exception as e:  # the SDK constructor raises its own error types
            raise LLMError(str(e)) from e
    return _instance
