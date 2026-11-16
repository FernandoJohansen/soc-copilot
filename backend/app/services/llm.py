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
from app.services.severity import SEVERITY_POLICY, STAGE_POLICY, STAGE_SEVERITY, severity_for_stage

SYSTEM_PROMPT = f"""\
You are a SOC triage analyst. You receive a group of related security log events that were \
already correlated by source IP, user and time, plus a few MITRE ATT&CK techniques retrieved \
as candidates. Decide whether the group is a security incident, and classify it.

Many groups are benign: a user mistyping a password, a monitoring system polling ports, a \
backup job touching file shares, a CDN with long hostnames. Judge from what the events show, \
not from volume alone, and set is_incident to false when the activity has an ordinary \
explanation.

Severity policy:
{SEVERITY_POLICY}

You do not write the severity number. You name the attack stage the events show, and the \
severity is derived from it (none 1, reconnaissance 2, attempt 3, success 4). Stages:
{STAGE_POLICY}
Pick the highest stage the events support: one successful login after many failures, or \
one download after a click, makes the whole group "success". The stage says how far the \
attack got; it does not change what the attack is. Choose the tactic and technique from \
what the attacker did (scanning is Discovery, a phishing email is Initial Access, even when \
it succeeded), never from the stage.

Rules for the answer:
- mitre_tactic is the ATT&CK tactic name (for example "Credential Access"). \
mitre_technique_id is the technique ID (for example "T1110"); use the parent technique, not \
a sub-technique. Prefer one of the candidate techniques when it fits; pick another only if \
none of them does.
- When is_incident is false, set attack_stage to "none" and leave the three mitre fields \
empty.
- summary: at most 5 lines, plain language, citing the concrete IPs, users, hosts and counts \
that support the conclusion.
- suggested_actions: 2 to 4 concrete next steps for the analyst. You only suggest; nothing is \
executed automatically.
- confidence: 0 to 1.
"""

ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    # summary comes first: a model that writes the fields in order then reasons before
    # it commits to a verdict, which matters for small local models.
    "properties": {
        "summary": {"type": "string"},
        "is_incident": {"type": "boolean"},
        "attack_stage": {"type": "string", "enum": list(STAGE_SEVERITY)},
        "mitre_tactic": {"type": "string"},
        "mitre_technique_id": {"type": "string"},
        "mitre_technique_name": {"type": "string"},
        "suggested_actions": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    },
    "required": [
        "is_incident",
        "attack_stage",
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


MAX_VALUE_CHARS = 60


def _compact_value(value: Any) -> str:
    """Shorten a long string in the middle, keeping its length visible."""
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        value = f"{value[:16]}...[{len(value)} chars]...{value[-28:]}"
    return json.dumps(value, default=str)


def _is_rendering_of_fields(message: Any, raw: dict[str, Any]) -> bool:
    """True when `message` is just the raw log line the other fields were parsed from."""
    if not isinstance(message, str):
        return False
    others = [str(v) for k, v in raw.items() if k != "message" and v not in (None, "")]
    return sum(v in message for v in others) >= 2


def _short_timestamp(timestamp: Any) -> str:
    """Seconds are enough for triage: drop microseconds and write UTC as Z."""
    text = str(timestamp)
    return re.sub(r"\.\d+", "", text).replace("+00:00", "Z")


def format_events(events: Sequence[dict[str, Any]]) -> str:
    """One compact line per event. Past LLM_MAX_EVENTS, say what was left out.

    Prompt size is what a local model pays for, so redundant text is dropped: a `message`
    that repeats the structured fields, sub-second timestamps, the middle of long strings.
    """
    limit = settings.llm_max_events
    lines = []
    for event in events[:limit]:
        raw = event.get("raw_data") or {}
        skip_message = _is_rendering_of_fields(raw.get("message"), raw)
        fields = " ".join(
            f"{k}={_compact_value(v)}"
            for k, v in raw.items()
            if not (k == "message" and skip_message)
        )
        lines.append(
            f"{_short_timestamp(event.get('timestamp'))} {event.get('source')} "
            f"{event.get('event_type')} {fields}"
        )
    omitted = events[limit:]
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
        "Return the analysis as a JSON object with the keys summary, is_incident, attack_stage, "
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
    stage_severity = severity_for_stage(data.get("attack_stage"))
    if stage_severity is not None:
        # The stage decides the severity; a number the model wrote anyway is ignored. An
        # incident whose stage is "none" contradicts itself: medium, so it still gets a look.
        data["severity"] = max(stage_severity, 2) if data.get("is_incident", True) else 1
    known = AnalysisResult.model_fields.keys()
    result = AnalysisResult(**{k: v for k, v in data.items() if k in known})
    if not result.is_incident:
        # Small models sometimes fill these in anyway; a non-incident has no technique.
        result.severity = 1
        result.attack_stage = "none"
        result.mitre_tactic = result.mitre_technique_id = result.mitre_technique_name = None
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
        self._model = settings.openai_model
        self._client = openai.AsyncOpenAI(api_key=settings.openai_api_key or None, timeout=90.0)

    async def analyze(self, events_text: str, mitre_context: str) -> LLMResponse:
        openai = self._openai
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(events_text, mitre_context)},
                ],
            )
        except openai.AuthenticationError as e:
            raise LLMError(f"{self.name} rejected the API key.") from e
        except openai.RateLimitError as e:
            raise LLMError(f"{self.name} rate limit reached.") from e
        except openai.APIStatusError as e:
            raise LLMError(f"{self.name} API error {e.status_code}: {e.message}") from e
        except openai.APIConnectionError as e:
            raise LLMError(f"Could not reach the {self.name} API.") from e
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


class OllamaProvider(LLMProvider):
    """A local model served by Ollama, through its native chat API.

    The native API (unlike the OpenAI-compatible one) constrains the answer to the JSON
    schema and lets us set the context window, which Ollama otherwise truncates silently.
    """

    name = "ollama"

    def __init__(self) -> None:
        import httpx

        self._httpx = httpx
        self._model = settings.ollama_model
        base_url = settings.ollama_base_url.rstrip("/").removesuffix("/v1")
        # Local models are slow, on CPU especially: long timeout.
        self._client = httpx.AsyncClient(base_url=base_url, timeout=settings.ollama_timeout)

    async def analyze(self, events_text: str, mitre_context: str) -> LLMResponse:
        httpx = self._httpx
        payload = {
            "model": self._model,
            "stream": False,
            "format": ANALYSIS_SCHEMA,
            "options": {"num_ctx": settings.ollama_num_ctx, "temperature": 0},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(events_text, mitre_context)},
            ],
        }
        try:
            response = await self._client.post("/api/chat", json=payload)
        except httpx.TimeoutException as e:
            raise LLMError(f"Ollama did not answer within {settings.ollama_timeout:.0f} s.") from e
        except httpx.HTTPError as e:
            raise LLMError(f"Could not reach Ollama at {self._client.base_url}.") from e
        if response.status_code == 404:
            raise LLMError(f"Ollama has no model {self._model!r}; run `ollama pull {self._model}`.")
        if response.status_code >= 400:
            raise LLMError(f"Ollama error {response.status_code}: {response.text[:200]}")
        data = response.json()
        usage = LLMUsage(
            model=data.get("model", self._model),
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
        )
        content = (data.get("message") or {}).get("content", "")
        return LLMResponse(result=_parse_response(content), usage=usage)


_PROVIDERS: dict[str, type[LLMProvider]] = {
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}
_instance: LLMProvider | None = None


def llm_configured() -> bool:
    """True when credentials for the selected provider are present."""
    if settings.llm_provider == "ollama":
        return True  # local server, no key
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
