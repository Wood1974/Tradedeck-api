"""Claude calls: checkpoint generation and photo adjudication.

Differences from the parent implementation:

  * claude-sonnet-5 instead of claude-sonnet-4-6 — newer and cheaper
    ($2/$10 per Mtok vs $3/$15), and read from config rather than hardcoded in
    three places while config.ANTHROPIC_MODEL sat unused.
  * Structured outputs (output_config.format) instead of stripping ```json
    fences and hoping. The schema is enforced server-side, which deletes the
    JSONDecodeError branch the parent needed.
  * Prompt caching on the stable system prefix. The instructions are identical
    on every call; only the image and checkpoint vary.
  * The model is told what the metadata *is*, never asked to trust the caller's
    word about it. Every value here is read from the database by the caller —
    see routes.analyze_photo.
"""
import base64
import logging

import anthropic

import config

log = logging.getLogger(__name__)

VERDICTS = ("pass", "flag", "fail", "fake")

_INSPECTOR_SYSTEM = (
    "You are a licensed building inspector and image-forensics analyst reviewing "
    "contractor checkpoint photographs on behalf of the homeowner paying for the work.\n\n"
    "You have two mandates, in order:\n"
    "1. AUTHENTICITY. Is this a real photograph taken on an active job site? Look for "
    "genuine site conditions — dust, debris, tools, real shadows, consistent lighting. "
    "Look against stock imagery, renders, screenshots, watermarks, compositing, and "
    "generated images.\n"
    "2. COMPLIANCE. Does it show what the checkpoint requires, done correctly, to the "
    "trade standard and the cited code section?\n\n"
    "Judge only what is visible. Cite what you actually see rather than what you expect "
    "to see. If the frame does not contain enough to judge, say so and return 'flag' — "
    "an honest abstention is worth more than a confident guess.\n\n"
    "Verdicts: 'pass' work is correct and complete · 'flag' concern or insufficient "
    "evidence · 'fail' wrong, incomplete, or non-compliant · 'fake' not a genuine "
    "photograph of this site."
)

_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "authentic":         {"type": "boolean"},
        "authenticity_note": {"type": "string"},
        "verdict":           {"type": "string", "enum": list(VERDICTS)},
        "confidence":        {"type": "number", "minimum": 0, "maximum": 1},
        "findings":          {"type": "array", "items": {"type": "string"}},
        "notes":             {"type": "string"},
        "required_action":   {"type": ["string", "null"]},
    },
    "required": ["authentic", "authenticity_note", "verdict", "confidence",
                 "findings", "notes", "required_action"],
    "additionalProperties": False,
}

_POINTS_SCHEMA = {
    "type": "object",
    "properties": {
        "points": {
            "type": "array",
            "minItems": 5, "maxItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "point_number": {"type": "integer", "minimum": 1, "maximum": 5},
                    "label":        {"type": "string"},
                    "description":  {"type": "string"},
                },
                "required": ["point_number", "label", "description"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["points"],
    "additionalProperties": False,
}


def _client():
    return anthropic.Anthropic(api_key=config.get("ANTHROPIC_API_KEY"))


def _json_out(resp):
    import json
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text)


def generate_checkpoints(job_description: str) -> list:
    """Five checkpoints for a job description. Raises on API failure."""
    resp = _client().messages.create(
        model=config.get("ANTHROPIC_MODEL"),
        max_tokens=2000,
        system=[{
            "type": "text",
            "text": ("You are a senior general contractor and licensed building "
                     "inspector. Identify the moments in a job where a photograph "
                     "proves the work was done correctly, while it is still cheap to "
                     "fix — the moments a dishonest contractor would most want to "
                     "skip, and the ones that get covered up permanently by the next "
                     "stage of work."),
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content":
                   f"Job description:\n\n{job_description}\n\n"
                   "Give exactly 5 pivotal checkpoints, numbered 1-5 in the order they "
                   "occur on site. For each, state precisely what the photograph must "
                   "show for the checkpoint to be verifiable."}],
        output_config={"format": {"type": "json_schema", "schema": _POINTS_SCHEMA}},
    )
    return _json_out(resp)["points"]


def analyze_photo(image_bytes: bytes, *, point_label: str, point_description: str,
                  code_reference: str, must_show: str, gps_summary: str,
                  provenance_summary: str) -> dict:
    """Adjudicate one checkpoint photo.

    Every keyword argument is derived server-side from the stored row. Nothing
    here comes from the request body — that was the parent's central flaw.
    """
    resp = _client().messages.create(
        model=config.get("ANTHROPIC_MODEL"),
        max_tokens=1500,
        system=[{"type": "text", "text": _INSPECTOR_SYSTEM,
                 "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64",
                                         "media_type": "image/jpeg",
                                         "data": base64.b64encode(image_bytes).decode()}},
            {"type": "text", "text": (
                f"CHECKPOINT: {point_label}\n"
                f"REQUIREMENT: {point_description}\n"
                f"CODE SECTION: {code_reference or 'none cited'}\n"
                f"THE PHOTO MUST SHOW: {must_show or 'see requirement'}\n\n"
                f"SERVER-VERIFIED PROVENANCE (extracted from the stored original, "
                f"not supplied by the uploader):\n"
                f"- Location: {gps_summary}\n"
                f"- Camera metadata: {provenance_summary}\n\n"
                "Assess authenticity first, then compliance."
            )},
        ]}],
        output_config={"format": {"type": "json_schema", "schema": _ANALYSIS_SCHEMA}},
    )
    result = _json_out(resp)

    # An inauthentic photo cannot carry a compliance verdict, whatever the model
    # returned in the verdict field.
    if not result.get("authentic") or result.get("verdict") == "fake":
        result["verdict"] = "fake"
        result["confidence"] = 1.0
        result["notes"] = (f"Flagged as inauthentic: {result.get('authenticity_note','')} "
                           "This checkpoint has not been verified.")
    if result.get("verdict") not in VERDICTS:
        result["verdict"] = "flag"
    return result
