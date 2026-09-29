"""Build a compact text "state" describing an HTTP request for Jev."""

MAX_CHARS = 8000
MARKER = "...[truncated]"
FIELD_MAX = 1000  # cap for path / query / header values
SELECTED_HEADERS = ("host", "user-agent", "content-type", "referer")


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - len(MARKER)] + MARKER


def build_state(method: str, path: str, query: str, headers: dict, body: str) -> str:
    lower = {
        str(k).lower(): str(v)
        for k, v in (headers or {}).items()
        if not str(k).lower().startswith("x-truth-")
    }
    lines = [
        f"Method: {_clip(method or '', FIELD_MAX)}",
        f"Path: {_clip(path or '', FIELD_MAX)}",
        f"Query: {_clip(query or '', FIELD_MAX)}",
    ]
    for name in SELECTED_HEADERS:
        if name in lower:
            lines.append(f"Header {name}: {_clip(lower[name], FIELD_MAX)}")
    lines.append(f"Cookie present: {'yes' if 'cookie' in lower else 'no'}")
    prefix = "\n".join(lines) + "\nBody: "
    room = max(MAX_CHARS - len(prefix), 0)
    return _clip(prefix + (body or ""), MAX_CHARS) if room else prefix[:MAX_CHARS]
