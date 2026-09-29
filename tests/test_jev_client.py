import httpx
import pytest

import jev_client
from jev_client import JevUnavailable, classify

# The canonical set the client actually sends (classic + semantic categories).
CATEGORIES = set(jev_client.CATEGORIES)
CLASSIC = {
    "none", "sql_injection", "xss", "path_traversal", "command_injection",
    "ssrf", "auth_bruteforce", "scanner_probe", "other_exploit",
}

CANNED = {
    "answers": {
        "is_attack": {"type": "noul", "noul": 0.98},
        "category": {
            "choice": "sql_injection",
            "confidence": 0.9,
            "probabilities": {"sql_injection": 0.9, "none": 0.02},
        },
    },
    "usage": {"cost": 0.00003},
}


class FakeResponse:
    def __init__(self, status_code=200, payload=None, bad_json=False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class FakeClient:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.exc:
            raise self.exc
        return self.response


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "dummy-key")


def test_parses_successful_response():
    fake = FakeClient(FakeResponse(200, CANNED))
    r = classify("GET /?id=1' OR 1=1", client=fake)
    assert r.is_attack == 0.98
    assert r.category == "sql_injection"
    assert r.category_confidence == 0.9
    assert r.category_probs == {"sql_injection": 0.9, "none": 0.02}
    assert r.cost == 0.00003


def test_cost_defaults_to_zero():
    payload = {"answers": CANNED["answers"]}
    r = classify("x", client=FakeClient(FakeResponse(200, payload)))
    assert r.cost == 0.0


def test_request_shape_and_auth():
    fake = FakeClient(FakeResponse(200, CANNED))
    classify("the-state", client=fake)
    url, kwargs = fake.calls[0]
    assert url == "https://openrouter.ai/api/v1/systemone"
    assert kwargs["headers"]["Authorization"] == "Bearer dummy-key"
    body = kwargs["json"]
    assert body["model"] == "typesafe/jev-1.13"
    assert body["state"] == "the-state"
    assert body["questions"]["is_attack"]["type"] == "noul"
    cat = body["questions"]["category"]
    assert cat["type"] == "choice"
    assert set(cat["criteria"]) == CATEGORIES
    assert CLASSIC <= set(cat["criteria"])  # classic categories still present
    assert cat["criteria"]["none"] == "Legitimate, benign traffic"


def test_transport_error_raises():
    fake = FakeClient(exc=httpx.ConnectTimeout("timeout"))
    with pytest.raises(JevUnavailable):
        classify("x", client=fake)


@pytest.mark.parametrize("status", [500, 503, 429])
def test_bad_status_raises(status):
    with pytest.raises(JevUnavailable):
        classify("x", client=FakeClient(FakeResponse(status, {})))


def test_malformed_json_raises():
    with pytest.raises(JevUnavailable):
        classify("x", client=FakeClient(FakeResponse(200, bad_json=True)))


def test_missing_fields_raises():
    with pytest.raises(JevUnavailable):
        classify("x", client=FakeClient(FakeResponse(200, {"answers": {}})))


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY")
    with pytest.raises(JevUnavailable):
        classify("x", client=FakeClient(FakeResponse(200, CANNED)))
