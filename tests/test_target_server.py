from fastapi.testclient import TestClient

from target_server import app

client = TestClient(app)


def test_root_ok():
    assert client.get("/").status_code == 200


def test_login_success():
    r = client.post("/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    assert "token" in r.json()


def test_login_wrong_creds():
    r = client.post("/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401


def test_search_echoes_q():
    r = client.get("/search", params={"q": "hello"})
    assert r.status_code == 200
    assert r.json()["q"] == "hello"


def test_profile_echoes_id():
    assert client.get("/profile", params={"id": "7"}).json()["id"] == "7"


def test_files_echoes_name():
    assert client.get("/files", params={"name": "a.txt"}).json()["name"] == "a.txt"
