from fastapi.testclient import TestClient

import target_server

client = TestClient(target_server.app)


def test_shop_home_has_search_login_and_files():
    r = client.get("/shop")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    html = r.text
    assert 'action="/shop/search"' in html
    assert 'action="/shop/login"' in html and 'method="post"' in html
    assert "/shop/files?name=" in html


def test_search_filters_products_and_echoes_query():
    r = client.get("/shop/search", params={"q": "shoe"})
    assert r.status_code == 200
    assert "Trail Running Shoes" in r.text
    assert "Mechanical Keyboard" not in r.text
    assert "shoe" in r.text


def test_search_escapes_user_input():
    r = client.get("/shop/search", params={"q": "<script>alert(1)</script>"})
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_login_form_success_and_failure():
    ok = client.post("/shop/login", content="username=admin&password=admin",
                     headers={"content-type": "application/x-www-form-urlencoded"})
    assert ok.status_code == 200 and "Welcome back, admin" in ok.text
    bad = client.post("/shop/login", content="username=admin&password=nope",
                      headers={"content-type": "application/x-www-form-urlencoded"})
    assert bad.status_code == 401 and "Wrong username or password" in bad.text


def test_files_known_and_unknown():
    ok = client.get("/shop/files", params={"name": "invoice_2026.pdf"})
    assert ok.status_code == 200 and "invoice_2026.pdf" in ok.text
    missing = client.get("/shop/files", params={"name": "nope.txt"})
    assert missing.status_code == 404


def test_json_api_routes_unchanged():
    assert client.get("/search", params={"q": "hello"}).json() == {"q": "hello"}
