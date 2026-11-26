import base64

from fastapi.testclient import TestClient

from server import insecure_app, secure_app

ins = TestClient(insecure_app.app)
sec = TestClient(secure_app.app, base_url="https://testserver")


def test_insecure_has_no_security_headers():
    h = ins.get("/").headers
    assert "strict-transport-security" not in h and "content-security-policy" not in h


def test_secure_headers_present():
    h = sec.get("/").headers
    assert h["strict-transport-security"].startswith("max-age=63072000")
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "default-src 'self'" in h["content-security-policy"]
    assert h["referrer-policy"] == "no-referrer"


def test_cookie_flags():
    bad = ins.post("/login", data={"username": "a", "password": "b"}).headers["set-cookie"].lower()
    assert "secure" not in bad and "httponly" not in bad
    good = sec.post("/login", data={"username": "a", "password": "b"}).headers["set-cookie"].lower()
    assert "secure" in good and "httponly" in good and "samesite=strict" in good


def test_basic_auth():
    tok = base64.b64encode(b"bob:pw").decode()
    assert sec.get("/basic").status_code == 401
    assert sec.get("/basic", headers={"Authorization": f"Basic {tok}"}).json()["user"] == "bob"


def test_rate_limit():
    secure_app._attempts.clear()
    codes = [sec.post("/login", data={"username": "x", "password": "y"}).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]
