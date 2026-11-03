import base64
import hashlib
import hmac
import json
import os
import secrets
import time


_SECRET = os.environ.get("DBDIAG_SECRET") or secrets.token_urlsafe(48)
TOKEN_TTL = 60 * 60 * 8


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"{base64.urlsafe_b64encode(salt).decode()}:{base64.urlsafe_b64encode(derived).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_part, hash_part = stored.split(":", 1)
        salt = base64.urlsafe_b64decode(salt_part.encode())
        expected = base64.urlsafe_b64decode(hash_part.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_token(user_id: int, role: str) -> str:
    payload = {"sub": user_id, "role": role, "exp": int(time.time()) + TOKEN_TTL}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    signature = hmac.new(_SECRET.encode(), encoded, hashlib.sha256).digest()
    return f"{encoded.decode()}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def verify_token(token: str) -> dict | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(_SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied):
            return None
        payload_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(payload_bytes)
        if not isinstance(payload.get("sub"), int) or payload.get("exp", 0) < time.time():
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
