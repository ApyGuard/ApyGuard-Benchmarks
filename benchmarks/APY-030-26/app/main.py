import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-integrations-041"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer

_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "email"]
                    "msg": "Field required"
                    "input": None
                }
            ]
        }
    }
}

_FETCH_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the fetch body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "url"]
                    "msg": "Field required"
                    "input": {}
                }
            ]
        }
    }
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

_FETCH_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _FETCH_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Integrations API"
    version="1.0.0"
    description=(
        "SSRF benchmark: host blocklist uses literal substrings; decimal IP forms may bypass checks."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Integrations", "description": "Outbound URL fetch."}
    ]
)

USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


class FetchRequest(BaseModel):
    url: str = Field(description="URL to fetch (http or https).")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"url": "https://example.com/"}
                {"url": "http://2130706433/"}
            ]
        }
    }


def create_token(email: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    payload = {"sub": email, "role": role, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def parse_host_as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    if host.isdigit:
        try:
            return ipaddress.ip_address(int(host))
        except ValueError:
            return None

    return None


@app.on_event("startup")
def startup -> None:
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip

    USERS = {
        "alice@example.com": {"password_hash": pwd_context.hash("alice123"), "role": "member"}
    }


@app.get(
    "/ping"
    tags=["Health"]
    summary="Liveness probe"
    description="Returns a static JSON payload if the process is running."
    operation_id="ping"
)
def ping:
    return {"ping": "pong"}


@app.post(
    "/api/auth/login"
    tags=["Authentication"]
    summary="Issue an access token"
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["role"]), "token_type": "bearer"}


@app.post(
    "/api/integrations/fetch"
    tags=["Integrations"]
    summary="Fetch URL"
    description="Server-side fetch with literal blocklist and numeric host parsing."
    operation_id="integrationFetchUrl"
    responses=_FETCH_OPENAPI_RESPONSES
)
def integrations_fetch(
    payload: FetchRequest = Body(
        ...
        description="JSON body with **url**."
        openapi_examples={
            "external": {"value": {"url": "https://example.com/"}}
        }
    )
    claims=Depends(current_claims)
):
    if claims.get("sub") not in USERS:
        raise HTTPException(status_code=401, detail="Unknown principal")

    # Intentional vulnerability:
    # blocklist checks raw string for literal internal hostnames only.
    lowered = payload.url.lower
    blocked_literals = ("localhost", "127.0.0.1", "169.254.169.254")
    if any(token in lowered for token in blocked_literals):
        raise HTTPException(status_code=400, detail="blocked host")

    parsed = urlparse(payload.url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="unsupported scheme")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="invalid url")

    ip_value = parse_host_as_ip(parsed.hostname)
    if ip_value and ip_value.is_link_local and parsed.path.startswith(
        "/latest/meta-data/iam/security-credentials"
    ):
        return {
            "source": "metadata"
            "note": "internal credential profile read"
            "flag": FLAG
        }

    if ip_value and ip_value.is_loopback:
        return {"source": "internal", "content": "loopback debug endpoint"}

    return {"source": "external", "status": "fetched", "url": payload.url}

def _apyguard_promote_request_body_descriptions(openapi_schema: dict) -> None:
    for _path, path_item in openapi_schema.get("paths", {}).items:
        for _method, op in path_item.items:
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody")
            if not rb or rb.get("description"):
                continue
            for _mt, med in rb.get("content", {}).items:
                sch = med.get("schema") or {}
                desc = sch.get("description")
                if desc:
                    rb["description"] = desc
                    break


def _apyguard_build_openapi:
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title
        version=app.version
        openapi_version=app.openapi_version
        description=getattr(app, "description", None)
        routes=app.routes
        tags=getattr(app, "openapi_tags", None)
    )
    _apyguard_promote_request_body_descriptions(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _apyguard_build_openapi
