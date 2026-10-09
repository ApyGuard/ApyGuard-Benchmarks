from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import Body, FastAPI, HTTPException
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-ssrf-secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "email"],
                    "msg": "Field required",
                    "input": None,
                },
            ],
        },
    },
}

_FETCH_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the fetch body.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "url"],
                    "msg": "Field required",
                    "input": {},
                },
            ],
        },
    },
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

_FETCH_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _FETCH_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Integration API",
    version="1.0.0",
    description=(
        "SSRF-style integration benchmark: server-side fetch follows user-supplied URLs with weak "
        "egress controls."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Integrations", "description": "Outbound URL fetch helper."},
    ],
)
USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"},
        },
    }


class FetchRequest(BaseModel):
    url: str = Field(description="Absolute URL to retrieve (may resolve to internal hosts in this benchmark).")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"url": "https://example.com/resource"},
                {"url": "http://169.254.169.254/latest/meta-data/"},
            ],
        },
    }


def create_token(email: str, user_id: int):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": str(user_id), "email": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


@app.on_event("startup")
def startup_event():
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()
    USERS = {"alice@example.com": {"id": 1, "password_hash": pwd_context.hash("alice123")}}


@app.get(
    "/ping",
    tags=["Health"],
    summary="Liveness probe",
    description="Returns a static JSON payload if the process is running.",
    operation_id="ping",
)
def ping():
    return {"ping": "pong"}


@app.post(
    "/api/auth/login",
    tags=["Authentication"],
    summary="Issue an access token",
    description="Authenticate with **email** and **password** and receive a JWT **access_token**.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["id"]), "token_type": "bearer"}


@app.post(
    "/api/integrations/fetch",
    tags=["Integrations"],
    summary="Fetch a URL",
    description="Performs a server-side resolution of **url** and returns metadata (egress filtering is intentionally weak).",
    operation_id="integrationFetchUrl",
    responses=_FETCH_OPENAPI_RESPONSES,
)
def fetch_url(
    payload: FetchRequest = Body(
        ...,
        description="JSON body with **url** to fetch.",
        openapi_examples={
            "external": {"summary": "Public URL", "value": {"url": "https://example.com/"}},
            "internal_hint": {
                "summary": "Internal-style host",
                "value": {"url": "http://169.254.169.254/latest/meta-data/"},
            },
        },
    ),
):
    parsed = urlparse(payload.url)
    host = (parsed.hostname or "").lower()

    # Intentional vulnerability: no allowlist/egress control for internal destinations.
    if host in {"169.254.169.254", "internal.apy.local", "localhost"}:
        return {
            "source": "internal",
            "metadata": {
                "service": "payments-worker",
                "token": FLAG,
            },
        }

    return {
        "source": "external",
        "url": payload.url,
        "preview": "ok",
    }

def _apyguard_promote_request_body_descriptions(openapi_schema: dict) -> None:
    for _path, path_item in openapi_schema.get("paths", {}).items():
        for _method, op in path_item.items():
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody")
            if not rb or rb.get("description"):
                continue
            for _mt, med in rb.get("content", {}).items():
                sch = med.get("schema") or {}
                desc = sch.get("description")
                if desc:
                    rb["description"] = desc
                    break


def _apyguard_build_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=getattr(app, "description", None),
        routes=app.routes,
        tags=getattr(app, "openapi_tags", None),
    )
    _apyguard_promote_request_body_descriptions(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _apyguard_build_openapi
