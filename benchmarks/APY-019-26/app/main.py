from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-policy-shadowing-secret"
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

_EXPORT_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the export body.",
        "value": {
            "detail": [
                {
                    "type": "bool_parsing",
                    "loc": ["body", "include_events"],
                    "msg": "Input should be a valid boolean, unable to interpret input",
                    "input": "not-a-boolean",
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

_EXPORT_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _EXPORT_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Admin API",
    version="1.0.0",
    description=(
        "Route shadowing benchmark: a misspelled path exposes the same export capability without "
        "admin checks."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Admin", "description": "User export operations."},
    ],
)
bearer = HTTPBearer()
USERS = {}
EXPORTS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "admin@example.com", "password": "admin123"},
            ],
        },
    }


class UserExportRequest(BaseModel):
    include_events: bool = Field(default=True, description="Whether to include event counts in the export.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"include_events": True}, {"include_events": False}],
        },
    }


def create_token(user: dict):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {"sub": str(user["id"]), "email": user["email"], "role": user["role"], "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def require_admin(claims: dict):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin required")


def export_payload(user_id: int):
    payload = EXPORTS.get(user_id)
    if not payload:
        raise HTTPException(status_code=404, detail="user export not found")
    return payload


@app.on_event("startup")
def startup_event():
    global USERS, EXPORTS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()

    USERS = {
        "alice@example.com": {
            "id": 1,
            "email": "alice@example.com",
            "role": "member",
            "password_hash": pwd_context.hash("alice123"),
        },
        "admin@example.com": {
            "id": 2,
            "email": "admin@example.com",
            "role": "admin",
            "password_hash": pwd_context.hash("admin123"),
        },
    }

    EXPORTS = {
        1: {"user_id": 1, "account_type": "member", "events": 3},
        2: {"user_id": 2, "account_type": "admin", "events": 42, "flag": FLAG},
    }


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
            "member": {"value": {"email": "alice@example.com", "password": "alice123"}},
            "admin": {"value": {"email": "admin@example.com", "password": "admin123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.post(
    "/api/users/{user_id}/admin/export",
    tags=["Admin"],
    summary="Admin export (canonical)",
    description="Canonical admin export; requires **admin** role.",
    operation_id="adminExportCanonical",
    responses=_EXPORT_OPENAPI_RESPONSES,
)
def admin_export(
    user_id: int,
    _payload: UserExportRequest = Body(
        ...,
        description="Export options.",
        openapi_examples={
            "with_events": {"value": {"include_events": True}},
        },
    ),
    claims=Depends(current_claims),
):
    require_admin(claims)
    return {"route": "canonical", "export": export_payload(user_id)}


@app.post(
    "/api/user/{user_id}/admin/export",
    tags=["Admin"],
    summary="Admin export (shadow route)",
    description="Alternate path with the same behavior but without enforcing admin role (intentional).",
    operation_id="adminExportShadow",
    responses=_EXPORT_OPENAPI_RESPONSES,
)
def admin_export_shadow(
    user_id: int,
    _payload: UserExportRequest = Body(
        ...,
        description="Export options.",
        openapi_examples={
            "with_events": {"value": {"include_events": True}},
        },
    ),
    _claims=Depends(current_claims),
):
    # Intentional vulnerability: shadow route reaches same capability without admin policy.
    return {"route": "shadow", "export": export_payload(user_id)}

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
