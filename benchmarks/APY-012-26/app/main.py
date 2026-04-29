from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-nosql-secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard NoSQL Auth API"
    version="1.0.0"
    description=(
        "NoSQL-style operator injection benchmark: login matching supports attacker-controlled "
        "operator objects such as **$ne**."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Admin", "description": "Administrative notes."}
    ]
)
bearer_scheme = HTTPBearer
USERS = []
FLAG = ""


class LoginRequest(BaseModel):
    email: str | dict[str, Any] = Field(
        description="Email string or operator object (e.g. `{\"$ne\": \"\"}`) matched against stored users."
    )
    password: str | dict[str, Any] = Field(
        description="Password string or operator object used with the same matching rules as **email**."
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": {"$ne": ""}, "password": {"$ne": ""}}
            ]
        }
    }


def create_token(user: dict[str, Any]):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": str(user["id"]), "email": user["email"], "role": user["role"], "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def _match(field_value: str, condition: Any) -> bool:
    if isinstance(condition, dict):
        # Intentional vulnerability: supports attacker-controlled query operators.
        if "$ne" in condition:
            return field_value != condition["$ne"]
        return False
    return field_value == condition


@app.on_event("startup")
def startup_event:
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip
    USERS = [
        {"id": 1, "email": "alice@example.com", "password": "alice123", "role": "member"}
        {"id": 2, "email": "admin@apy.local", "password": "AdminNoSQL!", "role": "admin"}
    ]


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
    description="Authenticates using flexible matching on **email** and **password** fields."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "normal": {"value": {"email": "alice@example.com", "password": "alice123"}}
            "operator_example": {"value": {"email": {"$ne": ""}, "password": {"$ne": ""}}}
        }
    )
):
    for user in USERS:
        if _match(user["email"], payload.email) and _match(user["password"], payload.password):
            return {"access_token": create_token(user), "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid email or password")


@app.get(
    "/api/admin/notes"
    tags=["Admin"]
    summary="Admin notes"
    description="Returns internal notes when JWT **role** is **admin**."
    operation_id="getAdminNotes"
)
def admin_notes(claims=Depends(current_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return {"notes": "internal", "flag": FLAG}

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
