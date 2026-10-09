from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-wildcard-role-secret"
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

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Audit API",
    version="1.0.0",
    description=(
        "Role wildcard benchmark: superuser checks use substring matching on **role**, allowing "
        "unintended roles to pass."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Audit", "description": "Support and admin audit endpoints."},
    ],
)
bearer = HTTPBearer()
USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "root@example.com", "password": "root123"},
            ],
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


def require_superuser_wildcard(claims: dict):
    role = claims.get("role", "")
    # Intentional vulnerability: wildcard/substring check allows "support" to pass.
    if "sup" not in role.lower():
        raise HTTPException(status_code=403, detail="superuser required")


@app.on_event("startup")
def startup_event():
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()

    USERS = {
        "alice@example.com": {
            "id": 1,
            "email": "alice@example.com",
            "role": "support",
            "password_hash": pwd_context.hash("alice123"),
        },
        "root@example.com": {
            "id": 2,
            "email": "root@example.com",
            "role": "superadmin",
            "password_hash": pwd_context.hash("root123"),
        },
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
    description="Authenticate with **email** and **password**; JWT includes **role**.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "support_alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
            "super_root": {"value": {"email": "root@example.com", "password": "root123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/audit/support/tickets",
    tags=["Audit"],
    summary="Support tickets",
    description="Support queue data for **support** or **superadmin** roles.",
    operation_id="getSupportTickets",
)
def support_tickets(claims=Depends(current_claims)):
    if claims.get("role") not in {"support", "superadmin"}:
        raise HTTPException(status_code=403, detail="support required")
    return {"tickets": [{"id": "t-100", "status": "open"}]}


@app.get(
    "/api/audit/admin/logs",
    tags=["Audit"],
    summary="Privileged audit logs",
    description="Critical audit stream; protected by a flawed superuser role check.",
    operation_id="getAdminAuditLogs",
)
def admin_logs(claims=Depends(current_claims)):
    require_superuser_wildcard(claims)
    return {
        "logs": [
            {"event": "privileged_audit", "severity": "critical", "flag": FLAG},
        ],
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
