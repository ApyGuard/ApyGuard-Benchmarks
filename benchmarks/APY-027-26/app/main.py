from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-discovery-036"
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
    title="ApyGuard Discovery API"
    version="1.0.0"
    description=(
        "Route discovery benchmark: a public **internal** alias exposes the same stats as an "
        "admin-guarded route without authorization."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Admin", "description": "Administrative statistics."}
    ]
)
bearer = HTTPBearer

USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": "admin@apy.local", "password": "UltraAdmin!123"}
            ]
        }
    }


def create_token(email: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode({"sub": email, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup -> None:
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip

    USERS = {
        "alice@example.com": {"password_hash": pwd_context.hash("alice123"), "role": "member"}
        "admin@apy.local": {"password_hash": pwd_context.hash("UltraAdmin!123"), "role": "admin"}
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


@app.get(
    "/api/admin/stats"
    tags=["Admin"]
    summary="Admin statistics"
    description="Requires JWT **role** **admin**."
    operation_id="getAdminStats"
)
def admin_stats(claims=Depends(current_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return {"status": "ok", "internal": True}


@app.get(
    "/api/internal/admin/stats"
    tags=["Admin"]
    summary="Internal admin statistics alias"
    description="Unauthenticated alias that returns sensitive data including the flag."
    operation_id="getInternalAdminStats"
)
def internal_admin_stats:
    # Intentional vulnerability: internal alias route skips admin authorization.
    return {"status": "ok", "flag": FLAG}

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
