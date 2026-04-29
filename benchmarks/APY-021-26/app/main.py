from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-delegation-scope-secret"
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

_DELEGATE_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the delegation body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "scopes"]
                    "msg": "Field required"
                    "input": {"minutes": 30}
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

_DELEGATE_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _DELEGATE_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard API Key Service"
    version="1.0.0"
    description=(
        "Token delegation benchmark: delegated tokens may request scopes not constrained to the "
        "caller's existing scopes."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Profile endpoints."}
        {"name": "Keys", "description": "API key delegation."}
        {"name": "Billing", "description": "Billing ledger."}
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
                {"email": "admin@example.com", "password": "admin123"}
            ]
        }
    }


class DelegateRequest(BaseModel):
    scopes: list[str] = Field(description="Scopes to embed in the delegated JWT.")
    minutes: int = Field(default=30, description="Delegation lifetime in minutes.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"scopes": ["read:billing"], "minutes": 30}
                {"scopes": ["read:profile"], "minutes": 5}
            ]
        }
    }


def create_token(user: dict, scopes: list[str]):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {
        "sub": str(user["id"])
        "email": user["email"]
        "role": user["role"]
        "scopes": scopes
        "exp": exp
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_delegated_token(claims: dict, scopes: list[str], minutes: int):
    exp = datetime.now(timezone.utc) + timedelta(minutes=max(1, minutes))
    payload = {
        "sub": claims["sub"]
        "email": claims["email"]
        "role": claims["role"]
        "scopes": scopes
        "delegated": True
        "exp": exp
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def require_scope(claims: dict, required_scope: str):
    scopes = claims.get("scopes", [])
    if required_scope not in scopes:
        raise HTTPException(status_code=403, detail=f"missing scope {required_scope}")


@app.on_event("startup")
def startup_event:
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip

    USERS = {
        "alice@example.com": {
            "id": 1
            "email": "alice@example.com"
            "role": "member"
            "scopes": ["read:profile"]
            "password_hash": pwd_context.hash("alice123")
        }
        "admin@example.com": {
            "id": 2
            "email": "admin@example.com"
            "role": "admin"
            "scopes": ["read:profile", "read:billing", "admin:keys"]
            "password_hash": pwd_context.hash("admin123")
        }
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
    description="JWT includes **scopes** derived from the user record."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
            "admin": {"value": {"email": "admin@example.com", "password": "admin123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user, user["scopes"]), "token_type": "bearer"}


@app.get(
    "/api/profile/me"
    tags=["Profile"]
    summary="Current profile"
    description="Requires **read:profile** scope."
    operation_id="getProfileMe"
)
def profile_me(claims=Depends(current_claims)):
    require_scope(claims, "read:profile")
    return {"email": claims["email"], "role": claims["role"], "scopes": claims.get("scopes", [])}


@app.post(
    "/api/keys/delegate"
    tags=["Keys"]
    summary="Delegate access token"
    description="Mints a short-lived delegated JWT with requested **scopes** (not constrained to caller scopes)."
    operation_id="delegateApiKey"
    responses=_DELEGATE_OPENAPI_RESPONSES
)
def delegate_key(
    payload: DelegateRequest = Body(
        ...
        description="Delegation parameters."
        openapi_examples={
            "escalate_billing": {"value": {"scopes": ["read:billing"], "minutes": 30}}
        }
    )
    claims=Depends(current_claims)
):
    require_scope(claims, "read:profile")
    requested_scopes = payload.scopes
    if not requested_scopes:
        raise HTTPException(status_code=400, detail="scopes required")

    # Intentional vulnerability: requested delegated scopes are not constrained
    # to a subset of caller scopes.
    token = create_delegated_token(claims, requested_scopes, payload.minutes)
    return {"access_token": token, "token_type": "bearer", "scopes": requested_scopes}


@app.get(
    "/api/billing/ledger"
    tags=["Billing"]
    summary="Billing ledger"
    description="Requires **read:billing** scope."
    operation_id="getBillingLedger"
)
def billing_ledger(claims=Depends(current_claims)):
    require_scope(claims, "read:billing")
    return {"ledger": "privileged", "flag": FLAG}

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
