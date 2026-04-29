from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-scope-confusion-secret"
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
    title="ApyGuard Scoped Billing API"
    version="1.0.0"
    description=(
        "OAuth-style scope confusion benchmark: scope checks use a loose **read:** prefix, "
        "allowing broader access than intended."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Profile-scoped endpoints."}
        {"name": "Billing", "description": "Billing and ledger data."}
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
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


def create_token(user: dict):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {
        "sub": str(user["id"])
        "email": user["email"]
        "role": user["role"]
        "scope": user["scope"]
        "exp": exp
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def require_scope_loosely(claims: dict, required_scope: str):
    # Intentional vulnerability: loose prefix check instead of exact required scope.
    token_scope = claims.get("scope", "")
    if not token_scope.startswith("read:"):
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
            "scope": "read:profile"
            "password_hash": pwd_context.hash("alice123")
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
    description="JWT includes a **scope** string used for coarse authorization checks."
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
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/profile/me"
    tags=["Profile"]
    summary="Current profile"
    description="Requires a token whose **scope** passes the loose prefix check for profile access."
    operation_id="getProfileMe"
)
def profile_me(claims=Depends(current_claims)):
    require_scope_loosely(claims, "read:profile")
    return {"email": claims["email"], "scope": claims.get("scope")}


@app.get(
    "/api/billing/ledger"
    tags=["Billing"]
    summary="Billing ledger"
    description="Sensitive ledger; scope validation is intentionally weaker than exact match."
    operation_id="getBillingLedger"
)
def billing_ledger(claims=Depends(current_claims)):
    require_scope_loosely(claims, "read:billing")
    return {"ledger": "sensitive", "flag": FLAG}

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
