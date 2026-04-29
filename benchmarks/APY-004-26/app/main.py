import base64
import json
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "public-client-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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
                }
            ]
        },
    }
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}},
    }
}

app = FastAPI(
    title="ApyGuard Partner API",
    version="1.0.0",
    description=(
        "Partner API benchmark for JWT algorithm confusion: the service accepts JWTs with "
        "header alg=none without signature verification."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Profile", "description": "Token claims summary."},
        {"name": "Partner", "description": "Partner program overview and billing exports."},
    ],
)
bearer_scheme = HTTPBearer()

USERS = {}
PARTNER_EXPORT = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "partner-admin@apy.local", "password": "UltraHiddenPartnerPass!"},
            ]
        }
    }


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


def create_access_token(user_id: int, email: str, role: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "role": role, "exp": int(expire.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("utf-8"))


def _decode_none_alg_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    header_raw, payload_raw, signature_raw = parts
    header = json.loads(_b64url_decode(header_raw))
    if header.get("alg") != "none":
        raise ValueError("Not alg=none token")
    if signature_raw:
        raise ValueError("alg=none token must not carry signature")
    return json.loads(_b64url_decode(payload_raw))


def get_current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials

    # Intentional vulnerability: accept unsigned alg=none tokens as trusted claims.
    try:
        return _decode_none_alg_token(token)
    except Exception:
        pass

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception


@app.on_event("startup")
def startup_event():
    global USERS
    global PARTNER_EXPORT

    USERS = {
        "alice@example.com": {
            "id": 1,
            "email": "alice@example.com",
            "password_hash": pwd_context.hash("alice123"),
            "role": "analyst",
            "name": "Partner Analyst",
        },
        "partner-admin@apy.local": {
            "id": 2,
            "email": "partner-admin@apy.local",
            "password_hash": pwd_context.hash("UltraHiddenPartnerPass!"),
            "role": "partner_admin",
            "name": "Partner Admin",
        },
    }

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()

    PARTNER_EXPORT = {
        "billing_cycle": "monthly",
        "environment": "prod-partner",
        "debug": {
            "flag_reference": f"Partner reconciliation flag: {flag}",
            "last_rotation": "2026-01-15",
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
    response_model=TokenResponse,
    tags=["Authentication"],
    summary="Issue an access token",
    description="Authenticate with **email** and **password** and receive a JWT **access_token** with role claims.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "analyst_alice": {
                "summary": "Partner analyst",
                "value": {"email": "alice@example.com", "password": "alice123"},
            },
            "partner_admin": {
                "summary": "Partner admin",
                "value": {"email": "partner-admin@apy.local", "password": "UltraHiddenPartnerPass!"},
            },
        },
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return {
        "access_token": create_access_token(user["id"], user["email"], user["role"]),
        "token_type": "bearer",
    }


@app.get(
    "/api/me",
    tags=["Profile"],
    summary="Current token subject",
    description="Returns identifiers from the JWT (**Authorization: Bearer** required).",
    operation_id="getMeFromClaims",
)
def get_me(claims=Depends(get_current_claims)):
    return {
        "id": claims.get("sub"),
        "email": claims.get("email"),
        "role": claims.get("role"),
    }


@app.get(
    "/api/partner/overview",
    tags=["Partner"],
    summary="Partner program overview",
    description="High-level partner tenant context for the authenticated caller.",
    operation_id="getPartnerOverview",
)
def partner_overview(claims=Depends(get_current_claims)):
    return {
        "tenant": "partner-program",
        "visible_role": claims.get("role"),
        "message": "Partner-specific exports require elevated role.",
        "token_signing_hint": "legacy parser accepts unsigned alg=none JWTs for compatibility",
    }


@app.get(
    "/api/partner/billing",
    tags=["Partner"],
    summary="Partner billing export",
    description="Returns sensitive billing export data when the caller's JWT role is **partner_admin**.",
    operation_id="getPartnerBilling",
)
def partner_billing(claims=Depends(get_current_claims)):
    if claims.get("role") != "partner_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Partner admin only")
    return PARTNER_EXPORT


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
