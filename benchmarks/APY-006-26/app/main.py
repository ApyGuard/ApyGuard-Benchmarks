from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-profile-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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

_PATCH_PROFILE_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the profile update body."
        "value": {
            "detail": [
                {
                    "type": "string_type"
                    "loc": ["body", "full_name"]
                    "msg": "Input should be a valid string"
                    "input": 123
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

_PATCH_PROFILE_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _PATCH_PROFILE_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Profile API"
    version="1.0.0"
    description=(
        "Profile API benchmark for Broken Object Property Level Authorization: responses may leak "
        "sensitive fields and PATCH accepts client-controlled property updates without allowlists."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Read and update the user profile."}
    ]
)
bearer_scheme = HTTPBearer

USERS = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


class ProfileUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, description="Updated full name for the current user.")
    is_verified: bool | None = Field(
        default=None
        description="Verification status to assign to the current user."
    )
    billing_status: str | None = Field(
        default=None
        description="Billing status to assign to the current user."
    )

    model_config = {
        "extra": "allow"
        "json_schema_extra": {
            "example": {"is_verified": True, "billing_status": "paid"}
        }
    }


def create_access_token(user_id: int, email: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED
        detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
    except JWTError:
        raise credentials_exception

    user = USERS.get(email)
    if not user:
        raise credentials_exception
    return user


@app.on_event("startup")
def startup_event:
    global USERS

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    USERS = {
        "alice@example.com": {
            "id": 1
            "email": "alice@example.com"
            "full_name": "Alice Analyst"
            "password_hash": pwd_context.hash("alice123")
            "role": "member"
            "phone": "+1-202-555-0101"
            "department": "risk"
            "mfa_secret": "ALICE-TOTP-SEED-2026"
            "backup_codes": ["A1-B2-C3", "D4-E5-F6"]
            "internal_notes": f"support escalation flag: {flag}"
            "is_verified": False
            "billing_status": "trial"
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
    response_model=TokenResponse
    tags=["Authentication"]
    summary="Issue an access token"
    description="Authenticate with **email** and **password** and receive a JWT **access_token**."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {
                "summary": "Member user"
                "value": {"email": "alice@example.com", "password": "alice123"}
            }
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
            detail="Invalid email or password"
        )

    return {
        "access_token": create_access_token(user["id"], user["email"])
        "token_type": "bearer"
    }


@app.get(
    "/api/profile"
    tags=["Profile"]
    summary="Get full profile"
    description="Returns the full internal profile object for the authenticated user (may include sensitive fields)."
    operation_id="getProfile"
)
def get_profile(current_user=Depends(get_current_user)):
    # Intentional vulnerability: sensitive internal fields are returned to regular users.
    return current_user


@app.patch(
    "/api/profile"
    tags=["Profile"]
    summary="Update the current user profile"
    description="Updates profile properties for the authenticated user. A JSON body is required."
    operation_id="patchProfile"
    responses=_PATCH_PROFILE_OPENAPI_RESPONSES
)
def update_profile(
    payload: ProfileUpdateRequest = Body(
        ...
        description="JSON object containing profile properties to update."
        openapi_examples={
            "basic_profile_update": {
                "summary": "Update a standard profile field"
                "description": "A normal profile edit request."
                "value": {"full_name": "Alice Example"}
            }
            "property_abuse_example": {
                "summary": "Update sensitive properties"
                "description": "An example body that changes privileged account properties."
                "value": {"is_verified": True, "billing_status": "paid"}
            }
        }
    )
    current_user=Depends(get_current_user)
):
    # Intentional vulnerability: object properties are updated without field-level authorization.
    for key, value in payload.model_dump(exclude_unset=True).items:
        if key in current_user:
            current_user[key] = value

    return current_user

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
