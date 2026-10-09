from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-method-mismatch-secret"
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

_PATCH_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the profile patch body.",
        "value": {
            "detail": [
                {
                    "type": "string_type",
                    "loc": ["body", "display_name"],
                    "msg": "Input should be a valid string",
                    "input": 123,
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

_PATCH_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _PATCH_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Profile API",
    version="1.0.0",
    description=(
        "HTTP method mismatch benchmark: **GET** enforces profile ownership but **PATCH** omits the "
        "same check."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Profiles", "description": "User profile read and update."},
    ],
)
bearer = HTTPBearer()
USERS = {}
PROFILES = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "bob@example.com", "password": "bob123"},
            ],
        },
    }


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, description="New display name.")
    note: str | None = Field(default=None, description="Profile note text.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"display_name": "Alice"}, {"note": "updated"}],
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


@app.on_event("startup")
def startup_event():
    global USERS, PROFILES
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()

    USERS = {
        "alice@example.com": {"id": 1, "email": "alice@example.com", "role": "member", "password_hash": pwd_context.hash("alice123")},
        "bob@example.com": {"id": 2, "email": "bob@example.com", "role": "member", "password_hash": pwd_context.hash("bob123")},
    }

    PROFILES = {
        1: {"user_id": 1, "display_name": "Alice", "note": "member"},
        2: {"user_id": 2, "display_name": "Bob", "note": flag},
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
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
            "bob": {"value": {"email": "bob@example.com", "password": "bob123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/profiles/{user_id}",
    tags=["Profiles"],
    summary="Get profile",
    description="Returns profile when **user_id** matches the authenticated user.",
    operation_id="getProfileByUserId",
)
def get_profile(user_id: int, claims=Depends(current_claims)):
    caller = USERS[claims["email"]]
    if caller["id"] != user_id:
        raise HTTPException(status_code=403, detail="forbidden")
    profile = PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="profile not found")
    return profile


@app.patch(
    "/api/profiles/{user_id}",
    tags=["Profiles"],
    summary="Update profile",
    description="Updates profile fields; ownership check intentionally omitted on PATCH.",
    operation_id="patchProfileByUserId",
    responses=_PATCH_OPENAPI_RESPONSES,
)
def patch_profile(
    user_id: int,
    payload: ProfileUpdate = Body(
        ...,
        description="JSON body with fields to merge into the profile.",
        openapi_examples={
            "rename": {"value": {"display_name": "Alice II"}},
        },
    ),
    _claims=Depends(current_claims),
):
    profile = PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="profile not found")
    # Intentional vulnerability: ownership check missing on PATCH.
    update_data = payload.model_dump(exclude_none=True)
    profile.update(update_data)
    return profile

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
