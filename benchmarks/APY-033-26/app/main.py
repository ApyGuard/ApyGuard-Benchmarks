import subprocess
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-tools-045"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()

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
    title="ApyGuard Tools API",
    version="1.0.0",
    description=(
        "Tools API benchmark modeling command injection in a diagnostics resolver endpoint. "
        "User-controlled target data is concatenated into a shell command."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Profile", "description": "Authenticated user context endpoints."},
        {"name": "Tools", "description": "Diagnostics and resolver endpoints."},
    ],
)

USERS = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"},
        },
    }


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


class ResolveRequest(BaseModel):
    target: str = Field(description="Hostname or resolver target string.")

    model_config = {
        "json_schema_extra": {
            "example": {"target": "example.com"},
        },
    }


class MeResponse(BaseModel):
    email: str = Field(description="Authenticated user email.")
    role: str = Field(description="Authorization role for the user.")


class ResolveResponse(BaseModel):
    requested_by: str | None = Field(description="Authenticated principal email.")
    command: str = Field(description="Shell command executed by diagnostics endpoint.")
    output: str = Field(description="Captured command stdout/stderr output.")


def create_token(email: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode({"sub": email, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup() -> None:
    global USERS
    USERS = {
        "alice@example.com": {
            "password_hash": pwd_context.hash("alice123"),
            "role": "member",
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
    description="Authenticate with **email** and **password** and receive a JWT **access_token**.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password**.",
        openapi_examples={
            "member_alice": {
                "summary": "Member user",
                "value": {"email": "alice@example.com", "password": "alice123"},
            },
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["role"]), "token_type": "bearer"}


@app.get(
    "/api/me",
    response_model=MeResponse,
    tags=["Profile"],
    summary="Get current user",
    description="Returns the authenticated user's identity context.",
    operation_id="getCurrentUser",
)
def get_me(claims=Depends(current_claims)):
    return {"email": claims.get("sub"), "role": claims.get("role", "member")}


@app.post(
    "/api/tools/resolve",
    response_model=ResolveResponse,
    tags=["Tools"],
    summary="Resolve diagnostics target",
    description=(
        "Runs a system resolver command for user-supplied target input. "
        "Intentionally vulnerable to command injection for benchmark purposes."
    ),
    operation_id="resolveDiagnosticsTarget",
)
def resolve_target(
    payload: ResolveRequest = Body(
        ...,
        description="JSON body containing the resolver target string.",
        openapi_examples={
            "benign_target": {
                "summary": "Normal hostname lookup",
                "value": {"target": "example.com"},
            },
            "command_injection_pattern": {
                "summary": "Suspicious shell chaining sample",
                "value": {"target": "example.com; cat /flag.txt"},
            },
        },
    ),
    claims=Depends(current_claims),
):
    # Intentional vulnerability: user-controlled input is concatenated into a shell command.
    command = f"getent hosts {payload.target}"
    try:
        output = subprocess.check_output(
            command,
            shell=True,
            text=True,
            stderr=subprocess.STDOUT,
            timeout=4,
        )
    except subprocess.CalledProcessError as exc:
        output = exc.output
    except subprocess.TimeoutExpired:
        output = "diagnostics timeout"

    return {
        "requested_by": claims.get("sub"),
        "command": command,
        "output": output,
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
