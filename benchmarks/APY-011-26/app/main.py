from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-legacy-secret"
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
    title="ApyGuard Legacy Admin API",
    version="1.0.0",
    description=(
        "Legacy API benchmark: an older admin reports route omits role checks while the v2 route "
        "enforces **admin**."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Admin", "description": "Administrative report exports."},
    ],
)
bearer_scheme = HTTPBearer()
USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "admin@apy.local", "password": "AdminLegacy!"},
            ],
        },
    }


def create_token(user_id: int, email: str, role: str):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": str(user_id), "email": email, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event():
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()
    USERS = {
        "alice@example.com": {"id": 1, "role": "support", "password_hash": pwd_context.hash("alice123")},
        "admin@apy.local": {"id": 2, "role": "admin", "password_hash": pwd_context.hash("AdminLegacy!")},
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
    description="Authenticate with **email** and **password**; JWT includes **role** claims.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "support": {"value": {"email": "alice@example.com", "password": "alice123"}},
            "admin": {"value": {"email": "admin@apy.local", "password": "AdminLegacy!"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    return {"access_token": create_token(user["id"], payload.email, user["role"]), "token_type": "bearer"}


@app.get(
    "/api/v2/admin/reports",
    tags=["Admin"],
    summary="Admin reports (v2)",
    description="Restricted export; requires **admin** role in the JWT.",
    operation_id="getAdminReportsV2",
)
def admin_reports_v2(claims=Depends(current_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return {"version": "v2", "status": "restricted"}


@app.get(
    "/api/v1/admin/reports",
    tags=["Admin"],
    summary="Admin reports (v1 legacy)",
    description="Legacy export path; authentication is required but role checks are intentionally weak.",
    operation_id="getAdminReportsV1",
)
def admin_reports_v1(claims=Depends(current_claims)):
    # Intentional vulnerability: legacy endpoint checks auth but not role.
    return {
        "version": "v1",
        "export": "legacy full export",
        "flag": FLAG,
        "requested_by": claims.get("email"),
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
