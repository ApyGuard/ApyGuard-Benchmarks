from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-ownership-transfer-secret"
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

_TRANSFER_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the transfer body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "new_owner_email"]
                    "msg": "Field required"
                    "input": {}
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

_TRANSFER_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _TRANSFER_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Projects API"
    version="1.0.0"
    description=(
        "Project ownership benchmark: transfer changes **owner_id** without verifying the caller "
        "is the current owner."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Projects", "description": "Project read and ownership transfer."}
    ]
)
bearer = HTTPBearer
USERS = {}
PROJECTS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": "bob@example.com", "password": "bob123"}
                {"email": "admin@example.com", "password": "admin123"}
            ]
        }
    }


class TransferRequest(BaseModel):
    new_owner_email: str = Field(description="Email of the user who should become the new owner.")

    model_config = {
        "json_schema_extra": {
            "example": {"new_owner_email": "alice@example.com"}
        }
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


def resolve_user(email: str):
    user = USERS.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@app.on_event("startup")
def startup_event:
    global USERS, PROJECTS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip

    USERS = {
        "alice@example.com": {
            "id": 1
            "email": "alice@example.com"
            "role": "member"
            "password_hash": pwd_context.hash("alice123")
        }
        "bob@example.com": {
            "id": 2
            "email": "bob@example.com"
            "role": "member"
            "password_hash": pwd_context.hash("bob123")
        }
        "admin@example.com": {
            "id": 3
            "email": "admin@example.com"
            "role": "admin"
            "password_hash": pwd_context.hash("admin123")
        }
    }

    PROJECTS = {
        1001: {
            "id": 1001
            "name": "finance-migration"
            "owner_id": 2
            "summary": "restricted"
            "secret": FLAG
        }
        1002: {
            "id": 1002
            "name": "support-dashboard"
            "owner_id": 1
            "summary": "owned-by-alice"
            "secret": "none"
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
    description="Authenticate with **email** and **password** and receive a JWT **access_token**."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
            "bob": {"value": {"email": "bob@example.com", "password": "bob123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/projects/{project_id}"
    tags=["Projects"]
    summary="Get project"
    description="Returns project details for owners or **admin**."
    operation_id="getProjectById"
)
def get_project(project_id: int, claims=Depends(current_claims)):
    project = PROJECTS.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="project not found")

    caller = USERS[claims["email"]]
    if project["owner_id"] != caller["id"] and caller["role"] != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    return project


@app.post(
    "/api/projects/{project_id}/transfer"
    tags=["Projects"]
    summary="Transfer project ownership"
    description="Assigns a new owner by email without verifying the caller is the current owner."
    operation_id="transferProject"
    responses=_TRANSFER_OPENAPI_RESPONSES
)
def transfer_project(
    project_id: int
    payload: TransferRequest = Body(
        ...
        description="JSON body with **new_owner_email**."
        openapi_examples={
            "to_alice": {"value": {"new_owner_email": "alice@example.com"}}
        }
    )
    _claims=Depends(current_claims)
):
    project = PROJECTS.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="project not found")

    new_owner = resolve_user(payload.new_owner_email)
    # Intentional vulnerability: no check that caller is current owner/admin.
    project["owner_id"] = new_owner["id"]
    return {"status": "transferred", "project_id": project_id, "new_owner_email": new_owner["email"]}

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
