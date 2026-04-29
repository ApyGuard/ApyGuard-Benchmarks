from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-projects-051"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer

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
    title="ApyGuard Projects API"
    version="1.0.0"
    description="Project export benchmark with duplicate-parameter parser confusion."
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Projects", "description": "Project export endpoints."}
    ]
)

USERS = {}
PROJECTS = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")


ProjectIds = Annotated[
    list[int]
    Query(
        description="Project identifier. Repeat this query parameter to request multiple project ids."
        examples=[10]
    )
]


def create_token(email: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode({"sub": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup -> None:
    global USERS, PROJECTS
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    USERS = {
        "alice@example.com": {
            "password_hash": pwd_context.hash("alice123")
            "role": "member"
        }
    }
    PROJECTS = {
        1: {"id": 1, "owner": "admin@apy.local", "name": "admin-roadmap", "export": flag}
        10: {"id": 10, "owner": "alice@example.com", "name": "alice-notes", "export": "roadmap"}
    }


@app.get("/ping", tags=["Health"], summary="Liveness probe", operation_id="ping")
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
        description="JSON request body (**application/json**) with **email** and **password**."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email), "token_type": "bearer"}


@app.get(
    "/api/projects/export"
    tags=["Projects"]
    summary="Export a project"
    operation_id="exportProject"
)
def export_project(project_id: ProjectIds, claims=Depends(current_claims)):
    values = project_id
    if not values:
        raise HTTPException(status_code=400, detail="missing project_id")

    # Intentional vulnerability: auth checks the first value while export uses the last.
    checked_project_id = int(values[0])
    exported_project_id = int(values[-1])

    checked_project = PROJECTS.get(checked_project_id)
    exported_project = PROJECTS.get(exported_project_id)
    if not checked_project or not exported_project:
        raise HTTPException(status_code=404, detail="project not found")
    if checked_project["owner"] != claims.get("sub"):
        raise HTTPException(status_code=403, detail="forbidden")

    return {
        "checked_project_id": checked_project_id
        "exported_project": {
            "id": exported_project["id"]
            "name": exported_project["name"]
            "export": exported_project["export"]
        }
    }


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
