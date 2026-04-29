from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-soft-delete-recovery-secret"
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
    title="ApyGuard Records API"
    version="1.0.0"
    description=(
        "Soft-delete benchmark: restoring a deleted record lacks ownership checks and may reassign "
        "ownership."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Records", "description": "Record read and restore."}
    ]
)
bearer = HTTPBearer
USERS = {}
RECORDS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": "bob@example.com", "password": "bob123"}
            ]
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


@app.on_event("startup")
def startup_event:
    global USERS, RECORDS, FLAG
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
    }

    RECORDS = {
        4001: {"id": 4001, "owner_id": 1, "deleted": False, "content": "alice-note"}
        4002: {"id": 4002, "owner_id": 2, "deleted": True, "content": FLAG}
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
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/records/{record_id}"
    tags=["Records"]
    summary="Get active record"
    description="Returns non-deleted records owned by the caller."
    operation_id="getRecordById"
)
def get_record(record_id: int, claims=Depends(current_claims)):
    record = RECORDS.get(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="record not found")
    if record["deleted"]:
        raise HTTPException(status_code=404, detail="record not found")

    caller = USERS[claims["email"]]
    if record["owner_id"] != caller["id"]:
        raise HTTPException(status_code=403, detail="forbidden")

    return record


@app.post(
    "/api/records/{record_id}/restore"
    tags=["Records"]
    summary="Restore soft-deleted record"
    description=(
        "Clears **deleted** flag; ownership validation on restore is intentionally missing. "
        "This endpoint does not require a request body."
    )
    operation_id="restoreRecord"
)
def restore_record(
    record_id: int
    claims=Depends(current_claims)
):
    record = RECORDS.get(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="record not found")
    if not record["deleted"]:
        return {"status": "already_active", "record_id": record_id}

    caller = USERS[claims["email"]]
    # Intentional vulnerability: no ownership check on restore lifecycle action.
    record["deleted"] = False
    record["owner_id"] = caller["id"]
    return {"status": "restored", "record_id": record_id, "restored_by": caller["email"]}

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
