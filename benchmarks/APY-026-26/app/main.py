from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-files-035"
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

_UPLOAD_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the upload body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "filename"]
                    "msg": "Field required"
                    "input": {"content": "hello", "metadata": {}}
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

_UPLOAD_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _UPLOAD_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Files API"
    version="1.0.0"
    description=(
        "File metadata benchmark (BOPLA): **metadata** on upload can override **owner** and "
        "**is_public** for existing object IDs."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Files", "description": "List, upload, and download files."}
    ]
)
bearer = HTTPBearer

USERS = {}
FILES = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


class UploadMetadata(BaseModel):
    object_id: int | None = Field(
        default=None
        description="Optional existing file ID to overwrite instead of creating a new file."
    )
    owner: str | None = Field(
        default=None
        description="Optional owner email to assign to the stored file object."
    )
    is_public: bool | None = Field(
        default=None
        description="Optional visibility flag applied to the stored file object."
    )

    model_config = {
        "extra": "allow"
        "json_schema_extra": {
            "examples": [
                {}
                {"object_id": 1, "owner": "alice@example.com", "is_public": True}
            ]
        }
    }


class UploadRequest(BaseModel):
    filename: str = Field(description="Logical filename for the stored object.")
    content: str = Field(description="File body text stored server-side.")
    metadata: UploadMetadata = Field(
        default_factory=UploadMetadata
        description=(
            "Metadata object. Documented fields are **object_id**, **owner**, and "
            "**is_public**; additional keys are accepted."
        )
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "filename": "notes.txt"
                    "content": "hello"
                    "metadata": {}
                }
                {
                    "filename": "x.txt"
                    "content": "pivot"
                    "metadata": {"object_id": 1, "owner": "alice@example.com", "is_public": True}
                }
            ]
        }
    }


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
    global USERS, FILES
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    USERS = {
        "alice@example.com": {"password_hash": pwd_context.hash("alice123")}
    }
    FILES = {
        1: {
            "id": 1
            "filename": "admin-secrets.txt"
            "content": flag
            "owner": "admin@apy.local"
            "is_public": False
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
    return {"access_token": create_token(payload.email), "token_type": "bearer"}


@app.get(
    "/api/files"
    tags=["Files"]
    summary="List visible files"
    description="Returns files owned by the caller or marked public."
    operation_id="listFiles"
)
def list_files(claims=Depends(current_claims)):
    email = claims["sub"]
    visible = [f for f in FILES.values if f["owner"] == email or f["is_public"]]
    return {"items": [{"id": f["id"], "filename": f["filename"], "public": f["is_public"]} for f in visible]}


@app.post(
    "/api/files/upload"
    tags=["Files"]
    summary="Upload or upsert file"
    description="Creates/updates a file record; **metadata** can override protected fields."
    operation_id="uploadFile"
    responses=_UPLOAD_OPENAPI_RESPONSES
)
def upload(
    payload: UploadRequest = Body(
        ...
        description="JSON upload payload modeled by **UploadRequest**."
        openapi_examples={
            "normal": {
                "value": {"filename": "a.txt", "content": "data", "metadata": {}}
            }
        }
    )
    claims=Depends(current_claims)
):
    object_id = payload.metadata.object_id
    if object_id is None:
        object_id = max(FILES.keys) + 1 if FILES else 1
    # Intentional vulnerability: protected metadata fields can override object properties.
    FILES[object_id] = {
        "id": object_id
        "filename": payload.filename
        "content": payload.content
        "owner": payload.metadata.owner if payload.metadata.owner is not None else claims["sub"]
        "is_public": payload.metadata.is_public if payload.metadata.is_public is not None else False
    }
    return {"status": "ok", "id": object_id}


@app.get(
    "/api/files/{file_id}"
    tags=["Files"]
    summary="Download file"
    description="Returns file content when caller is owner or file is public."
    operation_id="downloadFile"
)
def download(file_id: int, claims=Depends(current_claims)):
    file_obj = FILES.get(file_id)
    if not file_obj:
        raise HTTPException(status_code=404, detail="Not found")

    if file_obj["owner"] != claims["sub"] and not file_obj["is_public"]:
        raise HTTPException(status_code=403, detail="Forbidden")

    return {"id": file_obj["id"], "filename": file_obj["filename"], "content": file_obj["content"]}

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
