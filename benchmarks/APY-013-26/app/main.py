from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-file-secret"
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
    title="ApyGuard File API"
    version="1.0.0"
    description=(
        "File handling benchmark: uploads write to disk with client-controlled filenames; download "
        "joins a user path without traversal sanitization."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Files", "description": "Multipart upload and download."}
    ]
)
bearer_scheme = HTTPBearer
USERS = {}
UPLOAD_DIR = Path("uploads")


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


def create_token(email: str, user_id: int):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": str(user_id), "email": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event:
    global USERS
    USERS = {
        "alice@example.com": {"id": 1, "password_hash": pwd_context.hash("alice123")}
    }
    UPLOAD_DIR.mkdir(exist_ok=True)


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
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["id"]), "token_type": "bearer"}


@app.post(
    "/api/files/upload"
    tags=["Files"]
    summary="Upload a file"
    description=(
        "Multipart upload of a single file; contents are written under **uploads/** using the "
        "original **filename** from the part."
    )
    operation_id="uploadFile"
)
async def upload_file(
    file: UploadFile = File(
        ...
        description="File part to store on disk (filename influences storage path)."
    )
    _claims=Depends(current_claims)
):
    target = UPLOAD_DIR / file.filename
    content = await file.read
    target.write_bytes(content)
    return {"uploaded": file.filename, "size": len(content)}


@app.get(
    "/api/files/download"
    tags=["Files"]
    summary="Download file by path"
    description=(
        "Reads a file under the uploads directory using query **path** joined without traversal "
        "sanitization (intentionally vulnerable)."
    )
    operation_id="downloadFile"
)
def download_file(
    path: str = Query(
        ...
        description="Relative path segment joined with the uploads directory (may traverse with `..` segments)."
        examples=["notes.txt", "../etc/passwd"]
    )
    _claims=Depends(current_claims)
):
    # Intentional vulnerability: path traversal via unsanitized join.
    target = Path("uploads") / path
    if not target.exists:
        raise HTTPException(status_code=404, detail="file not found")
    return {"path": str(target), "content": target.read_text(encoding="utf-8", errors="ignore")}

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
