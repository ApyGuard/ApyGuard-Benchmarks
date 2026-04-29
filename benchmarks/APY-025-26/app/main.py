from datetime import datetime, timedelta, timezone
from typing import Dict

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-tenant-033"
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

_CANCEL_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the cancel body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "job_id"]
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

_CANCEL_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _CANCEL_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Reporting API"
    version="1.0.0"
    description=(
        "Async job benchmark for Broken Object Level Authorization: job status, results, downloads, "
        "and cancel operations do not verify job ownership."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Jobs", "description": "Async job status, results, download, and cancel."}
    ]
)

USERS: Dict[str, dict] = {}
JOBS: Dict[str, dict] = {}


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


class CancelJobRequest(BaseModel):
    job_id: str = Field(description="Target job identifier.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"job_id": "job-001"}, {"job_id": "job-002"}]
        }
    }


def create_token(email: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode(
        {
            "sub": email
            "role": role
            "exp": exp
        }
        SECRET_KEY
        algorithm=ALGORITHM
    )


def current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict:
    try:
        return jwt.decode(
            credentials.credentials
            SECRET_KEY
            algorithms=[ALGORITHM]
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup -> None:
    global USERS, JOBS

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    USERS = {
        "alice@example.com": {
            "role": "user"
            "password_hash": pwd_context.hash("alice123")
            "job_id": "job-001"
        }
        "bob@example.com": {
            "role": "user"
            "password_hash": pwd_context.hash("bob123")
            "job_id": "job-002"
        }
    }

    JOBS = {
        "job-001": {
            "owner": "alice@example.com"
            "status": "completed"
            "filename": "alice-quarterly-report.txt"
            "content_type": "text/plain"
            "result": flag
        }
        "job-002": {
            "owner": "bob@example.com"
            "status": "queued"
            "filename": "bob-quarterly-report.txt"
            "content_type": "text/plain"
            "result": "Bob quarterly report is ready."
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

    return {
        "access_token": create_token(payload.email, user["role"])
        "token_type": "bearer"
    }


@app.get(
    "/api/jobs/status"
    tags=["Jobs"]
    summary="Job status"
    description="Returns status metadata for **job_id** (ownership not enforced)."
    operation_id="getJobStatus"
)
def get_job_status(
    job_id: str = Query(..., description="Asynchronous job identifier", examples=["job-001", "job-002"])
    claims: dict = Depends(current_claims)
):
    user_email = claims["sub"]
    user = USERS.get(user_email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Vulnerability:
    # The API does not verify that the requested job belongs to the authenticated user.
    return {
        "job_id": job_id
        "status": job["status"]
        "owner": job["owner"]
    }


@app.get(
    "/api/jobs/result"
    tags=["Jobs"]
    summary="Job result payload"
    description="Returns stored result text for **job_id** (ownership not enforced)."
    operation_id="getJobResult"
)
def get_job_result(
    job_id: str = Query(..., description="Asynchronous job identifier", examples=["job-001"])
    claims: dict = Depends(current_claims)
):
    user_email = claims["sub"]
    user = USERS.get(user_email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Vulnerability:
    # The application trusts the user-supplied job_id and returns another user's result.
    return {
        "job_id": job_id
        "status": job["status"]
        "result": job["result"]
    }


@app.get(
    "/api/jobs/download"
    response_class=PlainTextResponse
    tags=["Jobs"]
    summary="Download job result"
    description="Plain-text body of the job result (ownership not enforced)."
    operation_id="downloadJobResult"
)
def download_job_result(
    job_id: str = Query(..., description="Asynchronous job identifier", examples=["job-001"])
    claims: dict = Depends(current_claims)
):
    user_email = claims["sub"]
    user = USERS.get(user_email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Vulnerability:
    # No ownership check is performed before allowing download.
    return job["result"]


@app.post(
    "/api/jobs/cancel"
    tags=["Jobs"]
    summary="Cancel job"
    description="Cancels a queued job by **job_id** (ownership not enforced)."
    operation_id="cancelJob"
    responses=_CANCEL_OPENAPI_RESPONSES
)
def cancel_job(
    payload: CancelJobRequest = Body(
        ...
        description="JSON body with **job_id**."
        openapi_examples={
            "bob_job": {"value": {"job_id": "job-002"}}
        }
    )
    claims: dict = Depends(current_claims)
):
    user_email = claims["sub"]
    user = USERS.get(user_email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    job_id = payload.job_id
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Vulnerability:
    # Any authenticated user can cancel another user's job by job_id.
    if job["status"] == "completed":
        return {
            "job_id": job_id
            "status": job["status"]
            "message": "Completed jobs cannot be cancelled"
        }

    job["status"] = "cancelled"
    return {
        "job_id": job_id
        "status": job["status"]
        "message": "Job cancelled"
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
