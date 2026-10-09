import json
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-nosql-037"
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
    title="ApyGuard Search API",
    version="1.0.0",
    description=(
        "Search benchmark: **filter** JSON may include NoSQL-style operator objects for **owner** matching."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Search", "description": "Document search with JSON filter."},
    ],
)
bearer = HTTPBearer()

USERS = {}
RECORDS = []


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"},
        },
    }


def create_token(email: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode({"sub": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def match_owner(record: dict, owner_filter):
    if isinstance(owner_filter, dict):
        if "$ne" in owner_filter:
            return record["owner"] != owner_filter["$ne"]
        if "$eq" in owner_filter:
            return record["owner"] == owner_filter["$eq"]
        return False
    return record["owner"] == owner_filter


@app.on_event("startup")
def startup() -> None:
    global USERS, RECORDS
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()

    USERS = {
        "alice@example.com": {"password_hash": pwd_context.hash("alice123")},
    }
    RECORDS = [
        {"id": 1, "owner": "alice@example.com", "body": "normal document"},
        {"id": 2, "owner": "admin@apy.local", "body": flag},
    ]


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
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email), "token_type": "bearer"}


@app.get(
    "/api/search",
    tags=["Search"],
    summary="Search records",
    description="JSON string **filter** with **owner** key; operators like **$ne** are accepted.",
    operation_id="searchRecords",
)
def search(
    filter: str = Query(
        default='{"owner":"alice@example.com"}',
        description='JSON object string, e.g. `{"owner":"alice@example.com"}` or `{"owner":{"$ne":""}}`.',
    ),
    claims=Depends(current_claims),
):
    try:
        parsed = json.loads(filter)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid filter JSON") from exc

    owner_filter = parsed.get("owner", claims["sub"])
    # Intentional vulnerability: operator objects are accepted without allowlisting.
    matches = [record for record in RECORDS if match_owner(record, owner_filter)]
    return {"items": matches}

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
