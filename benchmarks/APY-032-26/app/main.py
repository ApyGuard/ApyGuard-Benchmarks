import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-ledger-044"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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
    title="ApyGuard Ledger API"
    version="1.0.0"
    description=(
        "Ledger API benchmark modeling SQL injection in a field-projection export endpoint. "
        "The export path interpolates user-controlled fields directly into SQL."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Authenticated user context endpoints."}
        {"name": "Ledger", "description": "Ledger list and export endpoints."}
    ]
)
bearer_scheme = HTTPBearer

USERS = {}
DB_PATH = "ledger.db"


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


class MeResponse(BaseModel):
    id: str = Field(description="Authenticated user identifier from JWT subject.")
    email: str = Field(description="Authenticated user email.")
    role: str = Field(description="Application role for the current user.")


class LedgerEntryResponse(BaseModel):
    id: int = Field(description="Ledger row identifier.")
    description: str = Field(description="Ledger entry description.")
    amount: int = Field(description="Ledger entry amount.")
    created_at: str = Field(description="Entry creation date string.")


class ExportMetaResponse(BaseModel):
    allowed_example: str = Field(description="Example of expected projection format.")
    note: str = Field(description="Diagnostic note returned by the endpoint.")


class ExportResponse(BaseModel):
    meta: ExportMetaResponse = Field(description="Export metadata and hints.")
    items: list[dict[str, object]] = Field(
        description="Query result rows; shape depends on user-controlled projection."
    )


def get_connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_access_token(user_id: int, email: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED
        detail="Could not validate credentials"
    )
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception


def init_db:
    connection = get_connection
    cursor = connection.cursor
    cursor.execute("DROP TABLE IF EXISTS ledger")
    cursor.execute("DROP TABLE IF EXISTS secrets")
    cursor.execute(
        """
        CREATE TABLE ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT
            owner_email TEXT NOT NULL
            description TEXT NOT NULL
            amount INTEGER NOT NULL
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT
            flag TEXT NOT NULL
        )
        """
    )

    cursor.executemany(
        "INSERT INTO ledger(owner_email, description, amount, created_at) VALUES(?, ?, ?, ?)"
        [
            ("alice@example.com", "monthly-subscription", 49, "2026-03-01")
            ("alice@example.com", "api-credit-topup", 120, "2026-03-12")
            ("bob@example.com", "internal-adjustment", 250, "2026-03-20")
        ]
    )

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip
    cursor.execute("INSERT INTO secrets(flag) VALUES(?)", (flag,))
    connection.commit
    connection.close


@app.on_event("startup")
def startup_event:
    global USERS
    USERS = {
        "alice@example.com": {
            "id": 1
            "email": "alice@example.com"
            "password_hash": pwd_context.hash("alice123")
        }
    }
    init_db


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
    response_model=TokenResponse
    tags=["Authentication"]
    summary="Issue an access token"
    description="Authenticate with **email** and **password** and receive a JWT **access_token**."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password**."
        openapi_examples={
            "analyst_alice": {
                "summary": "Analyst user"
                "value": {"email": "alice@example.com", "password": "alice123"}
            }
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
            detail="Invalid email or password"
        )
    return {
        "access_token": create_access_token(user["id"], user["email"])
        "token_type": "bearer"
    }


@app.get(
    "/api/me"
    response_model=MeResponse
    tags=["Profile"]
    summary="Get current user"
    description="Returns the authenticated user's identity context."
    operation_id="getCurrentUser"
)
def get_me(claims=Depends(get_current_claims)):
    return {"id": claims["sub"], "email": claims["email"], "role": "analyst"}


@app.get(
    "/api/ledger"
    response_model=list[LedgerEntryResponse]
    tags=["Ledger"]
    summary="List ledger entries"
    description="Lists ledger rows for the authenticated owner."
    operation_id="listLedgerEntries"
)
def list_ledger(claims=Depends(get_current_claims)):
    email = claims["email"]
    connection = get_connection
    rows = connection.execute(
        "SELECT id, description, amount, created_at FROM ledger WHERE owner_email = ? ORDER BY id"
        (email,)
    ).fetchall
    connection.close
    return [dict(row) for row in rows]


@app.get(
    "/api/ledger/export"
    response_model=ExportResponse
    tags=["Ledger"]
    summary="Export ledger entries"
    description=(
        "Exports ledger rows with user-selected projection fields. "
        "Intentionally vulnerable to SQL injection for benchmark purposes."
    )
    operation_id="exportLedgerEntries"
)
def export_ledger(
    fields: str = Query(
        "id,description,amount,created_at"
        description="Comma-separated SQL projection string used directly in query construction."
    )
    claims=Depends(get_current_claims)
):
    email = claims["email"]
    hint = {
        "allowed_example": "id,description,amount,created_at"
        "note": "field selection is forwarded to SQL projection"
    }

    connection = get_connection
    query = f"SELECT {fields} FROM ledger WHERE owner_email = '{email}' ORDER BY id"

    try:
        rows = connection.execute(query).fetchall
    except sqlite3.Error as exc:
        connection.close
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST
            detail={"error": str(exc), "hint": hint}
        )

    connection.close
    return {
        "meta": hint
        "items": [dict(row) for row in rows]
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
