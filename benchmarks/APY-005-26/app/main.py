import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-reports-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
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
    title="ApyGuard Reports API",
    version="1.0.0",
    description=(
        "Reports API benchmark for SQL injection: search forwards user input into a SQL **LIKE** "
        "fragment without parameterization."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Profile", "description": "Current user summary."},
        {"name": "Reports", "description": "Report listing and search."},
    ],
)
bearer_scheme = HTTPBearer()

USERS = {}
DB_PATH = "reports.db"


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


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_access_token(user_id: int, email: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise credentials_exception


def init_db():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DROP TABLE IF EXISTS reports")
    cursor.execute("DROP TABLE IF EXISTS secrets")
    cursor.execute(
        """
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            owner TEXT NOT NULL,
            total INTEGER NOT NULL
        )
        """,
    )
    cursor.execute(
        """
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag TEXT NOT NULL
        )
        """,
    )
    cursor.executemany(
        "INSERT INTO reports(name, status, owner, total) VALUES(?, ?, ?, ?)",
        [
            ("daily-sales", "ready", "analyst", 42),
            ("renewal-risk", "draft", "analyst", 17),
            ("partner-forecast", "ready", "finance", 91),
        ],
    )
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()
    cursor.execute("INSERT INTO secrets(flag) VALUES(?)", (flag,))
    connection.commit()
    connection.close()


@app.on_event("startup")
def startup_event():
    global USERS
    USERS = {
        "alice@example.com": {
            "id": 1,
            "email": "alice@example.com",
            "password_hash": pwd_context.hash("alice123"),
        },
    }
    init_db()

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
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "alice": {
                "summary": "Analyst user",
                "value": {"email": "alice@example.com", "password": "alice123"},
            },
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    return {
        "access_token": create_access_token(user["id"], user["email"]),
        "token_type": "bearer",
    }


@app.get(
    "/api/me",
    tags=["Profile"],
    summary="Current user",
    description="Returns a minimal user stub from JWT claims.",
    operation_id="getMe",
)
def get_me(claims=Depends(get_current_claims)):
    return {"id": claims["sub"], "email": claims["email"], "role": "analyst"}


@app.get(
    "/api/reports",
    tags=["Reports"],
    summary="List reports",
    description="Returns all report rows from the database.",
    operation_id="listReports",
)
def list_reports(claims=Depends(get_current_claims)):
    connection = get_connection()
    rows = connection.execute(
        "SELECT id, name, status, owner, total FROM reports ORDER BY id",
    ).fetchall()
    connection.close()
    return [dict(row) for row in rows]


@app.get(
    "/api/reports/search",
    tags=["Reports"],
    summary="Search reports by name",
    description=(
        "Filters reports where **name** matches the query string using a SQL **LIKE** pattern. "
        "Query parameter **q** is concatenated into raw SQL (intentionally unsafe)."
    ),
    operation_id="searchReports",
)
def search_reports(
    q: str = Query(
        "",
        description="Substring matched against report **name** in a SQL LIKE clause.",
        examples=["daily", "%"],
    ),
    claims=Depends(get_current_claims),
):
    allowed_info = {
        "filter_field": "name",
        "note": "user input is forwarded to the SQL layer",
    }

    connection = get_connection()
    query = (
        "SELECT id, name, status, owner, total "
        f"FROM reports WHERE name LIKE '%{q}%' ORDER BY id"
    )

    try:
        rows = connection.execute(query).fetchall()
    except sqlite3.Error as exc:
        connection.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": str(exc), "hint": allowed_info},
        )

    connection.close()
    return {
        "meta": allowed_info,
        "items": [dict(row) for row in rows],
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
