from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-tenant-032"
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
    title="ApyGuard Billing API",
    version="1.0.0",
    description=(
        "Cross-tenant listing benchmark: optional **tenant_id** query overrides the tenant implied by the JWT."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Billing", "description": "Invoice listing."},
    ],
)
bearer = HTTPBearer()

USERS = {}
INVOICES = []


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "bob@tenantb.local", "password": "bob123"},
            ],
        },
    }


def create_token(email: str, role: str, tenant_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode(
        {"sub": email, "role": role, "tenant_id": tenant_id, "exp": exp},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup() -> None:
    global USERS, INVOICES
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()

    USERS = {
        "alice@example.com": {
            "password_hash": pwd_context.hash("alice123"),
            "role": "member",
            "tenant_id": "tenant-a",
        },
        "bob@tenantb.local": {
            "password_hash": pwd_context.hash("bob123"),
            "role": "member",
            "tenant_id": "tenant-b",
        },
    }

    INVOICES = [
        {"id": "inv-100", "tenant_id": "tenant-a", "amount": 120, "note": "normal payment"},
        {"id": "inv-900", "tenant_id": "tenant-b", "amount": 9999, "note": flag},
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
    description="JWT embeds **tenant_id** from the user record.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "tenant_a": {"value": {"email": "alice@example.com", "password": "alice123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {
        "access_token": create_token(payload.email, user["role"], user["tenant_id"]),
        "token_type": "bearer",
    }


@app.get(
    "/api/invoices",
    tags=["Billing"],
    summary="List invoices",
    description="Filters by **tenant_id** when provided, otherwise uses JWT **tenant_id**.",
    operation_id="listInvoices",
)
def list_invoices(
    tenant_id: str | None = Query(
        default=None,
        description="Optional tenant override (intentionally trusted over token tenant).",
        examples=["tenant-a", "tenant-b"],
    ),
    claims=Depends(current_claims),
):
    # Intentional vulnerability: user-supplied tenant_id overrides token tenant scope.
    effective_tenant = tenant_id or claims["tenant_id"]
    return {"items": [invoice for invoice in INVOICES if invoice["tenant_id"] == effective_tenant]}

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
