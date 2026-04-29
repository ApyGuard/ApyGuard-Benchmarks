from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-tenant-bola-secret"
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
    title="ApyGuard Tenant Invoice API"
    version="1.0.0"
    description=(
        "Multi-tenant invoice benchmark: path includes **tenant_id** but user-to-tenant binding "
        "is not enforced before returning invoice data."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Invoices", "description": "Tenant-scoped invoices."}
    ]
)
bearer = HTTPBearer
USERS = {}
INVOICES = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": "bob@beta.local", "password": "bob123"}
            ]
        }
    }


def create_token(user: dict):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {
        "sub": str(user["id"])
        "email": user["email"]
        "tenant_id": user["tenant_id"]
        "role": user["role"]
        "exp": exp
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event:
    global USERS, INVOICES
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    USERS = {
        "alice@example.com": {
            "id": 1
            "email": "alice@example.com"
            "role": "member"
            "tenant_id": "tenant-alpha"
            "password_hash": pwd_context.hash("alice123")
        }
        "bob@beta.local": {
            "id": 2
            "email": "bob@beta.local"
            "role": "member"
            "tenant_id": "tenant-beta"
            "password_hash": pwd_context.hash("bob123")
        }
    }

    INVOICES = {
        "inv-a-100": {"id": "inv-a-100", "tenant_id": "tenant-alpha", "amount": 40, "note": "normal"}
        "inv-b-900": {
            "id": "inv-b-900"
            "tenant_id": "tenant-beta"
            "amount": 940
            "internal_flag": flag
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
    description="Authenticate with **email** and **password**; JWT includes **tenant_id**."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
            "bob": {"value": {"email": "bob@beta.local", "password": "bob123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/tenants/{tenant_id}/invoices/{invoice_id}"
    tags=["Invoices"]
    summary="Get invoice in tenant"
    description="Fetches **invoice_id** after validating it belongs to **tenant_id** in the path (caller tenant may not match)."
    operation_id="getTenantInvoice"
)
def get_invoice(tenant_id: str, invoice_id: str, _claims=Depends(current_claims)):
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="invoice not found")
    # Intentional vulnerability: user-to-tenant authorization not checked.
    if invoice["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="invoice not found")
    return invoice

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
