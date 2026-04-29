from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

import crud
import schemas
from database import Base, SessionLocal, engine

SECRET_KEY = "apyguard-support-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

Base.metadata.create_all(bind=engine)

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

_EXPORT_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the export body."
        "value": {
            "detail": [
                {
                    "type": "bool_parsing"
                    "loc": ["body", "async_delivery"]
                    "msg": "Input should be a valid boolean, unable to interpret input"
                    "input": "not-a-boolean"
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

_EXPORT_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _EXPORT_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Support API"
    version="1.0.0"
    description=(
        "Support platform API benchmark for Broken Function Level Authorization (BFLA): "
        "an admin export route accepts any authenticated user without verifying admin role."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Current user profile."}
        {"name": "Tickets", "description": "Support tickets (role-restricted listing)."}
        {"name": "Admin", "description": "Administrative export operations."}
    ]
)
bearer_scheme = HTTPBearer


def get_db:
    db = SessionLocal
    try:
        yield db
    finally:
        db.close


def create_access_token(user_id: int, role: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED
        detail="Could not validate credentials"
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise credentials_exception

    user = crud.get_user(db, user_id)
    if not user:
        raise credentials_exception
    return user


@app.on_event("startup")
def startup_event:
    db = SessionLocal
    crud.delete_all(db)

    crud.create_user(
        db
        email="alice@example.com"
        password="alice123"
        role="support"
        full_name="Support Agent"
    )
    crud.create_user(
        db
        email="admin@apy.local"
        password="UltraSecretAdmin!"
        role="admin"
        full_name="Platform Admin"
    )

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    crud.create_ticket(
        db
        subject="Refund pending"
        status="open"
        owner_email="customer1@example.com"
        public_note="Customer asked for invoice copy."
    )
    crud.create_ticket(
        db
        subject="Billing portal issue"
        status="investigating"
        owner_email="customer2@example.com"
        public_note="Escalate if reproduced in production."
    )

    app.state.export_payload = {
        "generated_by": "system"
        "environment": "production"
        "secrets": {
            "support_master_note": f"Admin export flag: {flag}"
            "rotation_window": "quarterly"
        }
    }
    db.close


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
    response_model=schemas.TokenResponse
    tags=["Authentication"]
    summary="Issue an access token"
    description="Authenticate with **email** and **password** and receive a JWT **access_token** including **role** claims."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: schemas.LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "support_alice": {
                "summary": "Support user"
                "value": {"email": "alice@example.com", "password": "alice123"}
            }
            "admin_user": {
                "summary": "Admin user"
                "value": {"email": "admin@apy.local", "password": "UltraSecretAdmin!"}
            }
        }
    )
    db: Session = Depends(get_db)
):
    user = crud.get_user_by_email(db, payload.email)
    if not user or not crud.verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED
            detail="Invalid email or password"
        )

    return {
        "access_token": create_access_token(user.id, user.role)
        "token_type": "bearer"
    }


@app.get(
    "/api/me"
    response_model=schemas.UserResponse
    tags=["Profile"]
    summary="Get current user"
    description="Returns the authenticated user including **role** (**Authorization: Bearer** required)."
    operation_id="getCurrentUser"
)
def get_me(current_user=Depends(get_current_user)):
    return current_user


@app.get(
    "/api/tickets"
    response_model=list[schemas.TicketResponse]
    tags=["Tickets"]
    summary="List support tickets"
    description="Returns tickets when the caller's role is **support** or **admin**; otherwise **403**."
    operation_id="listTickets"
)
def list_tickets(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role not in {"support", "admin"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return crud.get_tickets(db)


@app.post(
    "/api/admin/export"
    tags=["Admin"]
    summary="Admin data export"
    description=(
        "Returns a privileged export payload. Intended for administrators; "
        "the benchmark intentionally omits strict role checks beyond authentication."
    )
    operation_id="postAdminExport"
    responses=_EXPORT_OPENAPI_RESPONSES
)
def admin_export(
    _payload: schemas.AdminExportRequest = Body(
        ...
        description="JSON request body (**application/json**). See *AdminExportRequest* for fields."
        openapi_examples={
            "sync_export": {
                "summary": "Synchronous export"
                "value": {"async_delivery": False}
            }
            "async_export": {
                "summary": "Async delivery flag"
                "value": {"async_delivery": True}
            }
        }
    )
    current_user=Depends(get_current_user)
):
    # Intentional vulnerability: the route requires authentication but does not verify admin role.
    return app.state.export_payload

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
