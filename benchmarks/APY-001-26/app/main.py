from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

import crud
import schemas
from database import Base, SessionLocal, engine

SECRET_KEY = "apyguard-demo-secret"
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

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Order API"
    version="1.0.0"
    description=(
        "Order management API benchmark for Broken Object Level Authorization (BOLA/IDOR): "
        "authentication is enforced but object ownership is not verified for order detail access."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Current user profile."}
        {"name": "Orders", "description": "User orders and order detail by ID."}
    ]
)
bearer_scheme = HTTPBearer


def get_db:
    db = SessionLocal
    try:
        yield db
    finally:
        db.close


def create_access_token(user_id: int):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
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

    alice = crud.create_user(
        db
        email="alice@example.com"
        password="alice123"
        full_name="Alice Carter"
    )
    bob = crud.create_user(
        db
        email="bob@example.com"
        password="bob123"
        full_name="Bob Stone"
    )

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    crud.create_order(
        db
        user_id=alice.id
        item="starter-plan-renewal"
        status="processing"
        total_cents=4900
        internal_note="Customer requested invoice by email."
    )
    crud.create_order(
        db
        user_id=alice.id
        item="analytics-addon"
        status="shipped"
        total_cents=1900
        internal_note="Ship with standard packaging."
        is_priority=True
    )
    crud.create_order(
        db
        user_id=bob.id
        item="enterprise-upgrade"
        status="pending-review"
        total_cents=24900
        internal_note=f"Finance escalation flag: {flag}"
        is_priority=True
    )
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
    description="Authenticate with **email** and **password** and receive a JWT **access_token**."
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: schemas.LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {
                "summary": "Alice"
                "value": {"email": "alice@example.com", "password": "alice123"}
            }
            "bob": {
                "summary": "Bob"
                "value": {"email": "bob@example.com", "password": "bob123"}
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
        "access_token": create_access_token(user.id)
        "token_type": "bearer"
    }


@app.get(
    "/api/me"
    response_model=schemas.UserResponse
    tags=["Profile"]
    summary="Get current user"
    description="Returns the authenticated user's profile (**Authorization: Bearer** required)."
    operation_id="getCurrentUser"
)
def get_me(current_user=Depends(get_current_user)):
    return current_user


@app.get(
    "/api/orders"
    response_model=list[schemas.OrderSummaryResponse]
    tags=["Orders"]
    summary="List my orders"
    description="Returns order summaries for the authenticated user only."
    operation_id="listMyOrders"
)
def list_orders(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return crud.get_orders_for_user(db, current_user.id)


@app.get(
    "/api/orders/{order_id}"
    response_model=schemas.OrderDetailResponse
    tags=["Orders"]
    summary="Get order by ID"
    description=(
        "Returns full order detail including internal fields for the given **order_id**. "
        "Requires a valid bearer token."
    )
    operation_id="getOrderById"
)
def get_order(
    order_id: int
    current_user=Depends(get_current_user)
    db: Session = Depends(get_db)
):
    order = crud.get_order(db, order_id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    # Intentional vulnerability: authentication is enforced, but ownership is not.
    return order

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
