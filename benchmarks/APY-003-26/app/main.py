from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

import crud
import schemas
from database import Base, SessionLocal, engine

SECRET_KEY = "apyguard-workspace-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ApyGuard Workspace API"
    version="1.0.0"
    description=(
        "Workspace API benchmark modeling a mass-assignment flaw: profile updates accept "
        "arbitrary writable fields from clients and apply them to the user model without an allowlist."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Profile", "description": "Read and update the authenticated user profile."}
        {"name": "Workspace", "description": "Workspace context for the current user."}
        {"name": "Admin", "description": "Administrative content (restricted by role)."}
    ]
)
bearer_scheme = HTTPBearer

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

_PATCH_ME_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the profile update body."
        "value": {
            "detail": [
                {
                    "type": "string_type"
                    "loc": ["body", "full_name"]
                    "msg": "Input should be a valid string"
                    "input": 123
                }
            ]
        }
    }
}

_PATCH_ME_OPENAPI_RESPONSES = {
    200: {
        "description": "Current user profile after a successful update."
        "content": {
            "application/json": {
                "examples": {
                    "updated_profile": {
                        "summary": "Updated member"
                        "description": "Example **UserResponse** after PATCH."
                        "value": {
                            "id": 1
                            "email": "alice@example.com"
                            "full_name": "Alice Example"
                            "role": "member"
                            "plan": "starter"
                            "workspace_slug": "blue"
                        }
                    }
                }
            }
        }
    }
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _PATCH_ME_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}


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
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED
        detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
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
        full_name="Workspace Member"
        role="member"
        plan="starter"
        workspace_slug="blue"
    )
    crud.create_user(
        db
        email="owner@apy.local"
        password="OwnerOnly!123"
        full_name="Workspace Owner"
        role="admin"
        plan="enterprise"
        workspace_slug="red"
    )

    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read.strip

    crud.create_announcement(db, "Roadmap", "Quarterly planning sync on Friday.")
    crud.create_announcement(db, "Privileged Note", f"Executive rollout flag: {flag}")
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
            "member_alice": {
                "summary": "Member user"
                "description": "Seed member credentials."
                "value": {"email": "alice@example.com", "password": "alice123"}
            }
            "owner_account": {
                "summary": "Workspace owner"
                "description": "Seed admin/owner credentials."
                "value": {"email": "owner@apy.local", "password": "OwnerOnly!123"}
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

    return {"access_token": create_access_token(user.id), "token_type": "bearer"}


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


@app.patch(
    "/api/me"
    response_model=schemas.UserResponse
    tags=["Profile"]
    summary="Update the current user profile"
    description="Updates writable profile fields for the authenticated user. A JSON body is required."
    operation_id="patchCurrentUserProfile"
    responses=_PATCH_ME_OPENAPI_RESPONSES
)
def update_me(
    payload: schemas.ProfileUpdateRequest = Body(
        ...
        description="JSON object containing profile fields to update."
        openapi_examples={
            "basic_profile_update": {
                "summary": "Update a standard profile field"
                "description": "A normal profile edit request."
                "value": {"full_name": "Alice Example"}
            }
            "mass_assignment_example": {
                "summary": "Update a sensitive field"
                "description": "An example body that changes a security-sensitive property."
                "value": {"role": "admin"}
            }
        }
    )
    current_user=Depends(get_current_user)
    db: Session = Depends(get_db)
):
    user = crud.get_user(db, current_user.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Intentional vulnerability: arbitrary profile fields are mass-assigned onto the user model.
    for key, value in payload.model_dump(exclude_unset=True).items:
        if hasattr(user, key):
            setattr(user, key, value)

    db.add(user)
    db.commit
    db.refresh(user)
    return user


@app.get(
    "/api/workspace/summary"
    tags=["Workspace"]
    summary="Workspace summary"
    description="Returns workspace slug, plan, and role for the authenticated user."
    operation_id="getWorkspaceSummary"
)
def workspace_summary(current_user=Depends(get_current_user)):
    return {
        "workspace_slug": current_user.workspace_slug
        "plan": current_user.plan
        "role": current_user.role
    }


@app.get(
    "/api/admin/announcements"
    response_model=list[schemas.AnnouncementResponse]
    tags=["Admin"]
    summary="List announcements"
    description="Lists announcements; requires **admin** role."
    operation_id="listAdminAnnouncements"
)
def admin_announcements(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return crud.get_announcements(db)


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
