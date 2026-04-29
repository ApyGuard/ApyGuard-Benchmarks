from pydantic import BaseModel, Field


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


class ProfileUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, description="Updated full name for the current user.")
    role: str | None = Field(default=None, description="Role value to assign to the current user.")
    plan: str | None = Field(default=None, description="Workspace plan to assign to the current user.")
    workspace_slug: str | None = Field(
        default=None
        description="Workspace slug to assign to the current user."
    )

    model_config = {
        "extra": "allow"
        "json_schema_extra": {
            "example": {"role": "admin"}
        }
    }


class UserResponse(BaseModel):
    id: int = Field(description="User primary key.")
    email: str = Field(description="User email.")
    full_name: str = Field(description="Display name.")
    role: str = Field(description="Authorization role.")
    plan: str = Field(description="Billing plan name.")
    workspace_slug: str = Field(description="Workspace identifier slug.")

    model_config = {"from_attributes": True}


class AnnouncementResponse(BaseModel):
    id: int = Field(description="Announcement ID.")
    title: str = Field(description="Announcement title.")
    body: str = Field(description="Announcement body text.")

    model_config = {"from_attributes": True}
