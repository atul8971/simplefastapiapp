import os
import re
from typing import Optional
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import sqlite3
import bcrypt

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Math Operations API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security: Use environment variables for secrets (never hardcode)
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

# Security scheme for bearer token authentication
security = HTTPBearer()


# ============ DATABASE UTILITIES ============


@contextmanager
def get_db_connection():
    """Context manager for database connections - ensures proper cleanup."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize database with proper schema."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


# ============ SECURITY UTILITIES ============


def hash_password(password: str) -> str:
    """Hash password using bcrypt (industry-standard secure hashing)."""
    # bcrypt automatically handles salting and uses adaptive hashing
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)  # Work factor of 12 is recommended
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored bcrypt hash."""
    try:
        password_bytes = password.encode('utf-8')
        stored_hash_bytes = stored_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)
    except (ValueError, TypeError):
        return False


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify bearer token for authentication."""
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: ADMIN_TOKEN not set",
        )
    if credentials.credentials != ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def verify_admin_token(admin_token: Optional[str]) -> bool:
    """Verify admin token for authorization."""
    if not ADMIN_TOKEN:
        return False
    return admin_token == ADMIN_TOKEN


# ============ PYDANTIC MODELS ============


class OperationRequest(BaseModel):
    a: float
    b: float


class OperationResponse(BaseModel):
    result: float
    operation: str


class UserRequest(BaseModel):
    """User creation request with proper validation."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username must contain only alphanumeric characters and underscores")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserResponse(BaseModel):
    """User response model - never expose sensitive data."""

    id: Optional[int] = None
    username: str
    email: str
    status: str


class SearchRequest(BaseModel):
    """Search request with validation."""

    query: str = Field(..., min_length=1, max_length=100)

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        # Prevent path traversal and command injection
        if any(char in v for char in [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r"]):
            raise ValueError("Query contains invalid characters")
        return v


class DeleteRequest(BaseModel):
    """Delete request with proper typing and authorization."""

    user_id: int = Field(..., gt=0)
    force: bool = False
    admin_token: str = Field(..., description="Admin token required for user deletion")


# ============ MATH OPERATIONS API ============


@app.get("/")
def read_root() -> dict:
    """
    Welcome endpoint for the Math Operations API.

    Returns:
        dict: A welcome message
    """
    return {"message": "Welcome to Math Operations API "}


@app.post("/add", response_model=OperationResponse)
def add(request: OperationRequest) -> OperationResponse:
    """
    Perform addition of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The sum of a and b along with operation type
    """
    result = request.a + request.b
    return OperationResponse(result=result, operation="addition")


@app.post("/subtract", response_model=OperationResponse)
def subtract(request: OperationRequest) -> OperationResponse:
    """
    Perform subtraction of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The difference of a - b along with operation type
    """
    result: float = request.a - request.b
    return OperationResponse(result=result, operation="subtraction")


@app.post("/divide", response_model=OperationResponse)
def divide(request: OperationRequest) -> OperationResponse:
    """
    Perform division of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The quotient of a / b along with operation type

    Raises:
        HTTPException: If b is zero (division by zero)
    """
    if request.b == 0:
        raise HTTPException(status_code=400, detail="Cannot divide by zero")
    result: float = request.a / request.b
    return OperationResponse(result=result, operation="division")


@app.post("/multiply", response_model=OperationResponse)
def multiply(request: OperationRequest) -> OperationResponse:
    """
    Perform multiplication of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The product of a * b along with operation type
    """
    result: float = request.a * request.b
    return OperationResponse(result=result, operation="multiplication")


# ============ USER MANAGEMENT API (SECURED) ============


@app.post("/users/create", response_model=UserResponse)
@limiter.limit("5/minute")  # Rate limit: 5 requests per minute per IP
def create_user(request: Request, user_data: UserRequest) -> UserResponse:
    """
    Create a new user with proper validation and security.

    Args:
        request: FastAPI request object (required for rate limiting)
        user_data: Validated user data from Pydantic model

    Returns:
        UserResponse: Created user info (without sensitive data)
    """
    # Hash the password before storage
    password_hash = hash_password(user_data.password)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (user_data.username, user_data.email, password_hash),
            )
            conn.commit()
            user_id = cursor.lastrowid

        return UserResponse(
            id=user_id,
            username=user_data.username,
            email=user_data.email,
            status="created",
        )

    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise HTTPException(status_code=400, detail="Username already exists")
        elif "email" in str(e).lower():
            raise HTTPException(status_code=400, detail="Email already exists")
        raise HTTPException(status_code=400, detail="User creation failed")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/users/search")
def search_users(
    query: str,
    admin_token: Optional[str] = None,
    _token: str = Depends(verify_token),
) -> dict:
    """
    Search users by username (requires authentication).

    Args:
        query: Search query string
        admin_token: Optional admin token for elevated access
        _token: Bearer token from authentication

    Returns:
        dict: Search results
    """
    # Validate query to prevent injection attacks
    if not query or len(query) > 100:
        raise HTTPException(status_code=400, detail="Invalid query length")

    # Sanitize query - only allow alphanumeric and basic characters
    if not re.match(r"^[a-zA-Z0-9_@.\-\s]+$", query):
        raise HTTPException(status_code=400, detail="Query contains invalid characters")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Use parameterized query with LIKE for safe searching
            cursor.execute(
                "SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 50",
                (f"%{query}%", f"%{query}%"),
            )
            rows = cursor.fetchall()
            users = [{"id": row["id"], "username": row["username"], "email": row["email"]} for row in rows]

        return {"results": users, "count": len(users)}

    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/users/delete")
def delete_user(
    request: DeleteRequest,
    _token: str = Depends(verify_token),
) -> dict:
    """
    Delete a user (requires authentication and admin authorization).

    Args:
        request: Delete request with user_id and admin_token
        _token: Bearer token from authentication

    Returns:
        dict: Deletion status
    """
    # Authorization check: verify admin token before allowing deletion
    if not verify_admin_token(request.admin_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin authorization required to delete users"
        )

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # First check if user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (request.user_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="User not found")

            # Use parameterized query for safe deletion
            cursor.execute("DELETE FROM users WHERE id = ?", (request.user_id,))
            conn.commit()

        return {"status": "deleted", "user_id": request.user_id}

    except HTTPException:
        raise
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/admin/config")
def get_admin_config(_token: str = Depends(verify_token)) -> dict:
    """
    Return non-sensitive configuration (requires authentication).

    Returns:
        dict: Safe application configuration
    """
    return {"app_name": "Math Operations API", "version": "1.0.0"}


# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database on application startup."""
    init_db()
