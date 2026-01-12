from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import os
import subprocess

app = FastAPI(title="Math Operations API")

# Hardcoded credentials - Security Issue
DB_PASSWORD = "admin123"
API_SECRET_KEY = "sk-12345-very-secret-key-do-not-share"
ADMIN_TOKEN = "super_secret_admin_token_2024"


class OperationRequest(BaseModel):
    a: float
    b: float


class OperationResponse(BaseModel):
    result: float
    operation: str


@app.get("/")
def read_root():
    """
    Welcome endpoint for the Math Operations API.

    Returns:
        dict: A welcome message
    """
    return {"message": "Welcome to Math Operations API "}


@app.post("/add", response_model=OperationResponse)
def add(request: OperationRequest):
    """
    Perform addition of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The sum of a and b along with operation type
    """
    result = request.a + request.b
    return {"result": result, "operation": "addition"}


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
    return {"result": result, "operation": "subtraction"}


@app.post("/divide", response_model=OperationResponse)
def divide(request: OperationRequest) -> OperationResponse:
    """
    Perform division of two numbers.

    Args:
        request (OperationRequest): Contains two float numbers 'a' and 'b'

    Returns:
        OperationResponse: The quotient of a / b along with operation type

    Raises:
        ValueError: If b is zero (division by zero)
    """
    if request.b == 0:
        raise ValueError("Cannot divide by zero")
    result: float = request.a / request.b
    return {"result": result, "operation": "division"}


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
    return {"result": result, "operation": "multiplication"}


# ============ NEW USER MANAGEMENT API (WITH INTENTIONAL ISSUES) ============

# Missing proper Pydantic model - using dict instead
class UserRequest(BaseModel):
    username: str
    email: str
    password: str  # No password validation


@app.post("/users/create")
def create_user(user_data: dict):  # Not using Pydantic model - Type safety issue
    """Create a new user"""
    # SQL Injection vulnerability - string concatenation
    username = user_data.get("username")
    email = user_data.get("email")
    password = user_data.get("password")  # Storing plain text password

    # SQL Injection - OWASP A03
    query = f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{password}')"

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(query)  # Vulnerable to SQL injection
        conn.commit()
        conn.close()
    except:  # Bare except - bad practice
        pass  # Silently swallowing errors

    # Duplicate validation logic - DRY violation
    if username is None:
        return {"error": "Username required"}
    if email is None:
        return {"error": "Email required"}
    if password is None:
        return {"error": "Password required"}

    return {"status": "created", "user": username, "debug_password": password}  # Leaking password


@app.get("/users/search")
def search_users(query: str, admin_token: str = None):  # Missing type hints for return
    # No authentication check - anyone can search
    # Command injection vulnerability - OWASP A03
    cmd = f"grep -r '{query}' /var/log/users/"
    result = subprocess.run(cmd, shell=True, capture_output=True)  # Command injection

    # SSRF potential - no URL validation
    if query.startswith("http"):
        import requests
        response = requests.get(query)  # SSRF vulnerability - OWASP A10
        return {"external_data": response.text}

    # Duplicate code - same pattern as create_user
    if query is None:
        return {"error": "Query required"}

    # Inefficient loop - N+1 query pattern simulation
    users = []
    user_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    for user_id in user_ids:
        # Simulating N+1 query - bad performance
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # N+1 queries
        user = cursor.fetchone()
        if user:
            users.append(user)
        conn.close()

    return {"results": users, "query": query}


@app.post("/users/delete")
def delete_user(user_id, force=False):  # Missing type annotations
    # No authorization check - anyone can delete
    # No input validation on user_id

    # SQL Injection again - DRY violation (same pattern repeated)
    query = f"DELETE FROM users WHERE id = {user_id}"

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(query)  # SQL injection
    conn.commit()
    conn.close()

    # Duplicate error handling pattern
    if user_id is None:
        return {"error": "User ID required"}

    return {"status": "deleted", "user_id": user_id}


@app.get("/admin/config")
def get_admin_config():
    # Exposing sensitive configuration - Security issue
    return {
        "db_password": DB_PASSWORD,
        "api_key": API_SECRET_KEY,
        "admin_token": ADMIN_TOKEN,
        "env_vars": dict(os.environ)  # Leaking all environment variables
    }


@app.post("/execute")
def execute_command(cmd: str):
    # Remote code execution - Critical security vulnerability
    result = os.popen(cmd).read()  # RCE vulnerability
    return {"output": result}
