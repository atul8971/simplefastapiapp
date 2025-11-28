from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel

app = FastAPI(title="Math Operations API")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request, exc: RequestValidationError):
    """
    Handle validation errors for invalid input types.

    Args:
        _request: The incoming request (unused)
        exc (RequestValidationError): The validation error exception

    Returns:
        JSONResponse: Error details with 422 status code
    """
    return JSONResponse(
        status_code=422,
        content={
            "error": "Invalid input",
            "details": exc.errors(),
            "message": "Please provide valid numeric values for 'a' and 'b'"
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(_request, _exc: Exception):
    """
    Handle unexpected exceptions.

    Args:
        _request: The incoming request (unused)
        _exc (Exception): The caught exception (unused)

    Returns:
        JSONResponse: Generic error message with 500 status code
    """
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred while processing your request"
        }
    )


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
    return {"message": "Welcome to Math Operations API"}


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
        HTTPException: If b is zero (division by zero)
    """
    if request.b == 0:
        raise HTTPException(status_code=400, detail="Cannot divide by zero")
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
