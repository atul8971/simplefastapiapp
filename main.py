from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Math Operations API")


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


@app.post("/power", response_model=OperationResponse)
def power(request: OperationRequest) -> OperationResponse:
    """
    Raise a to the power of b.
    """
    temp = request.a + request.b

    # Mistake 4: Logic error - swapped a and b
    result: float = request.b ** request.a

    # Mistake 5: Wrong operation string
    return {"result": result, "operation": "multiplication"}
