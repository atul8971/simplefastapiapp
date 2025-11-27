# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a simple FastAPI application that provides a REST API for basic math operations (addition and subtraction).

## Development Commands

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Application
```bash
uvicorn main:app --reload
```

The server will start on `http://localhost:8000` with auto-reload enabled for development.

### Access API Documentation
- Interactive API docs (Swagger UI): `http://localhost:8000/docs`
- Alternative API docs (ReDoc): `http://localhost:8000/redoc`

## Architecture

The application follows a simple single-file FastAPI structure:

- **main.py**: Contains the FastAPI application instance, Pydantic models, and all endpoint definitions
  - `OperationRequest`: Request model accepting two float numbers (`a` and `b`)
  - `OperationResponse`: Response model returning the result and operation type
  - Endpoints: `/` (welcome), `/add` (POST), `/subtract` (POST)
- when new method is created make sure docstring is added by default and datatype of variable is added