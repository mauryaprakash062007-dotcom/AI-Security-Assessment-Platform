import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    """
    Validates the X-API-Key header against the configured PLATFORM_API_KEY environment variable.
    """
    expected_api_key = os.getenv("PLATFORM_API_KEY")
    
    # If no API key is configured on the backend, we allow it to pass in development mode, 
    # but in a real prod environment we'd want this to fail.
    if not expected_api_key:
        return "development_mode"

    if api_key_header == expected_api_key:
        return api_key_header
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )
