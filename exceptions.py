from typing import Optional, Dict, Any

from fastapi import HTTPException
from starlette import status


class InvalidAuthentication(HTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "invalid_authentication"
    headers = {"WWW-Authenticate": "Bearer"}

    def __init__(
        self,
        detail=None
    ) -> None:
        if not detail:
            detail = InvalidAuthentication.detail
        super().__init__(status_code=InvalidAuthentication.status_code, detail=detail)
        self.headers = InvalidAuthentication.headers


class InvalidAuthorization(HTTPException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = 'invalid_authorization'
    headers = {"WWW-Authenticate": "Bearer"}

    def __init__(
        self,
        detail=None
    ) -> None:
        if not detail:
            detail = InvalidAuthorization.detail
        super().__init__(status_code=InvalidAuthorization.status_code, detail=detail)
        self.headers = InvalidAuthentication.headers
