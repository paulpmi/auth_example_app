import hashlib
import uuid
from dataclasses import dataclass
from typing import Optional

import bcrypt
from fastapi import FastAPI, HTTPException, Depends, Query
from key_generator import key_generator
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from config import fake_cache, fake_key_store, fake_db
from constants import JWTAud, AllowedAction
from exceptions import InvalidAuthorization, InvalidAuthentication
from security import create_jwt_tokens, GetCurrentUser, ProofOfPossessionFlow, create_non_authenticated_jwk, \
    UnauthenticatedProofOfPossession, oauth2_scheme, create_non_authenticated_jwt_tokens

"""
class PrintTimings(TimingClient):
    def timing(self, metric_name, timing, tags):
        print(metric_name, timing, tags)
"""

app = FastAPI()
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["127.0.0.1"]
)
app.add_middleware(
    CORSMiddleware, allow_origins=["127.0.0.1"]
)

"""
app.add_middleware(
    TimingMiddleware,
    client=PrintTimings(),
    metric_namer=StarletteScopeToName(prefix="myapp", starlette_app=app)
)
"""


class Exchange(BaseModel):
    client_id: str
    code_verifier: str


class Login(BaseModel):
    grant_type: str
    username: str
    password: str


class UserInfo(BaseModel):
    id: str
    username: str
    role: str


class TokenResponse(BaseModel):
    key: str
    access: str
    refresh: Optional[str]


@dataclass
class PKCE:
    redirect_uri: str = Query(None)
    client_id: str = Query(None)
    response_type: str = Query(None)
    state: str = Query(None)
    code_challenge: str = Query(None)
    code_challenge_method: str = Query('S256')


@app.get('/authorize/', status_code=200)
async def authorize_client(pkce: PKCE = Depends(PKCE)):
    if pkce.code_challenge_method not in ['S256', 'S512', 'S224']:
        raise HTTPException(status_code=400, detail="invalid_code_challenge_method")
    authorization_key = await create_non_authenticated_jwk()

    fake_cache[pkce.client_id] = {
        'algorithm': pkce.code_challenge_method,
        'challenge': pkce.code_challenge,
        'key': authorization_key
    }
    return {'authorization_code': authorization_key}


@app.post("/exchange/", response_model=TokenResponse, status_code=200)
async def exchange_key_for_token(
    exchange_data: Exchange,
    decoded: dict = Depends(
        UnauthenticatedProofOfPossession(
            allowed_issuers=['demo-server-1'],
            allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.exchange.value}'],
            allowed_aud=[JWTAud.auth_server.value]
        )
    ),
    key=Depends(oauth2_scheme)
):
    key = key.split(" ")[1]
    authorized_client_data = fake_cache.get(exchange_data.client_id)
    if not authorized_client_data:
        raise InvalidAuthorization(detail="authorization_not_found")

    if key != authorized_client_data['key']:
        raise InvalidAuthorization(detail="invalid_key")

    if authorized_client_data['algorithm'] == 'S256':
        hashed_challenge = hashlib.sha256(exchange_data.code_verifier.encode('utf-8')).hexdigest()
    elif authorized_client_data['algorithm'] == 'S512':
        hashed_challenge = hashlib.sha512(exchange_data.code_verifier.encode('utf-8')).hexdigest()
    elif authorized_client_data['algorithm'] == 'S224':
        hashed_challenge = hashlib.sha224(exchange_data.code_verifier.encode('utf-8')).hexdigest()
    else:
        raise InvalidAuthorization(detail="invalid_algorithm")

    if hashed_challenge != authorized_client_data['challenge']:
        raise InvalidAuthentication(detail="invalid_verifier")

    fake_cache.pop(exchange_data.client_id)

    tokens = await create_non_authenticated_jwt_tokens()
    return {
        'redirect-url': '127.0.0.1:4000/',
        **tokens
    }


@app.post("/sign-up/", status_code=201)
async def sign_up(
        sign_up_data: Login, decoded: dict = Depends(
            ProofOfPossessionFlow(
                allowed_issuers=['demo-server-1'],
                allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.sign_up.value}'],
                allowed_aud=[JWTAud.auth_server.value],
                is_signed_in=False
            )
        ),
        key=Depends(oauth2_scheme)
):
    user_bucket = fake_db.get('users')
    for v in user_bucket:
        if v['username'] == sign_up_data.username or bcrypt.checkpw(sign_up_data.password.encode(), v['password']):
            raise HTTPException(status_code=400, detail="user_already_exist")

    sign_up_data = sign_up_data.dict()
    sign_up_data['password'] = bcrypt.hashpw(sign_up_data['password'].encode(), bcrypt.gensalt())

    user_bucket.append(
        {'role': 'user', 'id': str(uuid.uuid4()), **sign_up_data}
    )


@app.post("/login/", response_model=TokenResponse, status_code=201)
async def login(
        login_data: Login,
        decoded: dict = Depends(
            ProofOfPossessionFlow(
                allowed_issuers=['demo-server-1'],
                allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.login.value}'],
                allowed_aud=[JWTAud.auth_server.value],
                is_signed_in=False
            )
        ),
        key=Depends(oauth2_scheme)
):

    user_bucket = fake_db.get('users')

    user = None

    for v in user_bucket:
        if v['username'] == login_data.username and bcrypt.checkpw(login_data.password.encode(), v['password']):
            user = v

    if not user:
        raise InvalidAuthentication(detail="user_not_found")

    return await create_jwt_tokens(user)


@app.get("/user-info/", response_model=UserInfo, status_code=200)
async def user_info(
        user: dict = Depends(
            GetCurrentUser(
                allowed_issuers=['demo-server-1'],
                allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.read.value}'],
                allowed_aud=[JWTAud.auth_server.value]
            )
        )
):
    return UserInfo.parse_obj(user)


@app.get("/refresh-token/", response_model=TokenResponse, status_code=201)
async def refresh_access_token(
        user: dict = Depends(
            GetCurrentUser(
                allowed_issuers=['demo-server-1'],
                allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.refresh.value}'],
                allowed_aud=[JWTAud.auth_server.value])
        )
):
    return await create_jwt_tokens(user)


@app.delete("/revoke-access/", status_code=200)
async def revoke_access(
        decoded_token: dict = Depends(
            ProofOfPossessionFlow(
                allowed_issuers=['demo-server-1'],
                allowed_scopes=[f'{JWTAud.auth_server.value}.{AllowedAction.revoke.value}'],
                allowed_aud=[JWTAud.auth_server.value])
        )
):
    fake_key_store['revoked_keys'][decoded_token['jti']] = True
    fake_key_store['revoked_keys'][decoded_token['kid']] = True
    return
