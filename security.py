import base64
import datetime
import hashlib
import hmac
import uuid
from typing import Optional

from fastapi import Depends
from fastapi.openapi.models import HTTPBase
from fastapi.security import OAuth2
from fastapi.security.base import SecurityBase
from jwcrypto import jwt
from jwcrypto.common import json_decode
from pydantic import BaseModel
from starlette.requests import Request

from config import jwt_private_key, jwt_encrypting_public_key, jwt_public_key, jwt_encrypting_private_key, \
    fake_key_store, fake_db
from constants import JWTAud, AllowedAction
from exceptions import InvalidAuthentication, InvalidAuthorization


async def build_scope(server, allowed_actions):
    scopes = []
    for allowed_action in allowed_actions:
        scopes.append(f'{server}.{allowed_action}')
    return scopes


async def generate_generic_access_authorization():
    audiences = [JWTAud.auth_server.value, JWTAud.order_server.value]
    scopes = await build_scope(JWTAud.auth_server.value, [AllowedAction.sign_up.value, AllowedAction.login.value])
    scopes += await build_scope(JWTAud.order_server.value, [
        AllowedAction.read.value
    ])
    return {'aud': audiences, 'scopes': scopes}


async def generate_access_authorization(user):
    audiences = [JWTAud.auth_server.value, JWTAud.order_server.value]
    scopes = await build_scope(JWTAud.auth_server.value, [
        AllowedAction.read.value, AllowedAction.sign_up.value, AllowedAction.login.value
    ])
    scopes += await build_scope(JWTAud.order_server.value, [
        AllowedAction.read.value, AllowedAction.write_self.value, AllowedAction.update_self.value
    ])

    if user['role'] == 'admin':
        scopes += await build_scope(JWTAud.order_server.value, [AllowedAction.delete_self.value])

    return {'aud': audiences, 'scopes': scopes}


async def create_non_authenticated_jwk():
    scopes = await build_scope(JWTAud.auth_server.value, [AllowedAction.exchange.value])

    key = json_decode(jwt.JWK.generate(kty='oct', size=256).export())
    non_auth_token = jwt.JWT(
        header={'alg': 'RS256', 'jti': str(uuid.uuid4()),
                'exp': (datetime.datetime.now() + datetime.timedelta(minutes=1)).timestamp(),
                'iat': datetime.datetime.now().timestamp()},
        claims={'iss': 'demo-server-1', 'scopes': scopes, 'aud': [JWTAud.auth_server.value], **key}
    )
    non_auth_token.make_signed_token(jwt_private_key)
    return non_auth_token.serialize()


async def create_non_authenticated_jwt_tokens():
    proof_of_possession_data = jwt.JWK.generate(kty='oct', size=256).export()
    proof_of_possession_token = jwt.JWT(
        header={'alg': 'RS256', 'kid': str(uuid.uuid4())},
        claims=proof_of_possession_data
    )
    proof_of_possession_token.make_signed_token(jwt_private_key)

    access_token_id = str(uuid.uuid4())

    authorizations = await generate_generic_access_authorization()

    access_token = jwt.JWT(
        header={
            'alg': 'RS256',
            'exp': (datetime.datetime.now() + datetime.timedelta(seconds=5)).timestamp(),
            'iat': datetime.datetime.now().timestamp()
        },
        claims={
            'cnf': {'dpop+jwt': proof_of_possession_token.serialize()},
            'iss': 'demo-server-1',
            **authorizations
        })

    access_token.make_signed_token(jwt_private_key)
    access_token = jwt.JWT(
        header={"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", 'jti': access_token_id, 'typ': 'access'},
        claims=access_token.serialize()
    )
    access_token.make_encrypted_token(jwt_encrypting_public_key)

    return {
        'key': proof_of_possession_token.serialize(),
        'access': access_token.serialize(),
    }


async def create_jwt_tokens(user):
    proof_of_possession_data = jwt.JWK.generate(kty='oct', size=256).export()
    proof_of_possession_token = jwt.JWT(
        header={'alg': 'RS256', 'kid': str(uuid.uuid4())},
        claims=proof_of_possession_data
    )
    proof_of_possession_token.make_signed_token(jwt_private_key)

    access_token_id = str(uuid.uuid4())

    authorizations = await generate_access_authorization(user)

    access_token = jwt.JWT(
        header={
            'alg': 'RS256',
            'exp': (datetime.datetime.now() + datetime.timedelta(seconds=5)).timestamp(),
            'iat': datetime.datetime.now().timestamp()
        },
        claims={
            'cnf': {'dpop+jwt': proof_of_possession_token.serialize()},
            'sub': user['id'],
            'username': user['username'],
            'iss': 'demo-server-1',
            **authorizations
        })

    access_token.make_signed_token(jwt_private_key)
    access_token = jwt.JWT(
        header={"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", 'jti': access_token_id, 'typ': 'access'},
        claims=access_token.serialize()
    )
    access_token.make_encrypted_token(jwt_encrypting_public_key)

    refresh_token_id = str(uuid.uuid4())
    refresh_token = jwt.JWT(
        header={
            'jti': refresh_token_id, 'kid': access_token_id,
            'alg': 'RS256',
            'exp': (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
            'iat': datetime.datetime.now().timestamp()
        },
        claims={
            'cnf': {'dpop+jwt': proof_of_possession_token.serialize()},
            'sub': user['id'],
            'iss': 'demo-server-1',
            'aud': [JWTAud.auth_server.value],
            'scopes': [
                f'{JWTAud.auth_server.value}.{AllowedAction.refresh.value}',
                f'{JWTAud.auth_server.value}.{AllowedAction.refresh.value}'
            ]
        })

    refresh_token.make_signed_token(jwt_private_key)

    refresh_token = jwt.JWT(
        header={'jti': refresh_token_id, 'kid': access_token_id, 'typ': 'refresh', "alg": "RSA-OAEP-256",
                "enc": "A256CBC-HS512"},
        claims=refresh_token.serialize()
    )
    refresh_token.make_encrypted_token(jwt_encrypting_public_key)

    return {
        'key': proof_of_possession_token.serialize(),
        'access': access_token.serialize(),
        'refresh': refresh_token.serialize()
    }


class SignatureHeaderPayload(BaseModel):
    key_id: str
    algorithm: str
    signed_headers: list
    signature: str


class Signature(SecurityBase):
    def __init__(
            self,
            *,
            auto_error: Optional[bool] = True
    ):
        self.model = HTTPBase(scheme='signature')
        self.scheme_name = self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        signature_header: str = request.headers.get("Signature")
        if not signature_header:
            raise InvalidAuthentication
        return signature_header


signature_scheme = Signature()
oauth2_scheme = OAuth2()


class UnauthenticatedProofOfPossession(SecurityBase):
    def __init__(self, allowed_issuers: list, allowed_scopes: list, allowed_aud: list, require_signed_headers: list = ['Date']):
        self.allowed_issuers = allowed_issuers
        self.allowed_scopes = allowed_scopes
        self.allowed_aud = allowed_aud
        self.require_signed_headers = require_signed_headers
        self.model = HTTPBase(scheme='pop')
        self.scheme_name = self.__class__.__name__
        self.auto_error = True

    async def __call__(
            self, request: Request, access_token: str = Depends(oauth2_scheme),
            signature_header: str = Depends(signature_scheme)
    ):
        access_token = access_token.split(" ")[1]
        try:
            client_public_key = jwt.JWS()
            client_public_key.deserialize(
                access_token
            )
            client_public_key.verify(jwt_public_key)
            decoded = json_decode(client_public_key.payload)
            header = client_public_key.jose_header
        except Exception as e:
            print(e)
            raise InvalidAuthentication

        if not header.get('exp') or header['exp'] <= datetime.datetime.now().timestamp():
            raise InvalidAuthorization(detail='expired_token')

        if not decoded.get('iss') or decoded['iss'] not in self.allowed_issuers:
            raise InvalidAuthorization

        if not decoded.get('scopes') or (set(decoded['scopes']) & set(self.allowed_scopes) == {}):
            raise InvalidAuthorization

        if not decoded.get('aud') or (set(decoded['aud']) & set(self.allowed_aud) == {}):
            raise InvalidAuthorization

        try:
            json_signature_header = base64.b64decode(signature_header)
            signature_payload = json_decode(json_signature_header)

            key_id = signature_payload['key_id']
            algorithm = signature_payload['algorithm']
            signed_headers = signature_payload['signed_headers']
            signed_header_data = signature_payload['signature']
        except Exception as e:
            raise InvalidAuthentication(detail="invalid_signature")

        if self.require_signed_headers and not all(item in signed_headers for item in self.require_signed_headers):
            raise InvalidAuthentication(detail="missing_signed_headers")

        encoded_value = None

        key = decoded['k'].encode("utf-8")

        for idx, signed_header in enumerate(signed_headers):
            header_value = request.headers.get(signed_header).encode("utf-8")
            if idx == 0:
                encoded_value = hmac.new(key, header_value, hashlib.sha256).digest()
            else:
                encoded_value = hmac.new(encoded_value, header_value, hashlib.sha256).digest()

        if encoded_value.hex() != signed_header_data:
            raise InvalidAuthentication(detail="invalid_signature")
        return {**header, **decoded}


class ProofOfPossessionFlow(SecurityBase):
    def __init__(
            self,
            allowed_issuers: list,
            allowed_scopes: list,
            allowed_aud: list,
            require_signed_headers: list = ['Date'],
            is_signed_in=True
    ):
        self.allowed_issuers = allowed_issuers
        self.allowed_scopes = allowed_scopes
        self.allowed_aud = allowed_aud
        self.require_signed_headers = require_signed_headers
        self.is_signed_in = is_signed_in
        self.model = HTTPBase(scheme='pop')
        self.scheme_name = self.__class__.__name__
        self.auto_error = True

    async def __call__(
            self, request: Request, access_token: str = Depends(oauth2_scheme),
            signature_header: str = Depends(signature_scheme)
    ):
        access_token = access_token.split(" ")[1]
        try:
            decrypted = jwt.JWT(jwt=access_token, key=jwt_encrypting_private_key)
            jti = json_decode(decrypted.header)['jti']
            decrypted.deserialize(decrypted.claims, key=jwt_public_key)
            decoded = json_decode(decrypted.claims)
            header = json_decode(decrypted.header)
        except Exception as e:
            raise InvalidAuthentication

        if not header.get('exp') or header['exp'] <= datetime.datetime.now().timestamp():
            raise InvalidAuthorization(detail='expired_token')

        if not decoded.get('iss') or decoded['iss'] not in self.allowed_issuers:
            raise InvalidAuthorization

        if self.is_signed_in:
            if not decoded.get('sub'):
                raise InvalidAuthentication(detail="subject_not_found")

        if not decoded.get('cnf') or not decoded['cnf'].get('dpop+jwt'):
            raise InvalidAuthorization

        if not decoded.get('scopes') or (set(decoded['scopes']) & set(self.allowed_scopes) == {}):
            raise InvalidAuthorization

        if not decoded.get('aud') or (set(decoded['aud']) & set(self.allowed_aud) == {}):
            raise InvalidAuthorization

        try:
            json_signature_header = base64.b64decode(signature_header)
            signature_payload = json_decode(json_signature_header)

            key_id = signature_payload['key_id']
            algorithm = signature_payload['algorithm']
            signed_headers = signature_payload['signed_headers']
            signed_header_data = signature_payload['signature']
        except Exception as e:
            raise InvalidAuthentication(detail="invalid_signature")

        encoded_key_token = decoded['cnf']['dpop+jwt']

        client_public_key = jwt.JWS()
        client_public_key.deserialize(
            encoded_key_token
        )
        client_public_key.verify(jwt_public_key)
        client_public_key_header = client_public_key.jose_header

        if client_public_key_header['kid'] != key_id:
            raise InvalidAuthorization

        if fake_key_store['revoked_keys'].get(jti):
            raise InvalidAuthorization(detail='inactive_user')

        if not all(item in signed_headers for item in self.require_signed_headers):
            raise InvalidAuthentication(detail="missing_signed_headers")

        encoded_value = None

        key = json_decode(client_public_key.payload)['k'].encode("utf-8")

        for idx, signed_header in enumerate(signed_headers):
            header_value = request.headers.get(signed_header).encode("utf-8")
            if idx == 0:
                encoded_value = hmac.new(key, header_value, hashlib.sha256).digest()
            else:
                encoded_value = hmac.new(encoded_value, header_value, hashlib.sha256).digest()

        if encoded_value.hex() != signed_header_data:
            raise InvalidAuthentication(detail="invalid_signature")
        return {**header, **decoded}


class GetCurrentUser(ProofOfPossessionFlow):
    async def __call__(
            self, request: Request, access_token: str = Depends(oauth2_scheme),
            signature_header: str = Depends(signature_scheme)
    ):
        decoded = await super().__call__(request, access_token, signature_header)
        user_bucket = fake_db['users']
        for user in user_bucket:
            if user['id'] == decoded['sub']:
                return user

        raise InvalidAuthentication(detail="user_not_found")
