import uuid

import bcrypt
from jwcrypto import jwk
from jwcrypto.common import json_decode

fake_db = {
    'users': [
        {
            'id': str(uuid.uuid4()),
            'role': 'admin',
            'username': 'some_username',
            'password': bcrypt.hashpw('some_password'.encode(), bcrypt.gensalt())
        },
        {
            'id': str(uuid.uuid4()),
            'role': 'user',
            'username': 'some_username_2',
            'password': bcrypt.hashpw('some_password_2'.encode(), bcrypt.gensalt())
        }
    ]
}

fake_cache = {}

fake_key_store = {
    'keys': {},
    'revoked_keys': {}
}

jwt_private_key = jwk.JWK.generate(kty='RSA', size=2048)
jwt_public_key = jwk.JWK()
jwt_public_key.import_key(**json_decode(jwt_private_key.export_public()))


jwt_encrypting_private_key = jwk.JWK.generate(kty='RSA', size=2048)
jwt_encrypting_public_key = jwk.JWK()
jwt_encrypting_public_key.import_key(**json_decode(jwt_encrypting_private_key.export_public()))
