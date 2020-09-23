from enum import Enum


class AllowedAction(Enum):
    read = 'read'
    write_self = 'write-self'
    write_others = 'write-others'
    update_self = 'update-self'
    update_others = 'update-others'
    delete_self = 'delete-self'
    delete_others = 'delete-others'
    refresh = 'refresh'
    revoke = 'revoke'
    sign_up = 'sign-up'
    login = 'login'
    exchange = 'exchange'


class JWTAud(Enum):
    auth_server = 'auth-server'
    order_server = 'order-server'
