import json
from flask import request, request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen

AUTH0_DOMAIN = 'dev-wmig32c8.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_shop'


# ---------------------------------------------------------------------#
# AuthError Exception
# ---------------------------------------------------------------------#

class AuthError(Exception):
    """A standardized way to communicate auth failure modes

    Parameters:
        -error: description of the error
        -status_code (int): HTTP response status codes in 3 digits
    """

    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# ---------------------------------------------------------------------#
# Auth Header
# ---------------------------------------------------------------------#

def get_token_auth_header():
    """ Obtains the access token from the Authorization Header

    It should attempt to get the header from the request,
    and split bearer and the token

    Returns:
        -str: represents the token part of the authorization header

    Raises:
        -AuthError: [401, "authorization_header_missing"], Authorization header is expected
        -AuthError: [401, "invalid_header"], Authorization header must start with "Bearer"
        -AuthError: [401, "invalid_header"], token not found
        -AuthError: [401, "invalid_header"], Authorization header must be bearer token
    """
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token


'''
    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''


def check_permissions(permission, payload):
    """Validate logged in user's permission

    Parameters:
        -permission (str): string represents the permission (i.e.: 'get:drinks-detail', 'post:drinks')
        -payload (dict): decoded jwt payload

    Returns:
        -boolean: True if permissions are included in the payload

    Raises:
        -400: an AuthError if permissions are not included in the payload
        -403: an AuthError if the requested permission string is not in the payload permissions array
    """
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'not_found',
            'description': 'Permissions are not included in the payload'
        }, 400)
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True


'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''


def verify_decode_jwt(token):
    """verify a json web token and returns the decoded payload

    Parameter:
        -token (str): a json web token

    Return:
        -The decoded payload in dict format

    Raises:
         -AuthError: [401, 'token_expired'], 'Authorization malformed.'
         -AuthError: [401, 'token_expired'], 'Token expired.'
         -AuthError: [401, 'invalid_claims'], 'Incorrect claims. Please check the audience and issuer.'
         -AuthError: [400, 'invalid_header'], 'Unable to parse authentication token.'
         -AuthError: [400, 'invalid_header'], 'Unable to find the appropriate key.'
    """
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please check the audience and issuer.'
            }, 401)

        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)

    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find the appropriate key.'
    }, 400)


def requires_auth(permission=''):
    """ Obtains the access token from get_token_auth_header and decodes the token,
        and it validates claims and check the requested permission

    Parameter:
        -permission (str): string that represents the permission (i.e. "post:drink")

    Returns:
        -the decorator which passes the decoded payload to the decorated method

    Raises:
        -AuthError: 401, unauthorized if no token provided
    """
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except AuthError:
                abort(401)

            check_permissions(permission, payload)

            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decorator