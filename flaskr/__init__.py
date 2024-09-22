import json
from flask import Flask
from flask import Flask, request, abort, render_template, redirect
from functools import wraps
from jose import jwt
from urllib.request import urlopen
from flask import jsonify
from dotenv import load_dotenv
import os

load_dotenv()

AUTH0_DOMAIN = "dev-rjs5hjuhg713iw0w.us.auth0.com"
ALGORITHMS = ['RS256']
API_AUDIENCE = "image"
YOUR_CLIENT_ID = os.getenv("YOUR_CLIENT_ID")
YOUR_CALLBACK_URI = 'http://localhost:5000/loginresults'

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
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


def verify_decode_jwt(token):
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
                'description': 'Incorrect claims. Please, check the audience and issuer.'
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


def ra(permission):
    def requires_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                abort(401)

            if permission == "":
                #ok
                return f(payload, *args, **kwargs)
            
            else:
                #we need to check
                print("permissions", payload['permissions'], permission, flush=True)
                if "permissions" not in payload or permission not in payload['permissions']:
                    abort(403)
                else:
                    return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth


def create_app():

    app = Flask("flaskr")

    @app.route('/')
    def home():
        return render_template("home.html")
    
    @app.route('/logout')
    def logout():
        return render_template("logout.html")
    
    @app.route('/appvars')
    def get_app_vars():
        login_url = f"https://{AUTH0_DOMAIN}/authorize?audience={API_AUDIENCE}&response_type=token&client_id={YOUR_CLIENT_ID}&redirect_uri={YOUR_CALLBACK_URI}"
        return {
            "login_url": login_url
        }
    

    @app.route('/loginresults')
    def loginresults():
        return render_template("loginresults.html")

    @app.route('/protected-route')
    @ra("")
    def protected_any(payload):
        print("protected", payload, flush=True)
        return jsonify({
            "secretstuff": 1234
        })
    

    @app.route('/protected-route-get')
    @ra('get:images')
    def protected_get(payload):
        print("get", payload, flush=True)
        return jsonify({
            "secretstuff get": 123456
        })
    

    @app.route('/protected-route-post', methods=['POST'])
    @ra('post:images')
    def protected_post(payload):
        print("post", payload, flush=True)
        return jsonify({
            "secretstuff post": 12345678
        })
        

    @app.route('/dologout')
    def dologout():
        # Auth0 logout URL
        auth0_logout_url = f"https://{AUTH0_DOMAIN}/v2/logout"
        
        # Parameters for Auth0 logout
        return_to = "http://localhost:5000/logout"  # Where you want the user to go after logout
        params = f"?client_id={YOUR_CLIENT_ID}&returnTo={return_to}"
        
        # Redirect the user to the Auth0 logout URL
        return redirect(f"{auth0_logout_url}{params}")

    return app
