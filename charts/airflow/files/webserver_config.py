from __future__ import annotations
import os
import logging
import jwt
import requests
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from airflow.www.fab_security.manager import AUTH_OAUTH
from airflow.www.security import AirflowSecurityManager
from flask_appbuilder import expose
from flask_appbuilder.security.views import AuthOAuthView


basedir = os.path.abspath(os.path.dirname(__file__))
log = logging.getLogger(__name__)


APP_THEME = "simplex.css"
WTF_CSRF_ENABLED = True


# ----------------------------------------------------
# AUTHENTICATION CONFIG
# ----------------------------------------------------
# For details on how to set up each of the following authentication, see
# http://flask-appbuilder.readthedocs.io/en/latest/security.html# authentication-methods
# for details.
AUTH_TYPE = AUTH_OAUTH
AUTH_ROLE_PUBLIC = 'Viewer'
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
AUTH_ROLES_SYNC_AT_LOGIN = True


AUTH_ROLES_MAPPING = {
  "airflow_admin": ["Admin"],
  "airflow_op": ["Op"],
  "airflow_user": ["User"],
  "airflow_viewer": ["Viewer"],
  "airflow_public": ["Public"],
}

PROVIDER_NAME = 'keycloak'
CLIENT_ID = 'airflow'
CLIENT_SECRET = 'HbL6S3jEpP2GUt4m7V79cQE8vJ0CG6dX'
OIDC_ISSUER = 'https://stage-auth.bitesla.net/realms/stage'
OIDC_BASE_URL = "https://stage-auth.bitesla.net/realms/stage/protocol/openid-connect"
OIDC_TOKEN_URL = f"{OIDC_BASE_URL}/token"
OIDC_AUTH_URL = f"{OIDC_BASE_URL}/auth"

# When using OAuth Auth, uncomment to setup provider(s) info
OAUTH_PROVIDERS = [{
    'name':PROVIDER_NAME,
    'token_key':'access_token',
    'icon':'fa-circle-o',
    'remote_app': {
        'api_base_url':OIDC_BASE_URL,
        'access_token_url':OIDC_TOKEN_URL,
        'authorize_url':OIDC_AUTH_URL,
        'request_token_url': None,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'client_kwargs':{
            'scope': 'email profile'
        },
    }
}]

req = requests.get(OIDC_ISSUER)
key_der_base64 = req.json()["public_key"]
key_der = b64decode(key_der_base64.encode())
public_key = serialization.load_der_public_key(key_der)

class CustomAuthRemoteUserView(AuthOAuthView):
    @expose("/logout/")
    def logout(self):
        """Delete access token before logging out."""
        return super().logout()
    

class CustomSecurityManager(AirflowSecurityManager):
    authoauthview = CustomAuthRemoteUserView
  
    def oauth_user_info(self, provider, response):
        if provider == PROVIDER_NAME:
            token = response["access_token"]
            me = jwt.decode(token, public_key, algorithms=['RS256'], audience="account")
            resource_access = me.get("resource_access", {})
            airflow_roles = resource_access.get("airflow", {}).get("roles", [])
            groups = airflow_roles if airflow_roles else ["airflow_public"]
            userinfo = {
                "username": me.get("preferred_username"),
                "email": me.get("email"),
                "first_name": me.get("given_name"),
                "last_name": me.get("family_name"),
                "role_keys": groups,
            }
            log.info("user info: {0}".format(userinfo))
            return userinfo
        return {}

SECURITY_MANAGER_CLASS = CustomSecurityManager