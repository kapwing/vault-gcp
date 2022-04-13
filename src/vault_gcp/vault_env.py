import requests
import os
import json
import time
import google.auth
from google.auth.transport.requests import AuthorizedSession, Request

VAULT_ADDR = os.environ.get('VAULT_ADDR')
CLIENT_ROLE = os.environ.get("CLIENT_ROLE", "cloud_builder")
AUDIENCE_URL = f'http://vault/{CLIENT_ROLE}'
APP_ROLE = os.environ.get("APP_ROLE", "kapwing_processor")
DEFAULT_SERVICE_ACCOUNT_EMAIL = os.environ.get("SERVICE_ACCOUNT_EMAIL")
SECRET_OUTPUT = os.environ.get("SECRET_OUTPUT", "env")


class VaultEnv():
    def __init__(self, *args, **kwargs) -> None:
        self.vault_token = None
        self._auth_token = None
        self._credentials = None
        self._jwt_token = None
        self.service_account_email = kwargs.get('service_account_email', DEFAULT_SERVICE_ACCOUNT_EMAIL)

    @property
    def auth_token(self):
        if not self._auth_token:
            self._auth_token = self.vault_token
        return self._auth_token

    @property
    def credentials(self):
        if not self._credentials:
            self._credentials = self.get_credentials()
        return self._credentials

    @property
    def jwt_token(self):
        if not self._jwt_token:
            self._jwt_token = self.get_jwt()
        return self._jwt_token

    def get_credentials(self):
        credentials, project_id = google.auth.default(scopes='https://www.googleapis.com/auth/cloud-platform')        
        self._credentials = credentials
        self._credentials.refresh(Request())
        if not self.service_account_email:
            if hasattr(self._credentials, "service_account_email"):
                self.service_account_email = self._credentials.service_account_email       
        return self._credentials

    def get_jwt(self):
        authed_session = AuthorizedSession(self.credentials)
        
        metadata_server_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self.service_account_email}:signJwt"
        token_headers = {'content-type': 'application/json'}

        now = int(time.time())
        expires = now + 900  # 15 mins in seconds, can't be longer.
        jwt_claim = {"aud": AUDIENCE_URL, "sub": self.service_account_email, "iat": now, "exp": expires}

        body = json.dumps({"payload": json.dumps(jwt_claim)})

        token_response = authed_session.request('POST', metadata_server_url, data=body, headers=token_headers)
        jwt = token_response.json()
        return jwt['signedJwt']

    def login_vault(self):
        url = f'{VAULT_ADDR}/v1/auth/gcp/login'
        jwtdata = {
            "role": CLIENT_ROLE,
            "jwt": f"{self.jwt_token}"
        }

        r = requests.post(url, data=jwtdata)
        r.raise_for_status()
        tokendata = r.json()
        self.vault_token = self._auth_token = tokendata['auth']['client_token']
        return self.vault_token

    def load_secrets(self, app_role=APP_ROLE, db_role=CLIENT_ROLE, secret_output=SECRET_OUTPUT, output_file="/workspace/.ci.env"):
        headers = {"X-Vault-Token": self.vault_token}
        url = f'{VAULT_ADDR}/v1/secret/{app_role}'
        r = requests.request("LIST", url=url, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        secret_keys = secretdata['data']['keys']

        fp = None
        if secret_output == "file":
            fp = open(output_file, "w")

        for key in secret_keys:
            url = f'{VAULT_ADDR}/v1/secret/{app_role}/{key}'
            r = requests.request("GET", url=url, headers=headers)
            r.raise_for_status()
            secretdata = r.json()
            secrets = secretdata['data'] or {}
            for k, v in secrets.items():
                if fp:
                    fp.write(f"{k}={v}\n")
                else:
                    os.environ[k] = v

        if db_role:
            url = f'{VAULT_ADDR}/v1/kv/data/{db_role}/mongodb'
            r = requests.request("GET", url=url, headers=headers)        
            r.raise_for_status()
            secretdata = r.json()
            secrets = secretdata['data']['data']

            if fp:
                fp.write(f"MONGODB_USERNAME={secrets['username']}\n")
                fp.write(f"MONGODB_PASSWORD={secrets['password']}\n")
            else:
                os.environ['MONGODB_USERNAME'] = secrets['username']
                os.environ['MONGODB_PASSWORD'] = secrets['password']
        
        if fp:
            fp.close()
        print(f'Finished Retrieving Secrets')

    def get_secret(self, secret_path, vault_token=None):
        vault_token = vault_token or self.vault_token
        headers = {"X-Vault-Token": vault_token}
        url = f'{VAULT_ADDR}/v1/{secret_path}'
        r = requests.request("GET", url=url, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        return secretdata
    
    def update_secret(self, secret_path, data, vault_token=None):
        vault_token = vault_token or self.vault_token
        headers = {"X-Vault-Token": vault_token}
        url = f'{VAULT_ADDR}/v1/{secret_path}'
        r = requests.request("POST", url=url, data=data, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        return secretdata

    def request(self, method, path, data={}, vault_token=None):
        vault_token = vault_token or self.vault_token
        headers = {"X-Vault-Token": vault_token}
        url = f'{VAULT_ADDR}/{path}'
        r = requests.request(method, url=url, data=data, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        return secretdata 

    def logout(self):
        headers = {"X-Vault-Token": self.auth_token}
        url = f'{VAULT_ADDR}/v1/auth/token/revoke-self'
        r = requests.post(url=url, headers=headers)
        print(f'Revoked: {r.status_code}')


if __name__ == '__main__':
    vault_env = VaultEnv()
    vault_env.login_vault()
    vault_env.load_secrets()
    vault_env.logout()
