import requests
import os
import json
import time
import google.auth
from google.auth.transport.requests import AuthorizedSession, Request

_DEFAULT = object()


class VaultEnv():
    def __init__(self, *args, **kwargs) -> None:
        self.vault_token = None
        self._auth_token = None
        self._credentials = None
        self._jwt_token = None
        self.service_account_email = kwargs.get(
            'service_account_email',
            os.environ.get("SERVICE_ACCOUNT_EMAIL"),
        )

    @property
    def auth_token(self):
        if not self._auth_token:
            self._auth_token = self.vault_token
        return self._auth_token

    @property
    def vault_addr(self):
        vault_addr = os.environ.get("VAULT_ADDR")
        if not vault_addr:
            raise RuntimeError("VAULT_ADDR is not set")
        return vault_addr

    @property
    def client_role(self):
        return os.environ.get("CLIENT_ROLE", "cloud_builder")

    @property
    def audience_url(self):
        return f'http://vault/{self.client_role}'

    @property
    def secret_path(self):
        secret_prefix = os.environ.get("SECRET_PREFIX", "engineering/services/")
        service_name = os.environ.get("SERVICE_NAME", "kapwing_scripts")
        return os.environ.get("SECRET_PATH", f"{secret_prefix}{service_name}")

    @property
    def version_path(self):
        version_prefix = os.environ.get("VERSION_PREFIX", "engineering/services/")
        return os.environ.get("VERSION_PATH", f"{version_prefix}{self.client_role}")

    @property
    def secret_output(self):
        return os.environ.get("SECRET_OUTPUT", "env")

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
        expires = now + 850  # 15 mins minus 30 seconds (TTL must be less than 15 min, so leaves some buffer)
        jwt_claim = {"aud": self.audience_url, "sub": self.service_account_email, "iat": now, "exp": expires}

        body = json.dumps({"payload": json.dumps(jwt_claim)})

        resp = authed_session.request('POST', metadata_server_url, data=body, headers=token_headers)
         # Surface helpful error messages
        if resp.status_code != 200:
            try:
                err = resp.json()
            except Exception:
                err = {"raw": resp.text}
            raise RuntimeError(f"signJwt failed: {resp.status_code} – {err}")

        return resp.json()["signedJwt"]


    def login_vault(self):
        url = f'{self.vault_addr}/v1/auth/gcp/login'
        jwtdata = {
            "role": self.client_role,
            "jwt": f"{self.jwt_token}"
        }

        try:
            r = requests.post(url, data=jwtdata, timeout=30)
            r.raise_for_status()
            tokendata = r.json()
            self.vault_token = self._auth_token = tokendata['auth']['client_token']
            return self.vault_token
        except requests.exceptions.HTTPError as err:
            print(f"HTTP Error occurred: {err}")
            body = getattr(err.response, "text", "")
            print(f"Response body: {body}")
            raise
        except requests.exceptions.ConnectionError as err:
            print(f"Connection Error occurred: {err}")
            raise
        except requests.exceptions.Timeout as err:
            print(f"Timeout Error occurred: {err}")
            raise
        except requests.exceptions.RequestException as err:
            print(f"An unexpected error occurred: {err}")
            raise
        

    def load_secrets(self, secret_path=None, version_path=_DEFAULT, secret_output=None, output_file="/workspace/.ci.env"):
        secret_path = secret_path or self.secret_path
        version_path = self.version_path if version_path is _DEFAULT else version_path
        secret_output = secret_output or self.secret_output
        headers = {"X-Vault-Token": self.vault_token}
        url = f'{self.vault_addr}/v1/secret/{secret_path}'
        r = requests.request("LIST", url=url, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        secret_keys = secretdata['data']['keys']

        fp = None
        if secret_output == "file":
            fp = open(output_file, "w")

        for key in secret_keys:
            url = f'{self.vault_addr}/v1/secret/{secret_path}/{key}'
            r = requests.request("GET", url=url, headers=headers)
            r.raise_for_status()
            secretdata = r.json()
            secrets = secretdata['data'] or {}
            for k, v in secrets.items():
                if fp:
                    fp.write(f"{k}={v}\n")
                else:
                    os.environ[k] = v

        if version_path:
            url = f'{self.vault_addr}/v1/kv/data/{version_path}/mongodb'
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
        url = f'{self.vault_addr}/v1/{secret_path}'
        r = requests.request("GET", url=url, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        return secretdata
    
    def update_secret(self, secret_path, data, vault_token=None):
        vault_token = vault_token or self.vault_token
        headers = {"X-Vault-Token": vault_token}
        url = f'{self.vault_addr}/v1/{secret_path}'
        r = requests.request("POST", url=url, data=data, headers=headers)
        r.raise_for_status()
        secretdata = r.json()
        return secretdata

    def request(self, method, path, data={}, vault_token=None, return_request=False):
        vault_token = vault_token or self.vault_token
        headers = {"X-Vault-Token": vault_token}
        url = f'{self.vault_addr}/{path}'
        r = requests.request(method, url=url, data=data, headers=headers)
        r.raise_for_status()
        if return_request:
            return r
        try:
            secretdata = r.json()
            return secretdata 
        except:
            return r.content

    def logout(self):
        headers = {"X-Vault-Token": self.auth_token}
        url = f'{self.vault_addr}/v1/auth/token/revoke-self'
        r = requests.post(url=url, headers=headers)
        print(f'Revoked: {r.status_code}')

    def validate_token(self, vault_token=None):
        headers = {"X-Vault-Token": vault_token or self.auth_token}
        url = f'{self.vault_addr}/v1/auth/token/lookup-self'
        r = requests.request("GET", url=url, headers=headers)
        r.raise_for_status()
        data = r.json()
        print(f'Valid: {r.status_code}')
        return data



if __name__ == '__main__':
    vault_env = VaultEnv()
    vault_env.login_vault()
    vault_env.load_secrets()
    vault_env.logout()
