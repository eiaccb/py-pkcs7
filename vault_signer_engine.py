
import logging
logger = logging.getLogger(__name__)

import os
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import serialization
import hvac

from signer_engine import SignerEngine, PrivateKeySignerEngine

algorithm_name_table = {
    'sha224': 'sha2-224',
    'sha256': 'sha2-256',
    'sha384': 'sha2-384',
    'sha512': 'sha2-512',
}

padding_name_table = {
    'EMSA-PSS': 'pss',
    'EMSA-PKCS1-v1_5': 'pkcs1v15',
}

class VaultSignerEngine(SignerEngine):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vault_addr = 'https://127.0.0.1:8200'
        self.vault_auth = None
        self.vault_verify = None
        self._vault_token = None
        self.mount_point = 'transit'
        self.vault_key_name = None

        if 'vault_addr' in self._kwargs and self._kwargs['vault_addr'] is not None:
            vault_addr = self._kwargs['vault_addr']
            del self._kwargs['vault_addr']
        else:
            vault_addr = os.getenv('VAULT_ADDR', None)
        if vault_addr:
            self.vault_addr = vault_addr

        if 'vault_auth' in self._kwargs:
            self.vault_auth = self._kwargs['vault_auth']
            del self._kwargs['vault_auth']

        if 'vault_verify' in self._kwargs and self._kwargs['vault_verify'] is not None:
            self.vault_verify = self._kwargs['vault_verify']
        elif skip_verify := os.getenv('VAULT_SKIP_VERIFY', False):
            self.vault_verify = False
        elif cacert := os.getenv('VAULT_CACERT', None):
            self.vault_verify = cacert
        elif capath := os.getenv('VAULT_CAPATH', None):
            self.vault_verify = capath
        else:
            self.vault_verify = True
            
        if 'vault_key_name' in self._kwargs:
            self.vault_key_name = self._kwargs['vault_key_name']
            del self._kwargs['vault_key_name']

        # __init__(url=None, token=None, cert=None, verify=None, timeout=30, proxies=None, allow_redirects=True, session=None, adapter=<class 'hvac.adapters.JSONAdapter'>, namespace=None, **kwargs)
        logger.error("Verify is {}".format(self.vault_verify))
        self._client = hvac.Client(self.vault_addr, verify=self.vault_verify)
        if self._client.sys.is_sealed():
            raise NotImplementedError("Vault is sealed")

        # On Windows, token is stored in %USERPROFILE%\.vault-token
        # La forma correcta es usar:
        # os.path.join(os.path.expanduser('~'), '.vault-token')
        if self.vault_auth == 'token':
            if not self._vault_token:
                # Try the environment variable
                self._vault_token = os.getenv('VAULT_TOKEN', None)
            if not self._vault_token:
                # Try to read it from file
                token_path = os.path.join(os.path.expanduser('~'), '.vault-token')
                if os.path.exists(token_path):
                    self._vault_token = open(token_path, 'r').readline()

            if not self._vault_token:
                raise ValueError('No token value found for token authentication')
            self._client.token = self._vault_token
        
    def get_public_key(self):
        logger.error("Getting Vault public key")
        if len(self.certificates) > 0:
            # There are certificates, the first onw is assumed to be
            # the one matcching the private key
            return self.certificates[0].public_key()
        else:
            res = self._client.secrets.transit.read_key(name=self.vault_key_name, mount_point=self.mount_point)
            try:
                latest_version = res['data']['latest_version']
                public_key_pem = res['data']['keys'][str(latest_version)]['public_key'].encode('ascii')
                public_key = serialization.load_pem_public_key(public_key_pem)
                return public_key
            except:
                logger.error(f"Bad answer from Vault getting public key: {res}")
                raise
        
    def sign(self, data, padding=None, hash_algorithm_name='', preshared=False):
        hash_algorithm = algorithm_name_table[hash_algorithm_name]
        signature_algorithm = padding_name_table[padding.name]

        res = self._client.secrets.transit.sign_data(
            name=self.vault_key_name,
            mount_point=self.mount_point,
            hash_input=b64encode(data).decode('ascii'),
            hash_algorithm=hash_algorithm,
            signature_algorithm=signature_algorithm)

        logger.error("Signature result: {}".format(res))
        sig = b64decode(res['data']['signature'].replace('vault:v1:', ''))
        return sig
