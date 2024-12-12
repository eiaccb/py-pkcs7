
import logging
logger = logging.getLogger(__name__)

import sys
import getpass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

potential_hash_algorithms = [
    # MD2 never supported, as far as we know
    ('MD2', '1.2.840.113549.2.2'),
    # Cryptography 39.0.0 removed support for MD5 and SHA1 in some places
    ('MD5', '1.2.840.113549.2.5'),
    ('SHA1', '1.3.14.3.2.26'),
    ('SHA256', '2.16.840.1.101.3.4.2.1'),
    ('SHA384', '2.16.840.1.101.3.4.2.2'),
    ('SHA512', '2.16.840.1.101.3.4.2.3'),
    
]

hash_algorithms = {}

for name, oid_string in potential_hash_algorithms:
    if hasattr(hashes, name):
        supported = True
    else:
        supported = False
    hash_algorithms[name.lower()] = {
        'oid_string': oid_string,
        'supported': supported,
    }

def get_hash_algorithm_oid(name):
    return x509.ObjectIdentifier(hash_algorithms[name.lower()].oid_string)

def get_hash_algorithm_class(name):
    if not hash_algorithms[name.lower()]['supported']:
        raise NotImplementedError("The current platform does not implement algorithm {}".format(name.upper()))
    return getattr(hashes, name.upper())

supported_hash_algorithms = hash_algorithms.keys()

digest_algorithms = dict()

digest_algorithms['rsa'] = {

    'md2': {
        'name': 'md2WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.2'),
        },
    'md5': {
        'name': 'md5WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.4'),
        },
    'sha1': {
        'name': 'sha1WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.5'),
        },
    'sha256': {
        'name': 'sha256WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.11'),
        },
    'sha384': {
        'name': 'sha384WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.12'),
    },
    'sha512': {
        'name': 'sha512WithRSAEncryption¡',
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.13'),
    },
}

def get_digest_algorithm_oid(key, hash_algorithm):
    if isinstance(key, rsa.RSAPublicKey):
        try:
            oid = digest_algorithms['rsa'][hash_algorithm.lower()]['oid']
        except KeyError:
            raise NotImplementedError("Hash algorithm {} cannot be used with an RSA key")
    else:
        raise NotImplementedError("Unsupported key type {}".format(type(key)))
    return oid
    
def oid2DigestAlgorithm(digestAlgorithm):
    if isinstance(digestAlgorithm, str):
        oid = digestAlgorithm
    elif isinstance(digestAlgorithm, x509.ObjectIdentifier):
        oid = digestAlgorithm.dotted_string
    else:
        oid = digestAlgorithm.algorithm.dotted_string
    if oid == '1.2.840.113549.2.5':
        return hashes.MD5()
    elif oid == '2.16.840.1.101.3.4.2.1':
        return hashes.SHA256()
    elif oid == '2.16.840.1.101.3.4.2.3':
        return hashes.SHA512()
    else:
        raise ValueError('Unknown algorithm %s' % digestAlgorithm)

class SignerEngine:
    
    # def __init__(self, certificates=[], padding=padding.PKCS1v15(), digest_algorithm=SHA512_OID):
    def __init__(self, *args, **kwargs):
        self.certificates = []
        self.padding = padding.PKCS1v15()
        self.digest_algorithm = 'SHA512_OID'

        if len(args) >= 3:
            self.digest_algorithm = args[2]
        elif len(args) >= 2:
            self.padding = args[1]
        elif len(args) >= 1:
            self.certificates = args[0]
        cut = min(len(args), 3) - 1
        self._args = args[cut:]

        # Don't modify the received dict just in case
        self._kwargs = kwargs.copy()
        if 'certificates' in self._kwargs:
            self.certificates = self._kwargs['certificates']
            del self._kwargs['certificates']
        if 'padding' in self._kwargs:
            self.padding = self._kwargs['padding']
            del self._kwargs['padding']
        if 'digest_algorithm' in self._kwargs:
            self.digest_algorithm = self._kwargs['digest_algorithm']
            del self._kwargs['digest_algorithm']

    def set_padding(self, padding):
        self.padding = padding

    def set_digest_algorithm(self, digest_algorithm):
        if not isinstance(digest_algorithm, x509.ObjectIdentifier):
            raise TypeError("x509.ObjectIdentifier required, received {}".format(type(digest_algorithm)))

        self.digest_algorithm = digest_algorithm
        
    def sign(self, data):
        raise NotImplementedError

    # A factory method
    @classmethod
    def create_signer_engine(cls, *args, **kwargs):
        print(args)
        print(kwargs)
        signer_engine_type = None
        if len(args) > 0:
            signer_engine_type = args[0]
            args = args[1:]
        elif 'signer_engine_type' in kwargs:
            signer_engine_type = kwargs['signer_engine_type']
            del kwargs['signer_engine_type']
        else:
            raise ValueError('Type of singer engine could not be determined')

        if signer_engine_type == 'PrivateKeyFile':
            return PrivateKeySignerEngine(*args, **kwargs)
        elif signer_engine_type == 'HashicorpVaultTransit':
            import vault_signer_engine
            return vault_signer_engine.VaultSignerEngine(*args, **kwargs)
        else:
            raise ValueError("Invalid engine type {}".format(signer_engine_type))
       
class PrivateKeySignerEngine(SignerEngine):

    # def __init__(self, private_key=None, certificates=[]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.private_key_path = None
        self.private_key_password = None
        self.private_key = None

        if len(self._args) >= 2:
            raise ValueError("Extra unknown arguments")
        elif len(self._args) >= 1:
            self.private_key = self._args[0]

        if 'private_key' in self._kwargs:
            self.private_key = self._kwargs['private_key']
            del self._kwargs['private_key']

        if 'private_key_path' in self._kwargs:
            self.private_key_path = self._kwargs['private_key_path']

        if 'private_key_password' in self._kwargs:
            self.private_key_password = self._kwargs['private_key_password']

        # What if it is subclasssed. Work backwords?

        if not self.private_key:
            if self.private_key_path:
                self.load_private_key(
                    private_key_path=self.private_key_path,
                    private_key_password=self.private_key_password,
                )

    def load_private_key(self, private_key_bytes=None, private_key_path=None, private_key_password=None):
        if not private_key_bytes:
            if private_key_path:
                private_key_bytes = open(private_key_path, 'rb').read()
            else:
                raise NotImplementedError("Needed data form private_key")

        if private_key_password:
            self.private_key = serialization.load_pem_private_key(private_key_bytes, private_key_password)
            return
        
        while True:
            password = getpass.getpass('Contraseña para la clave privada: ')
            if len(password):
                password = password.encode('utf8')
            else:
                password = None
            try:
                private_key = serialization.load_pem_private_key(private_key_bytes, password)
                break
            except TypeError:
                sys.stderr.write('La clave privada está protegida por contraseña\n')
            except ValueError:
                sys.stderr.write('La contraseña es incorrecta\n')
            continue

        self.private_key = private_key

    def get_public_key(self):
        return self.private_key.public_key()
    
    def sign(self, data, padding=None, hash_algorithm_name=None, prehashed=False):
        logger.debug("TBS: {}".format(data))

        if not padding:
            padding = self.padding

        if not hash_algorithm_name:
            hash_algorithm_name = self.hash_algorithm

        algorithm = get_hash_algorithm_class(hash_algorithm_name)()

        if prehashed:
            algorithm = Prehashed(algorithm)
        
        result = self.private_key.sign(
            data,
            padding=padding,
            algorithm=algorithm)
        return result

# Damn, Prehashed takes an argument!!!
# Notes:
# class Prehashed:
#     def __init__(self, algorithm: hashes.HashAlgorithm):
#        if not isinstance(algorithm, hashes.HashAlgorithm):
#             raise TypeError("Expected instance of HashAlgorithm.")
#
#        self._algorithm = algorithm
#        self._digest_size = algorithm.digest_size

#    @property
#    def digest_size(self) -> int:
#        return self._digest_size

# El problema es que ya no se soporta ni MD5 ni SHA1.

# Cómo firmar con clave privada?

# En vault tenemos:

# Note: using hash_algorithm=none requires setting prehashed=true and signature_algorithm=pkcs1v15. This generates a PKCSv1_5_NoOID signature rather than the PKCSv1_5_DERnull signature type usually created. See RFC 3447 Section 9.2.
# En la versión de cryptography que estamos usando aún funcionan
# MD5 y SHA1, aparentemente.

# El problema va a estar entonces en Vault, que ya no hace MD5.
# Bueno, quizá no pase nada.
