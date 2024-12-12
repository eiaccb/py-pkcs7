#!/usr/bin/env python

import sys
import argparse
from datetime import datetime, timedelta
import hashlib
from binascii import unhexlify

from cryptography import x509, __version__ as cryptography_version
# from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import asn1

from signer_engine import SignerEngine, supported_hash_algorithms, get_hash_algorithm_class, get_digest_algorithm_oid

digest_algorithms_borrame = dict()

# MD2 never supported, as far as we know
if hasattr(hashes, 'MD2'):
    digest_algorithms_borrame['md2WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.2'),
        'hash_algorithm': hashes.MD2,
    }

# Cryptography 39.0.0 removed support for MD5 and SHA1 in some places
if hasattr(hashes, 'MD5'):
    digest_algorithms_borrame['md5WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.4'),
        'hash_algorithm': hashes.MD5,
    }

if hasattr(hashes, 'SHA1'):
    digest_algorithms_borrame['sha1WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.5'),
        'hash_algorithm': hashes.SHA1,
    }

if getattr(hashes, 'SHA256', None):
    digest_algorithms_borrame['sha256WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.11'),
        'hash_algorithm': hashes.SHA256,
    }

if hasattr(hashes, 'SHA384'):
    digest_algorithms_borrame['sha386WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.12'),
        'hash_algorithm': hashes.SHA384,
    }

if hasattr(hashes, 'SHA512'):
    digest_algorithms_borrame['sha512WithRSAEncryption'] = {
        'key_type': rsa.RSAPublicKey,
        'oid': x509.ObjectIdentifier('1.2.840.113549.1.1.13'),
        'hash_algorithm': hashes.SHA512,
    }

def key2id(key):
    key_blob = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1)
    id = hashlib.sha1(key_blob).digest()
    return id

def key_usage(usage_list):
    key_usages = {
        'digital_signature': False,
        'content_commitment': False,
        'key_encipherment': False,
        'data_encipherment': False,
        'key_agreement': False,
        'key_cert_sign': False,
        'crl_sign': False,
        'encipher_only': False,
        'decipher_only': False,
    }

    for usage in usage_list:
        if usage in key_usages:
            key_usages[usage] = True
        else:
            raise KeyError("Invalid usage {}".format(usage))

    return x509.KeyUsage(
        key_usages['digital_signature'],
        key_usages['content_commitment'],
        key_usages['key_encipherment'],
        key_usages['data_encipherment'],
        key_usages['key_agreement'],
        key_usages['key_cert_sign'],
        key_usages['crl_sign'],
        key_usages['encipher_only'],
        key_usages['decipher_only'],
    )

def build_cert(signer_engine, hash_algorithm_name, subject_name, duration, ca=False, code_signing=False):

    public_key = signer_engine.get_public_key()
    hash_algorithm = get_hash_algorithm_class(hash_algorithm_name)()
          
    builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        subject_name
    ).not_valid_before(
        datetime.now()
    ).not_valid_after(
        datetime.now() + duration
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        public_key
    )

    key_usages = set()
    extended_key_usages = []
    application_cert_policies = []

    # Microsoft adds this, it contains a GUID for template used
    # builder.add_extension(
    #     x509.UnrecognizedExtension(
    #         x509.ObjectIdentifier('1.3.6.1.4.1.311.21.7'),
    #         b'aaaaa'),
    #    critical= False)

    if code_signing:
        key_usages.add('digital_signature')
        extended_key_usages.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

        # Added by some certificates for code signing created by Microsoft
        # Certificate Services, but selfcert.exe does not create include it
        # and our tests work without it. We leave here for documentation.

        application_cert_policies.append(x509.oid.ExtendedKeyUsageOID.CODE_SIGNING)

    if len(extended_key_usages) > 0:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usages),
            critical=False
        )

    if len(key_usages) > 0:
        builder = builder.add_extension(
            key_usage(key_usages),
            critical=False
        )

    if len(application_cert_policies) > 0:
        # XCN_OID_APPLICATION_CERT_POLICIES (1.3.6.1.4.1.311.21.10)
        # It is:
        # SEQUENCE (
        #   SEQUENCE (
        #     "1.3.6.1.5.5.7.3.3" (i.e. the ExtendedKeyUsage CODE_SIGNING
        # ))
        # Actually, a stub implementation. The list of policies should
        # be serialized. We don't know yet whether they become additional
        # SEQUENCEs in the outer SEQUENCE or they get just added to the
        # inner SEQUENCE
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier('1.3.6.1.4.1.311.21.10'),
                unhexlify('300C300A06082B06010505070303'),
            ),
            critical=False
        )                               

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier(key2id(public_key)), critical=False)

    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True,
        )

    # Now we generate a random temporary key pair with similar parameters
    temp_key = rsa.generate_private_key(
            public_exponent=public_key.public_numbers().e,
            key_size=public_key.key_size)

    # algorithm is None for some key types, a HashAlgorithm otherwise
    # rsa_padding is None if not RSA
    # If RSA, it can be PKCS1v15 or PSS; defaults to PKCS1v15
    # PKCS1v15 no longer recommended, use PSS if possible for signatures
    # (OAEP is for encryption)
    # PSS needs (mgf=MGF1, salt_length in PSS.DIGEST_LENGTH or PSS.MAX_LENGTH)
    # MGF1 is (algorithm) a HashAlgorithm
    # Should we get from the signer?
    fake_cert = builder.sign(
        private_key=temp_key,
        algorithm=hash_algorithm)

    # Now we extract the tbsCertificate part of the certificate
    tbsCertificate = fake_cert.tbs_certificate_bytes

    # And now we build the real certificate
    # and sign its relevant part with the signer_engine

    # This part is needed because of the way the asn1 module works,
    # we first need to extract the bytes of the 
    decoder = asn1.Decoder()
    decoder.start(tbsCertificate)
    tag, c_val = decoder.read()

    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence) # Certificate
    # tbsCertificate
    encoder.write(c_val, asn1.Numbers.Sequence, asn1.Types.Constructed)

    # signatureAlgorithm
    encoder.enter(asn1.Numbers.Sequence)     #
    algorithm_oid = get_digest_algorithm_oid(public_key, hash_algorithm_name)
    encoder.write(
        algorithm_oid.dotted_string,
        asn1.Numbers.ObjectIdentifier)
    encoder.write('', asn1.Numbers.Null) # parameters
    encoder.leave()

    # TBC: digest_algorithm antes es un encryption
    # Aquí viene a ser el simple hash
    sig = signer_engine.sign(tbsCertificate, padding=padding.PKCS1v15(), hash_algorithm_name=hash_algorithm_name)

    encoder.write(sig, asn1.Numbers.BitString)

    encoder.leave()         # Certificate

    encoded_bytes = encoder.output()

    # Now verify:
    cert = x509.load_der_x509_certificate(encoded_bytes)

    return cert

def main():
    
    parser = argparse.ArgumentParser(
        description="Generate a self-signed certificate using a signer engine",
    )

    parser.add_argument('subject',
                        type=str,
                        metavar='<subject-dn>',
                        help='Certificate subject',
                        )

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Show debug information',
                        )

    parser.add_argument('-D', '--duration',
                        type=int,
                        metavar='<days>',
                        default='365',
                        help='Certificate validity in days',
                        )

    parser.add_argument('--hash-algorithm',
                        type=str,
                        choices=supported_hash_algorithms,
                        default='sha256',
                        )
    
    parser.add_argument('-c', '--code-signing',
                        action='store_true',
                        help='Enabled for code signing',
                        )

    parser.add_argument('-C', '--ca',
                        action='store_true',
                        help='Enabled for issuing other certificates',
                        )

    parser.add_argument('-E', '--engine-type',
                        type=str,
                        metavar='<engine-type>',
                        default='file',
                        help='Signer engine type',
                        )

    parser.add_argument('-k', '--private-key',
                        type=str,
                        metavar='<path>',
                        help='Path to private key',
                        )

    parser.add_argument('--vault-addr',
                        type=str,
                        metavar='<url>',
                        default=None,
                        help='Path to transit key in vault',
                        )
    
    parser.add_argument('--vault-skip-verify',
                        action='store_true',
                        help='Do not verify vault server certificate (only for testing!!!)',
                        )
    
    parser.add_argument('--vault-cacert',
                        type=str,
                        metavar='<path-to-bundle>',
                        help='Path to certificate bundle to validate vault server certificate',
                        )
    
    parser.add_argument('--vault-capath',
                        type=str,
                        metavar='<path-to-dir>',
                        help='Path to directory containing root certificates to  validate vault server certificate',
                        )
    
    parser.add_argument('--vault-auth-method',
                        type=str,
                        metavar='<method>',
                        default='token',
                        help='How to authenticate against Vault (defaults to token)',
                        )
    
    parser.add_argument('--vault-key',
                        type=str,
                        metavar='<keyname>',
                        help='Name of key in vault transit backend',
                        )
    
    parser.add_argument('-o', '-out', '--output',
                        type=str,
                        metavar='<path>',
                        help='Path to output certificate',
                        )

    args = parser.parse_args()

    if args.debug:
        logger.parent.setLevel(logging.DEBUG)

    output_filename = args.output

    subject_name = x509.Name.from_rfc4514_string(args.subject)
    # Olde versions did not reverse the RDNs as required
    if cryptography_version < '38.0.0':
        subject_name = x509.Name.from_rfc4514_string(subject_name.rfc4514_string())

    if args.engine_type == 'file':
        if not args.private_key:
            print("Se precisa indicar clave privada")
            return
        signer_engine = SignerEngine.create_signer_engine('PrivateKeyFile', private_key_path=args.private_key)
    elif args.engine_type == 'vault':
        if args.vault_skip_verify:
            verify = False
        elif args.vault_cacert:
            verify = args.vault_cacert
        elif args.vault_capath:
            verify = args.vault_capath
        else:
            # False would prevent defaulting to environment variables
            verify = None

        signer_engine = SignerEngine.create_signer_engine(
            'HashicorpVaultTransit',
            vault_addr=args.vault_addr,
            vault_verify=verify,
            vault_auth=args.vault_auth_method,
            vault_key_name=args.vault_key,
        )
    
    else:
        print("Invalid signer type: {}".format(args.engine_type))
        return

    cert = build_cert(
        signer_engine,
        hash_algorithm_name=args.hash_algorithm,
        subject_name=subject_name,
        duration=timedelta(days=args.duration),
        ca=args.ca,
        code_signing=args.code_signing,
    )
    
    if output_filename:
        with open(output_filename, 'wb') as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
    else:
        sys.stdout.write(cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf8'))

main()
