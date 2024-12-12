# py-pkcs7
Support in python for reading and writing PKCS7 files

Support in pyca for PKCS#7 files is very incomplete. In particular, there is not support for signatures or encryption.

There are scenarios where this support would be helpful:

- Producing signatures using keys stored in Hashicorp Vault
- Producing signatures for MS Office macros

The software in this repository provides low-level support used by repository vbaProject-sign. It has been kept unbundled because it mey be useful in other contexts.

Greatly improved versions of signer_engine.py and vault_signer_engine are included derived from those in the sibling project vbaProject-sign. 

Example of creating a self-signed certificate for code signing from a key stored in a transit key named 'code-signing' in Hashicorp Vault:

./create_self_signed.py -E vault 'CN=code-signing,DC=example,DC=org' -k ../../mkcerts/ccn-cert-2024.key --code-signing --vault-key code-signing -o code-signing-cert.pem

Only token authentication is supported for now, that will be taken from the
usual ~/.vault-token place if not given otherwise.

The code honors the cli environment variables VAULT_ADDR, VAULT_CAPATH and
some other, including VAULT_SKIP_VERIFY that should be used very sparingly
and only for testing.

