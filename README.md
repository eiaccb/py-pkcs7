# py-pkcs7
Support in python for reading and writing PKCS7 files

Support in pyca for PKCS#7 files is very incomplete. In particular, there is not support for signatures or encryption.

There are scenarios where this support would be helpful:

- Producing signatures using keys stored in Hashicorp Vault
- Producing signatures for MS Office macros

The software in this repository provides low-level support used by repository vbaProject-sign. It has been kept unbundled because it mey be useful in other contexts.
