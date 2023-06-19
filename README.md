# Https Reverse Proxy
## Generate self-signed CA
```shell
# generate private key using RSA 2048 bit
openssl genrsa -out ca.key 2048
# generate certificate using the private key
# PLEASE DON'T FILL EMAIL
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt
# extract pkcs8 format key from the private key
openssl pkcs8 -in ca.key -topk8 -nocrypt -out ca.pkcs8
```