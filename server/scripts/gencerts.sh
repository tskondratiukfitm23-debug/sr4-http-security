#!/usr/bin/env bash
# Локальний CA + серверний сертифікат з SAN (localhost, 127.0.0.1)
set -euo pipefail
mkdir -p server/certs
cd server/certs
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=KUBG-Demo-CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 398 -sha256 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null
chmod 600 ca.key server.key
echo "Certificates in server/certs (use --cacert server/certs/ca.crt)"
