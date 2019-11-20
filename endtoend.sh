#!/bin/bash
set -euf -o pipefail

PACKAGE_ROOT="github.com/evanj/go-tls-example"

# generate the keys
echo "*** generating keys ..."
cat > ca_config.cnf <<HERE
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
# empty; see
# https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045

[v3_ca_config]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
HERE

openssl ecparam -genkey -out cakey.pem -name prime256v1
openssl req -new -x509 -sha256 -key cakey.pem -out cacert.pem -config ca_config.cnf -extensions v3_ca_config -days 3650 -subj "/O=Example Inc/CN=Example Inc Root CA" 

openssl ecparam -genkey -out serverkey.pem -name prime256v1
openssl req -new -sha256 -key serverkey.pem -out serverkey.csr -days 1095 -subj "/O=Example Inc/CN=localhost"
openssl x509 -req -in serverkey.csr -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out servercert.pem -days 1095

# build and run the end-to-end test!
echo "*** building and running test ..."
go build -o echoclient-bin ${PACKAGE_ROOT}/echoclient
go build -o echoserver-bin ${PACKAGE_ROOT}/echoserver 
go run ${PACKAGE_ROOT}/endtoend --echoclientPath=./echoclient-bin --echoserverPath=./echoserver-bin \
  --serverCertPath=servercert.pem --serverKeyPath=serverkey.pem

