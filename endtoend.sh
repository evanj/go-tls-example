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

openssl ecparam -genkey -name prime256v1 -out cakey.pem
openssl req -new -x509 -key cakey.pem -config ca_config.cnf -extensions v3_ca_config -days 3650 -sha256 -subj "/O=Example Inc/CN=Example Inc Root CA" -out cacert.pem

openssl ecparam -genkey -name prime256v1 -out serverkey.pem
openssl req -new -subj "/O=Example Inc/CN=localhost" -key serverkey.pem -out serverkey.csr
openssl x509 -req -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 1095 -sha256 -in serverkey.csr -out servercert.pem

openssl ecparam -genkey -name prime256v1 -out clientkey.pem 
openssl req -new -subj "/O=Example Inc/CN=clientcert.example.com" -key clientkey.pem -out clientkey.csr
openssl x509 -req -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 1095 -sha256 -in clientkey.csr -out clientcert.pem


# build and run the end-to-end test!
echo "*** building and running test ..."
go build -o echoclient-bin ${PACKAGE_ROOT}/echoclient
go build -o echoserver-bin ${PACKAGE_ROOT}/echoserver 
go run ${PACKAGE_ROOT}/endtoend --echoclientPath=./echoclient-bin --echoserverPath=./echoserver-bin \
  --serverCertPath=servercert.pem --serverKeyPath=serverkey.pem \
  --caCertPath=cacert.pem \
  --clientCertPath=clientcert.pem --clientKeyPath=clientkey.pem
