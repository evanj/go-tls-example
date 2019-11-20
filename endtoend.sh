#!/bin/bash
set -euf -o pipefail

PACKAGE_ROOT="github.com/evanj/go-tls-example"

go build -o echoclient-bin ${PACKAGE_ROOT}/echoclient
go build -o echoserver-bin ${PACKAGE_ROOT}/echoserver 
go run ${PACKAGE_ROOT}/endtoend --echoclientPath=./echoclient-bin --echoserverPath=./echoserver-bin
