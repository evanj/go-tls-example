#!/bin/bassh
# Runs checks on CircleCI
set -euf -o pipefail

# Run tests!
go test -mod=readonly -race ./...

# go test only checks some vet warnings; check all
go vet -mod=readonly ./...

# Run golint on everything
go get -mod=readonly golang.org/x/lint/golint
golint --set_exit_status ./...

echo "=== STARTING END TO END TEST ==="
./endtoend.sh
echo "=== END TO END SUCCESS ==="

# run go fmt on all code: a later check will fail if there are diffs
go fmt ./...

# require that we use go mod tidy. TODO: is there a better way?
go mod tidy

# check for any diffs with fmt and go mod tidy
CHANGED=$(git status --porcelain --untracked-files=no)
if [ -n "${CHANGED}" ]; then
    echo "ERROR files were changed:" > /dev/stderr
    echo "$CHANGED" > /dev/stderr
    exit 10
fi
