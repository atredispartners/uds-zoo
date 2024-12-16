#!/bin/sh

# start the controller first
cd cmd/controller
go mod download github.com/tidwall/buntdb
go get github.com/tidwall/buntdb@v1.2.9
go build

# delete the data.db if it exists
rm data.db
sh -c ./controller &
cd ../../

# ensure the controller is running and listening
./scripts/wait-for-it.sh localhost:8888 -q

# fire up the levels
find ./examples -name 'main.go' | xargs -n1 -I_main -- sh -c 'go run _main &'
wait
