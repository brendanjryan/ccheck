default: build

 vet:
	go vet .

 build:
	go build .

 test:
	go test ./...


