
SERVER_SOURCE=cmd/server/chaserv.go
CLIENT_SOURCE=cmd/shell/chashell.go
LDFLAGS="-X main.targetDomain=$(DOMAIN_NAME) -X main.encryptionKey=$(ENCRYPTION_KEY) -s -w"
GCFLAGS="all=-trimpath=$GOPATH"

CLIENT_BINARY=chashell
SERVER_BINARY=chaserv

OSARCH = "linux/amd64 linux/386 linux/arm windows/amd64 windows/386 darwin/amd64 darwin/386"

check-env:
ifndef DOMAIN_NAME
	$(error DOMAIN_NAME is undefined)
endif
ifndef ENCRYPTION_KEY
	$(error ENCRYPTION_KEY is undefined)
endif

dep: check-env
	go get -v -u github.com/golang/dep/cmd/dep && \
	go get github.com/mitchellh/gox

build: check-env
	dep ensure && \
	go build $(LDFLAGS) -o bin/$(CLIENT_BINARY) $(CLIENT_SOURCE) && \
	go build $(LDFLAGS) -o bin/$(SERVER_BINARY) $(SERVER_SOURCE)

build-all: check-env
	echo "Building server"
	gox -osarch=$(OSARCH) -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -output "release/chaserv_{{.OS}}_{{.Arch}}" ./cmd/server
	echo "Building shell"
	gox -osarch=$(OSARCH) -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -output "release/chashell_{{.OS}}_{{.Arch}}" ./cmd/shell
