GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BUILD_DIR=build/
SERVER_SOURCE=chaserv.go
CLIENT_SOURCE=chashell.go
LDFLAGS=--ldflags "-X main.targetDomain=$(DOMAIN_NAME) -X main.encryptionKey=$(ENCRYPTION_KEY)" -s -w -gcflags "all=-trimpath=$GOPATH"

CLIENT_BINARY=chashell
SERVER_BINARY=chaserv

PLATFORMS=darwin linux windows
ARCHITECTURES=386 amd64

default: build

all: clean build_all install

build:
	go build $(LDFLAGS) $(CLIENT_SOURCE) -o ${CLIENT_BINARY}
	go build $(LDFLAGS) $(SERVER_SOURCE) -o ${SERVER_BINARY}


build_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	go build $(LDFLAGS) -o release/$(CLIENT_BINARY)-$(GOOS)-$(GOARCH) $(CLIENT_SOURCE);\
	go build $(LDFLAGS) -o release/$(SERVER_BINARY)-$(GOOS)-$(GOARCH) $(SERVER_SOURCE))))

install:
	go install ${LDFLAGS}

# Remove only what we've created
clean:
	find ${ROOT_DIR} -name '${BINARY}[-?][a-zA-Z0-9]*[-?][a-zA-Z0-9]*' -delete

.PHONY: check clean install build_all all