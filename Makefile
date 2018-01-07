GOPATH ?= $(shell pwd)
export GOPATH

GOBIN ?= $(shell pwd)
LDFLAGS:= -w

PACKAGE=stash.corp.netflix.com/ps/vssm

build: generate scrypt.bin bootstrapper.bin $(GOPATH)/src/$(PACKAGE)
	cd $(GOPATH)/src/$(PACKAGE) && go build

scrypt.bin:
	cd $(GOPATH)/src/$(PACKAGE)/scrypt && go build -o ../scrypt.bin

bootstrapper.bin:
	cd $(GOPATH)/src/$(PACKAGE)/bootstrapper && go build -o ../bootstrapper.bin

generate: $(GOPATH)/src/$(PACKAGE)
	mkdir -p build
	go build -o build/protoc-gen-go $(PACKAGE)/vendor/github.com/golang/protobuf/protoc-gen-go
	test -L src/$(PACKAGE) || ln -sf ../../.. src/$(PACKAGE)
	protoc --plugin=build/protoc-gen-go --go_out=plugins=grpc:src -I ./ ./vssm.proto ./internal.proto ./bootstrap.proto

$(GOPATH)/src/%:
	mkdir -p $(@D)
	test -L $@ || ln -sf ../../.. $@

fmt:
	gofmt -s -w *.go awsprov/*.go bootstrapper/*.go cloud/*.go logging/*.go scryptlib/*.go

test:
	cd $(GOPATH)/src/$(PACKAGE) && go test -v
	cd $(GOPATH)/src/$(PACKAGE)/awsprov && go test -v
	cd $(GOPATH)/src/$(PACKAGE)/logging && go test -v
	cd $(GOPATH)/src/$(PACKAGE)/scryptlib && go test -v

clean:
	rm -rf pkg dist bin src ./$(NAME)
