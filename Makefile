GOPATH ?= $(shell pwd)
export GOPATH

GOBIN ?= $(shell pwd)
LDFLAGS:= -w

PACKAGE=stash.corp.netflix.com/ps/vssm

build: generate $(GOPATH)/src/$(PACKAGE)
	cd $(GOPATH)/src/$(PACKAGE) && go build

generate: $(GOPATH)/src/$(PACKAGE)
	mkdir -p build
	go build -o build/protoc-gen-go $(PACKAGE)/vendor/github.com/golang/protobuf/protoc-gen-go
	test -L src/$(PACKAGE) || ln -sf ../../.. src/$(PACKAGE)
	protoc --plugin=build/protoc-gen-go --go_out=plugins=grpc:src -I ./ ./vssm.proto ./internal.proto ./bootstrap.proto

$(GOPATH)/src/%:
	mkdir -p $(@D)
	test -L $@ || ln -sf ../../.. $@

fmt:
	gofmt -s -w *.go

clean:
	rm -rf pkg dist bin src ./$(NAME)
