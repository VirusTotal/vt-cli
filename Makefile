# This how we want to name the binary output
BINARY=./build/vt

# These are the value we want to pass for VERSION
VERSION=`git describe`

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS=-ldflags "-X github.com/VirusTotal/vt-cli/cmd.Version=${VERSION}"

# Builds the project
build:
	go build ${LDFLAGS} -o ${BINARY} ./vt/main.go

# Installs our project: copies binaries
install:
	go install ${LDFLAGS} github.com/VirusTotal/vt-cli/vt

# Build the project for multiple architectures
all:
	gox ${LDFLAGS} -osarch="linux/amd64 windows/amd64 darwin/amd64" -output "build/{{.OS}}/{{.Arch}}/{{.Dir}}" github.com/VirusTotal/vt-cli/vt

# Cleans our project: deletes binaries
clean:
	rm -rf ./build

.PHONY: clean install
