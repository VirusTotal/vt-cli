# This how we want to name the binary output
BINARY=./build/vt

# Setup the -ldflags option for go build here, interpolate the variable values
LDFLAGS=-ldflags "-X github.com/VirusTotal/vt-cli/cmd.Version=${VERSION}"

# Builds the project
.PHONY: build
build:
	go build ${LDFLAGS} -o ${BINARY} ./vt/main.go

# Installs our project: copies binaries
.PHONY: install
install:
	go install ${LDFLAGS} github.com/VirusTotal/vt-cli/vt

# Build the project for multiple architectures
.PHONY: bins
bins:
	gox ${LDFLAGS} \
	-osarch="linux/amd64 linux/386 windows/amd64 windows/386 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/386" \
	-output "build/{{.OS}}/{{.Arch}}/{{.Dir}}" github.com/VirusTotal/vt-cli/vt

# Build a universal binary for macOS (combining amd64 and arm64)
.PHONY: all
all: bins
	@mkdir -p build/darwin/universal
	@if command -v lipo >/dev/null 2>&1; then \
		lipo -create -output build/darwin/universal/vt build/darwin/amd64/vt build/darwin/arm64/vt; \
	else \
		go run github.com/randall77/makefat@latest build/darwin/universal/vt build/darwin/amd64/vt build/darwin/arm64/vt; \
	fi

# Cleans our project: deletes binaries
.PHONY: clean
clean:
	rm -rf ./build
