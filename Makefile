EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?= 

DOCKER_REPO   := cloudflare/
OCTORPKI_NAME    := octorpki
OCTORPKI_VERSION := $(shell git describe --tags $(git rev-list --tags --max-count=1))
VERSION_PKG   := $(shell echo $(OCTORPKI_VERSION) | sed 's/^v//g')
ARCH          := x86_64
LICENSE       := BSD-3
URL           := https://github.com/cloudflare/octorpki
DESCRIPTION   := OctoRPKI: a RPKI validator
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       := '-X main.version=$(OCTORPKI_VERSION) -X main.buildinfos=$(BUILDINFOS)'

OUTPUT_OCTORPKI := $(DIST_DIR)octorpki-$(OCTORPKI_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: vet
vet:
	go vet -v ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: build-octorpki
build-octorpki: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_OCTORPKI) cmd/octorpki/octorpki.go 

.PHONY: docker-octorpki
docker-octorpki:
	docker build -t $(DOCKER_REPO)$(OCTORPKI_NAME):$(OCTORPKI_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile .

.PHONY: package-deb-octorpki
package-deb-octorpki: prepare
	fpm -s dir -t deb -n $(OCTORPKI_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
       	--deb-no-default-config-files \
        --package $(DIST_DIR) \
        $(OUTPUT_OCTORPKI)=/usr/bin/octorpki \
        package/octorpki.service=/lib/systemd/system/octorpki.service \
        package/octorpki.env=/etc/default/octorpki \
        cmd/octorpki/tals/afrinic.tal=/usr/share/octorpki/tals/afrinic.tal \
        cmd/octorpki/tals/apnic.tal=/usr/share/octorpki/tals/apnic.tal \
        cmd/octorpki/tals/lacnic.tal=/usr/share/octorpki/tals/lacnic.tal \
        cmd/octorpki/tals/ripe.tal=/usr/share/octorpki/tals/ripe.tal

.PHONY: package-rpm-octorpki
package-rpm-octorpki: prepare
	fpm -s dir -t rpm -n $(OCTORPKI_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_OCTORPKI)=/usr/bin/octorpki \
        package/octorpki.service=/lib/systemd/system/octorpki.service \
        package/octorpki.env=/etc/default/octorpki \
        cmd/octorpki/tals/afrinic.tal=/usr/share/octorpki/tals/afrinic.tal \
        cmd/octorpki/tals/apnic.tal=/usr/share/octorpki/tals/apnic.tal \
        cmd/octorpki/tals/lacnic.tal=/usr/share/octorpki/tals/lacnic.tal \
        cmd/octorpki/tals/ripe.tal=/usr/share/octorpki/tals/ripe.tal