# Debian package of fobots.
#   make          builds dist/fobots_VERSION_all.deb
#   make VERSION=1.2.0 deb
#   make test     unit tests (standard library, python3 -m unittest)
#   make check    syntax + tests
#   make integration   real nft, fake logs, in a throwaway namespace (no root)
#   make lint     lintian on the package (if installed)
#   make clean

# Version: 0.N where N = number of commits (goes up with each commit); can be overridden.
COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION ?= 0.$(COUNT)
DEB     := dist/fobots_$(VERSION)_all.deb
SOURCES := fobots.py $(wildcard fobots/*.py) fobots.conf.example fobots.service.example README.md README.fr.md build-deb.sh

.PHONY: deb test check integration lint clean help
.DEFAULT_GOAL := deb

help:
	@sed -n '2,9p' Makefile

deb: $(DEB)

$(DEB): $(SOURCES)
	./build-deb.sh $(VERSION)

test:
	python3 -m unittest discover -s tests

check: test
	python3 -m py_compile fobots.py fobots/*.py
	sh -n build-deb.sh
	python3 fobots.py --help >/dev/null
	@rm -rf __pycache__

integration:
	bash tests/integration.sh

lint: $(DEB)
	lintian $(DEB)

clean:
	rm -rf build dist __pycache__ fobots/__pycache__ tests/__pycache__
