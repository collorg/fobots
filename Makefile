# Debian package of fobots.
#   make          cleans, then builds dist/fobots_VERSION_all.deb
#   make VERSION=1.2.0 deb
#   make test     unit tests (standard library, python3 -m unittest)
#   make check    syntax + tests
#   make integration   real nft, fake logs, in a throwaway namespace (no root)
#   make upgrade  tests, builds the package and installs it (sudo); restarts a running service
#   make lint     lintian on the package (if installed)
#   make clean

# Version: 0.N where N = number of commits (goes up with each commit); can be overridden.
COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION ?= 0.$(COUNT)
DEB     := dist/fobots_$(VERSION)_all.deb
SUDO    := $(if $(filter 0,$(shell id -u)),,sudo)

.PHONY: deb upgrade test check integration lint clean help
.DEFAULT_GOAL := deb

help:
	@sed -n '2,10p' Makefile

# Always starts from a clean tree: no stale build/ nor old package left in dist/.
deb:
	$(MAKE) --no-print-directory clean
	./build-deb.sh $(VERSION)

# postinst restarts fobots.service if it is running (try-restart); a stopped one stays stopped.
upgrade: check deb
	$(SUDO) dpkg -i $(DEB)

test:
	python3 -m unittest discover -s tests

check: test
	python3 -m py_compile fobots.py fobots/*.py
	sh -n build-deb.sh
	python3 fobots.py --help >/dev/null
	@rm -rf __pycache__

integration:
	bash tests/integration.sh

lint: deb
	lintian $(DEB)

clean:
	rm -rf build dist __pycache__ fobots/__pycache__ tests/__pycache__
