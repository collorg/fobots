# Paquet Debian de fobots.
#   make          construit dist/fobots_VERSION_all.deb
#   make VERSION=1.2.0 deb
#   make test     tests unitaires (bibliothèque standard, python3 -m unittest)
#   make check    syntaxe + tests
#   make lint     lintian sur le paquet (si installé)
#   make clean

# Version : 0.N où N = nombre de commits (monte à chaque commit) ; surchargeable.
COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION ?= 0.$(COUNT)
DEB     := dist/fobots_$(VERSION)_all.deb
SOURCES := fobots.py fobots.conf.example fobots.service.example README.md README.fr.md build-deb.sh

.PHONY: deb test check lint clean help
.DEFAULT_GOAL := deb

help:
	@sed -n '2,8p' Makefile

deb: $(DEB)

$(DEB): $(SOURCES)
	./build-deb.sh $(VERSION)

test:
	python3 -m unittest discover -s tests

check: test
	python3 -m py_compile fobots.py
	sh -n build-deb.sh
	python3 fobots.py --help >/dev/null
	@rm -rf __pycache__

lint: $(DEB)
	lintian $(DEB)

clean:
	rm -rf build dist __pycache__
