SITEMAP := sitemap.xml
MD_SOURCES := $(shell find . -name "*.md" -type f -not -path "./code/*")
MD_TARGETS := $(MD_SOURCES:.md=.html)
HTML_DEPS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Version and commit info
VERSION := $(shell grep -m1 '^version' ../Cargo.toml | sed 's/.*"\(.*\)"/\1/')
COMMIT := $(shell git -C .. rev-parse --short HEAD)

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone
markdown: $(MD_TARGETS)

# Mirror source code to versioned paths under /code/
# Creates: /code/main/<commit>/* and /code/v<version>/*
mirror:
	rm -rf code
	mkdir -p code/main/$(COMMIT)
	mkdir -p code/v$(VERSION)
	for item in ../*; do \
		[ "$$(basename $$item)" != "docs" ] && cp -r "$$item" code/main/$(COMMIT)/; \
	done || true
	cp -r code/main/$(COMMIT)/* code/v$(VERSION)/
	@echo "Mirrored code to:"
	@echo "  - code/main/$(COMMIT)/"
	@echo "  - code/v$(VERSION)/"

# Generate sitemap
sitemap:
	python3 generate_sitemap.py

# Deploy: mirror code and generate sitemap
deploy: mirror sitemap

# Build everything: markdown, mirror, and sitemap
all: markdown mirror sitemap

# Clean all generated files
clean:
	rm -rf code $(MD_TARGETS) $(SITEMAP)

.PHONY: markdown mirror sitemap deploy all clean
