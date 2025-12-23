SITEMAP := sitemap.xml
MD_SOURCES := $(shell find . -name "*.md" -type f -not -path "./code/*")
MD_TARGETS := $(MD_SOURCES:.md=.html)
HTML_DEPS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Version and commit info from git (tags must exist)
COMMIT := $(shell git -C .. rev-parse --short HEAD)
LATEST_TAG := $(shell git -C .. describe --tags --abbrev=0)
PREV_TAG := $(shell git -C .. describe --tags --abbrev=0 $(LATEST_TAG)^ 2>/dev/null)

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone
markdown: $(MD_TARGETS)

# Mirror source code to versioned paths under /code/
# Creates: /code/main/<commit>/* and /code/<tag>/* for last 2 tags
mirror:
	rm -rf code
	mkdir -p code/main/$(COMMIT)
	for item in ../*; do \
		[ "$$(basename $$item)" != "docs" ] && cp -r "$$item" code/main/$(COMMIT)/; \
	done || true
	mkdir -p code/$(LATEST_TAG)
	cp -r code/main/$(COMMIT)/* code/$(LATEST_TAG)/
	@echo "Mirrored code to:"
	@echo "  - code/main/$(COMMIT)/"
	@echo "  - code/$(LATEST_TAG)/"
ifneq ($(PREV_TAG),)
	mkdir -p code/$(PREV_TAG)
	git -C .. archive $(PREV_TAG) | tar -x -C code/$(PREV_TAG)
	@echo "  - code/$(PREV_TAG)/"
endif

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
