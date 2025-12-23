SITEMAP := sitemap.xml
MD_SOURCES := $(shell find . -name "*.md" -type f -not -path "./code/*")
MD_TARGETS := $(MD_SOURCES:.md=.html)
HTML_DEPS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Fetch tags (needed for shallow clones like Cloudflare Pages)
FETCH_TAGS := $(shell git -C .. fetch --tags 2>/dev/null)

# Get last 3 version tags from git (at least one tag must exist)
TAG1 := $(shell git -C .. describe --tags --abbrev=0)
TAG2 := $(shell git -C .. describe --tags --abbrev=0 $(TAG1)^ 2>/dev/null)
TAG3 := $(shell git -C .. describe --tags --abbrev=0 $(TAG2)^ 2>/dev/null)

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone
markdown: $(MD_TARGETS)

# Mirror source code to versioned paths under /code/
# Creates: /code/<tag>/* for last 3 tags
mirror:
	rm -rf code
	mkdir -p code/$(TAG1)
	git -C .. archive $(TAG1) | tar -x -C code/$(TAG1)
	@echo "Mirrored code to:"
	@echo "  - code/$(TAG1)/"
ifneq ($(TAG2),)
	mkdir -p code/$(TAG2)
	git -C .. archive $(TAG2) | tar -x -C code/$(TAG2)
	@echo "  - code/$(TAG2)/"
endif
ifneq ($(TAG3),)
	mkdir -p code/$(TAG3)
	git -C .. archive $(TAG3) | tar -x -C code/$(TAG3)
	@echo "  - code/$(TAG3)/"
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
