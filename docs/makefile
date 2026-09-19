SITEMAP := sitemap.xml
RSS := rss.xml
MD_SOURCES := $(shell find . -name "*.md" -type f -not -path "./code/*")
MD_TARGETS := $(MD_SOURCES:.md=.html)
HTML_DEPS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --katex --standalone
markdown: $(MD_TARGETS)

# Mirror source code to versioned paths under /code/
# Creates: /code/<tag>/* for last 3 tags
# Fetches tags at runtime to support shallow clones
mirror:
	rm -rf code
	@# Fetch all tags (needed for shallow clones)
	git -C .. fetch origin 'refs/tags/*:refs/tags/*' --no-tags 2>/dev/null || true
	@# Get last 3 version tags sorted by version
	@TAGS=$$(git -C .. tag -l 'v*' --sort=-v:refname | head -3); \
	if [ -z "$$TAGS" ]; then \
		echo "Error: No version tags found"; \
		exit 1; \
	fi; \
	for tag in $$TAGS; do \
		echo "Fetching and mirroring $$tag..."; \
		git -C .. fetch origin tag $$tag --no-tags 2>/dev/null || true; \
		mkdir -p code/$$tag; \
		git -C .. archive $$tag | tar -x -C code/$$tag; \
		echo "  - code/$$tag/"; \
	done

# Generate sitemap
sitemap:
	python3 generate_sitemap.py

# Generate RSS feed for blog posts
rss:
	python3 generate_rss.py

# Deploy: mirror code and generate discovery files
deploy: mirror sitemap rss

# Build everything: markdown, mirror, sitemap, and RSS
all: markdown mirror sitemap rss

# Clean all generated files
clean:
	rm -rf code $(MD_TARGETS) $(SITEMAP) $(RSS)

.PHONY: markdown mirror sitemap rss deploy all clean
