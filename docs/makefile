SITEMAP := sitemap.xml
MD_SOURCES := $(shell find . -name "*.md" -type f)
MD_TARGETS := $(MD_SOURCES:.md=.html)
HTML_DEPS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone

all: $(MD_TARGETS) $(SITEMAP)

$(SITEMAP): generate_sitemap.py $(MD_TARGETS) $(HTML_DEPS)
	python3 generate_sitemap.py

clean:
	rm -f $(MD_TARGETS) $(SITEMAP)

# Mirror source code to /code/
mirror:
	rm -rf code
	cp -r .. code
	rm -rf code/.git code/target code/docs/code
	find code -name '.DS_Store' -delete 2>/dev/null || true
	find code -name '*.swp' -delete 2>/dev/null || true
	find code -name '.vscode' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -name '.idea' -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf code/examples/flood/assets
	find code -path '*/fuzz/artifacts' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -path '*/fuzz/corpus' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -path '*/fuzz/coverage' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -path '*/fuzz/target' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -name '_apalache-out' -type d -exec rm -rf {} + 2>/dev/null || true
	find code -type d -name 'out*' -path '*/quint/*' -exec rm -rf {} + 2>/dev/null || true

# So that make doesn't think the above two are directories
.PHONY: all clean mirror
