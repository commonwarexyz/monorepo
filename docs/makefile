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
	mkdir -p code
	rsync -av --progress ../ code/ \
		--exclude='.git' \
		--exclude='target' \
		--exclude='.DS_Store' \
		--exclude='*.swp' \
		--exclude='.vscode' \
		--exclude='.idea' \
		--exclude='examples/flood/assets' \
		--exclude='*/fuzz/artifacts' \
		--exclude='*/fuzz/corpus' \
		--exclude='*/fuzz/coverage' \
		--exclude='*/fuzz/target' \
		--exclude='**/quint/_apalache-out/' \
		--exclude='**/quint/out*/' \
		--exclude='docs/code'

# So that make doesn't think the above two are directories
.PHONY: all clean mirror
