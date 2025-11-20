# Look into subdirectories for markdown files
SOURCES := $(shell find . -name "*.md" -type f)
# Replace .md with .html
TARGETS := $(SOURCES:.md=.html)
SITEMAP := sitemap.xml
# All HTML files that should trigger sitemap regeneration (exclude template)
HTML_FILES := $(shell find . -name "*.html" -type f ! -name "template.html")

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone

all: $(TARGETS) $(SITEMAP)

$(SITEMAP): generate_sitemap.py $(HTML_FILES)
	python3 generate_sitemap.py

clean:
	rm -f $(TARGETS) $(SITEMAP)

# So that make doesn't think the above two are directories
.PHONY: all clean
