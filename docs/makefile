SITEMAP := sitemap.xml
MD_SOURCES := $(shell find . -name "*.md" -type f)
MD_TARGETS := $(SOURCES:.md=.html)
HTML_TARGETS := $(shell find . -name "*.html" -type f ! -name "template.html")

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone

all: $(MD_TARGETS) $(SITEMAP)

$(SITEMAP): generate_sitemap.py $(HTML_TARGETS)
	python3 generate_sitemap.py

clean:
	rm -f $(MD_TARGETS) $(HTML_TARGETS) $(SITEMAP)

# So that make doesn't think the above two are directories
.PHONY: all clean
