# Look into subdirectories for markdown files
SOURCES := $(shell find . -name "*.md" -type f)
# Replace .md with .html
TARGETS := $(SOURCES:.md=.html)

# Re-runs when the template file changes, or any markdown file changes
%.html: %.md template.html
	pandoc $< -o $@ --template=template.html --mathjax --standalone

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

# So that make doesn't think the above two are directories
.PHONY: all clean
