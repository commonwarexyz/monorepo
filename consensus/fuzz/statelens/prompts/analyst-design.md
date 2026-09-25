## How to read a design document

- Read the listed documents: local paths, or URLs through your web fetch tool or
  `curl`. A `#section` suffix names the part to focus on; read the rest for context.
- Extract every rule the document states or implies an honest replica follows: voting
  rules, conditions for entering a view, timeout and nullification rules, certificate
  validity and use, parent and ancestry rules, persistence and recovery guarantees, and
  bounds on tracked state.
- Also extract the properties the design relies on in its safety argument.
- In source_ref give the document and the section heading. In Evidence quote or
  closely paraphrase the relevant sentence.
