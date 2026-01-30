---
title: "Is it ready yet?"
description: "TBD"
date: "January 30th, 2026"
published-time: "2026-01-30T00:00:00Z"
modified-time: "2026-01-30T00:00:00Z"
author: "Patrick O'Grady"
author_twitter: "https://x.com/_patrickogrady"
url: "https://commonware.xyz/blogs/is-it-ready-yet"
image: "https://commonware.xyz/imgs/is-it-ready-yet-card.png"
---

Large parts of the Commonware Library are now considered BETA.

While I enjoy rabbit holing on random side quests as much as the next person, ....

```bash
# Ensure stability is internally consistent
just check-stability
```

```bash
# Generate docs for only code with stability >= BETA (level 1)
RUSTFLAGS="--cfg commonware_stability_BETA" RUSTDOCFLAGS="--cfg commonware_stability_BETA -A rustdoc::broken_intra_doc_links" cargo doc --open
```

```bash
# Check if your application only uses commonware APIs with stability >= BETA
RUSTFLAGS="--cfg commonware_stability_BETA" cargo build -p my-app
```