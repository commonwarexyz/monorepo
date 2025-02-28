# Setting Expectations

External contributors are encouraged to submit issues and pull requests to this repository. That being said, not all issues will be addressed nor will all correct pull requests be merged.

The Commonware Library provides robust, high-performance primitives and contributions that do not directly advance this work will not be considered. This includes (but is not limited to):

- Introducing an external dependency
- Implementing optional functionality
- Adding complex algorithms that provide marginal performance improvements
- Refactoring for the sake of refactoring
- Trivial changes from accounts farming contribution metrics (especially when aided by an LLM)
- New primitives and/or dialects that are ecosystem-specific

# Style

This repository uses the default cargo and clippy formatting rules for `.rs` files, treating warnings as errors. To check linting, run:

```bash
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo fmt --all -- --check
```

To fix linting automatically, run:

```bash
$ cargo fmt --all
```

# Releases

Releases are automatically published to `cargo` by [GitHub Actions](.github/workflows/publish.yml) whenever a version update is merged into the `main` branch.

To increment the patch version of all crates (and update the corresponding minimum required version in `workspace.dependencies`), run:

```bash
./scripts/bump_versions.sh
```

# Licensing and Copyright

You agree that any work submitted to this repository shall be dual-licensed under the included [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses, without any additional terms or conditions. Additionally, you agree to release your copyright interest in said work to the public domain, such that anyone is free to use, modify, and distribute your contributions without restriction.

# Support

Looking to discuss a potential contribution or get feedback? Reach out on [GitHub Discussions](https://github.com/commonwarexyz/monorepo/discussions)!