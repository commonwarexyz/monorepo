#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${RUSTFMT_STUB_LOG:-}" ]]; then
    for argument in "$@"; do
        if [[ "$argument" == -*.rs ]]; then
            echo "formatter parsed file as an option: $argument" >&2
            exit 1
        fi
        [[ "$argument" == *.rs ]] || continue
        if [[ ! -f "$argument" ]]; then
            echo "formatter received missing file: $argument" >&2
            exit 1
        fi
        printf '%s\n' "$argument" >> "$RUSTFMT_STUB_LOG"
    done
    exit 0
fi

repository_root=$(git rev-parse --show-toplevel)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/commonware-fix-fmt.XXXXXX")
trap 'rm -rf -- "$fixture_dir"' EXIT

cp "$repository_root/justfile" "$fixture_dir/justfile"
cp "$repository_root/.github/scripts/test_fix_fmt.sh" "$fixture_dir/rustfmt-stub"
chmod +x "$fixture_dir/rustfmt-stub"

cd "$fixture_dir"
git init -q
printf 'fn kept() {}\n' > kept.rs
printf 'fn deleted() {}\n' > deleted.rs
printf 'fn option() {}\n' > ./-option.rs
printf 'ignored.rs\n' > .gitignore
git add -- kept.rs deleted.rs ./-option.rs .gitignore
rm -- deleted.rs
printf 'fn untracked() {}\n' > untracked.rs
printf 'fn ignored() {}\n' > ignored.rs

formatted_files="$fixture_dir/formatted-files"
: > "$formatted_files"
RUSTFMT="$fixture_dir/rustfmt-stub" \
    RUSTFMT_STUB_LOG="$formatted_files" \
    NIGHTLY_VERSION="" \
    just fix-fmt --check

for expected in ./kept.rs ./untracked.rs ./-option.rs; do
    if ! grep -Fqx "$expected" "$formatted_files"; then
        echo "formatter did not receive expected file: $expected" >&2
        exit 1
    fi
done

for unexpected in ./deleted.rs ./ignored.rs; do
    if grep -Fqx "$unexpected" "$formatted_files"; then
        echo "formatter received unexpected file: $unexpected" >&2
        exit 1
    fi
done
