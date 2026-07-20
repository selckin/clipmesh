#!/usr/bin/env bash
# Run the same gates as .github/workflows/ci.yml, in the same order, so a
# failure here is a failure there. Run it before pushing.

die() { echo "$*" >&2; exit 1; }

cd "$(dirname "$0")" || die "cannot cd to the repo root"

echo "==> cargo fmt --check"
cargo fmt --check || die "formatting differs from rustfmt; run 'cargo fmt' and re-run"

echo "==> cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings || die "clippy found lints (CI treats warnings as errors)"

echo "==> cargo test"
cargo test || die "tests failed"

echo "==> cargo build --release"
cargo build --release || die "release build failed"

echo "==> all CI gates passed"
