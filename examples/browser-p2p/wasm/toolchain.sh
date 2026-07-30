# Apple's bundled Clang cannot target wasm32. Prefer Homebrew LLVM when it is
# available, while still honoring an explicitly configured cross-compiler.
if [ -z "${CC:-}" ] && command -v brew >/dev/null 2>&1; then
  llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
  if [ -x "${llvm_prefix}/bin/clang" ]; then
    export CC="${llvm_prefix}/bin/clang"
    export AR="${AR:-${llvm_prefix}/bin/llvm-ar}"
  fi
fi
