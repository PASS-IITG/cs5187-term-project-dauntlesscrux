# `bn_mod_add_fixed_top()` MSan experiment

## Assessment

`report-3db729.html` (source line 80) and `report-71c964.html` (source line 76) are two analyzer paths to one source-level candidate in `bn_mod_add_fixed_top()`, not two independent defects. The source paths read a scratch word before the first write when an operand has `d == NULL`. For the reviewed valid zero-operand cases, the corresponding mask is initialized to zero, so the uninitialized value is ANDed with zero.

The negative control triggered MemorySanitizer, confirming the instrumentation was active. The actual OpenSSL harness exercised both operand arrangements and produced no MSan diagnostic. MemorySanitizer propagates definedness bit by bit; an uninitialized value ANDed with an initialized zero yields initialized zero in its shadow model. Therefore, this result does not prove the source read is absent, but runtime impact remains unconfirmed. No vulnerability is claimed. Valgrind/Memcheck was unavailable.

## Reproduction

The original OpenSSL worktree was not modified. The experiment used a temporary archive of pinned revision `ed57129cd43b77e077c68fd5f7ea951976766f38`, built under `/tmp`. The archived source file hash was identical to the worktree source.

Set paths and extract the pinned source into a disposable temporary directory:

```sh
export TMPROOT=/tmp/openssl-bn-modadd-msan
mkdir -p "$TMPROOT/src"
git -C /mnt/d/CVE-Typestate-Project-clang-analysis archive --format=tar ed57129cd43b77e077c68fd5f7ea951976766f38 \
  | tar -xf - -C "$TMPROOT/src"
cd "$TMPROOT/src"
```

Configure and build OpenSSL with MemorySanitizer:

```sh
CC=clang-18 \
CFLAGS='-O1 -g -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -fPIE' \
LDFLAGS='-fsanitize=memory -pie' \
  ./Configure linux-x86_64 no-shared no-tests
make -j4 build_libs
```

Place the archived `bn_modadd_repro.c` and `msan_probe.c` in `$TMPROOT`, then compile them:

```sh
clang-18 -O1 -g -fsanitize=memory -fsanitize-memory-track-origins=2 \
  -fno-omit-frame-pointer -fPIE -pie -Iinclude \
  "$TMPROOT/bn_modadd_repro.c" libcrypto.a -ldl -pthread \
  -o "$TMPROOT/bn_modadd_repro"
clang-18 -O1 -g -fsanitize=memory -fsanitize-memory-track-origins=2 \
  -fno-omit-frame-pointer -fPIE -pie "$TMPROOT/msan_probe.c" \
  -o "$TMPROOT/msan_probe"
```

Run the negative control and both OpenSSL cases. The negative control is expected to exit 86 with an MSan warning; the two OpenSSL calls are expected to exit 0 and print results 0 and 1 respectively:

```sh
MSAN_OPTIONS=halt_on_error=1:exit_code=86 "$TMPROOT/msan_probe"
MSAN_OPTIONS=halt_on_error=1:exit_code=86 "$TMPROOT/bn_modadd_repro" a  # a=0, b=0, m=17
MSAN_OPTIONS=halt_on_error=1:exit_code=86 "$TMPROOT/bn_modadd_repro" b  # a=1, b=0, m=17
```

The observed command output is preserved in `logs/`; `commands.log`, `configure.log`, and `build.log` document the actual configure/build steps. `experiment-manifest.txt` records revision, source hash, results, and limitations.
