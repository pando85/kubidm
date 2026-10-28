#!/usr/bin/env bash
# Fail on patterns that panic or block in production Rust code.
#
#   .to_offset(                           use checked_to_offset: to_offset panics
#                                         when the result is out of range
#   blocking_read/write/lock(             in server/ and libs/: these panic on a
#                                         current-thread runtime and block a worker
#
# Test code is skipped on a best-effort basis: tests/ directories, *test*.rs files,
# server/testkit, comment lines, and top-level `#[cfg(test)] mod name { ... }` blocks
# (up to the closing `}` at column 0; other attributes may sit in between). A
# `#[cfg(test)]` on a single `use` or `fn` does NOT hide the code after it.
# Justified uses carry an inline marker comment:
#
#   expr.to_offset(x) // allow-pattern: <reason>
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

scan() {
    local label="$1" pattern="$2" pathspec_re="$3"
    local files=() f
    # grep exits 1 when a filter matches nothing; an empty selection is fine, so
    # collect the files first instead of letting pipefail turn it into a failure.
    # Files deleted from the work tree but still in the index are skipped.
    while IFS= read -r -d '' f; do
        if [ -f "$f" ]; then files+=("$f"); fi
    done < <(git ls-files -z --cached --others --exclude-standard -- '*.rs' \
        | { grep -zE "$pathspec_re" || true; } \
        | { grep -zEv '(^|/)(tests|benches)/|(^|/)tests?\.rs$|_tests?\.rs$|^server/testkit' || true; })
    [ "${#files[@]}" -gt 0 ] || return 0
    # shellcheck disable=SC2016  # the awk program is single quoted on purpose
    PATTERN="$pattern" LABEL="$label" awk '
        FNR == 1 { in_tests = 0; pending = 0 }
        in_tests {
            if ($0 ~ /^\}/) { in_tests = 0 }
            next
        }
        /^#\[cfg\(test\)\]/ { pending = 1; next }
        pending && /^[[:space:]]*((#\[.*\]|\/\/.*)[[:space:]]*)?$/ { next }
        pending {
            pending = 0
            if ($0 ~ /^(pub(\([a-z]+\))? +)?mod +[A-Za-z0-9_]+ *\{[[:space:]]*$/) { in_tests = 1; next }
        }
        /^[[:space:]]*\/\// { next }
        /allow-pattern:/ { next }
        $0 ~ ENVIRON["PATTERN"] { printf "%s:%d: %s [%s]\n", FILENAME, FNR, $0, ENVIRON["LABEL"]; bad = 1 }
        END { exit bad }
    ' "${files[@]}"
}

status=0
scan "use checked_to_offset" '(\.|::)to_offset\(' '.' || status=1
scan "blocking call in async code" '(\.|::)blocking_(read|write|lock)\(' '^(server|libs)/' || status=1

if [ "$status" -ne 0 ]; then
    echo >&2
    echo "Forbidden patterns found. Fix them, or add '// allow-pattern: <reason>' on the same line." >&2
fi
exit "$status"
