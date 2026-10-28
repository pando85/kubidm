#!/usr/bin/env bash
# Fail when "kanidm" (any case) appears in tracked file contents outside the
# allow-list. See scripts/rebrand_allowlist.txt and
# .opencode/skills/upstream-sync/SKILL.md for the rules.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

allowlist=scripts/rebrand_allowlist.txt
excluded=scripts/rebrand_excluded_paths.txt

excluded_re=$(grep -vE '^[[:space:]]*(#|$)' "$excluded" | paste -sd'|' -)

# Tracked plus not-yet-added files, so a local run sees new files too.
# xargs exits 123 when grep finds nothing in a batch; that is the good case.
# LC_ALL=C: in a UTF-8 locale grep -I treats a file with invalid UTF-8 as binary and
# skips it; in the C locale only files with NUL bytes are binary.
{ git ls-files -z --cached --others --exclude-standard \
    | grep -zEv "$excluded_re" \
    | LC_ALL=C xargs -0 -r grep -sIHni 'kanidm' -- || true; } \
    | awk -v allowlist="$allowlist" '
        BEGIN {
            FS_TAB = "\t"
            n = 0
            while ((getline line < allowlist) > 0) {
                if (line ~ /^[[:space:]]*(#|$)/) {
                    continue
                }
                n++
                tab = index(line, FS_TAB)
                if (tab > 0) {
                    path[n] = substr(line, 1, tab - 1)
                    tok[n] = substr(line, tab + 1)
                } else {
                    path[n] = ""
                    tok[n] = line
                }
            }
        }
        {
            first = index($0, ":")
            file = substr($0, 1, first - 1)
            rest = substr($0, first + 1)
            second = index(rest, ":")
            lineno = substr(rest, 1, second - 1)
            content = substr(rest, second + 1)
            for (i = 1; i <= n; i++) {
                if (path[i] == "" || file ~ path[i]) {
                    gsub(tok[i], "", content)
                }
            }
            if (tolower(content) ~ /kanidm/) {
                print file ":" lineno ": " substr($0, first + second + 1)
                bad++
            }
        }
        END {
            if (bad > 0) {
                printf "\n%d line(s) still say kanidm. Rebrand them, or add a narrow entry to %s.\n", bad, allowlist > "/dev/stderr"
                exit 1
            }
        }
    '
