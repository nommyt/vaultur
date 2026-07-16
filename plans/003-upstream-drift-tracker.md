# Plan 003: Add an automated upstream-drift tracker (Vaultwarden + Bitwarden release signals)

> **Executor instructions**: Follow this plan in order. Run each verification
> command and confirm the expected result before continuing. Stop on any
> condition in **STOP conditions**; do not substitute a different pin, silently
> weaken a check, or mutate GitHub while implementing. Preserve all unrelated
> worktree changes. When every local gate passes, mark this plan `DONE` in
> `plans/README.md`, then delete this completed plan file per repository policy.
>
> **Drift check (run first)**:
>
> ```bash
> git diff --stat 7eb3a33..HEAD -- \
>   .github/workflows/ci.yml scripts test/route-parity.spec.ts plans/README.md
> git status --short -- \
>   .vaultwarden-pin scripts/upstream-drift-report.sh \
>   .github/workflows/upstream-drift.yml
> ```
>
> The second command must print nothing. If one of those three target artifacts
> already exists, STOP. If the first command shows changes to CI, scripts, or
> route parity since this plan's baseline, compare the live files against the
> integration seams below; STOP if the conventions or assumptions no longer
> match. A dirty worktree elsewhere is allowed and must be left intact.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx (process/tooling — parity maintenance)
- **Planned at**: commit `7eb3a33`, 2026-07-08
- **Reviewed at**: commit `7eb3a33`, 2026-07-15 (working tree contains other
  in-progress security work)

## Outcome

Vaultur records the Vaultwarden commit it is ported against and runs one
read-only report every week. The report:

1. compares the pin with the complete upstream Git history without GitHub's
   compare-API commit/file truncation;
2. shows bounded commit, high-signal file, route-attribute, and diff-stat
   sections;
3. watches the latest stable Vaultwarden/web-vault builds plus recent official
   Bitwarden server, web/desktop/browser/CLI, Android, and iOS releases;
4. maintains one rolling public GitHub issue, updates only when the canonical
   state changes, and comments on a changed state so subscribers are notified;
5. fails loudly on a missing/non-ancestor pin, route-extractor rot, duplicate
   rolling issues, an oversized report, or GitHub/API failure.

Porting upstream changes and bumping the pin remain deliberate human work.

## Why this matters

Vaultur's compatibility depends on Vaultwarden and the official Bitwarden
clients, but the repository currently records no reference commit and watches
no upstream. The 2026-07-08 audit found the sibling reference checkout at
`d6a3d539` was nine commits behind `main`; the 2026-07-15 plan review found it
eleven commits behind. That range already includes protocol changes that break
current clients against Vaultur.

The original plan used GitHub's compare API as the source of the commit and
file lists. That endpoint returns at most 250 commits without pagination and at
most 300 changed files for the entire comparison. A pin is specifically meant
to remain fixed until a human catches up, so silent truncation is unacceptable.
The report already needs a clone for route extraction; this revision uses that
clone for the authoritative commit range and file list as well.

The original release state marker also watched only the first
`bitwarden/clients` result. GitHub's release list is not publication ordered in
this multi-product repository, and Android/iOS-only changes were absent from
the marker. The revised report sorts by `published_at` and hashes every release
entry it displays, so any displayed release change refreshes the issue.

## Current integration seams

- **Project**: one Hono/TypeScript Cloudflare Worker, managed with pnpm. This
  plan does not change runtime TypeScript.
- **Reference**: `github.com/dani-garcia/vaultwarden`, default branch `main`.
  Vaultur is currently ported against full SHA
  `d6a3d539ed13352085ca7dfa63c49017d86c419b` (2026-06-05). The new pin file
  must start at exactly that SHA; catching up is out of scope.
- **Route fixture**: `test/route-parity.spec.ts` is hand-maintained from
  Vaultwarden's Rocket `#[get/post/put/delete("...")]` attributes and grouped
  manually by mount prefix. The automated route comparison is intentionally a
  **heuristic** over raw attributes. It must preserve duplicate method/path
  pairs (no `sort -u`) and must not claim to reconstruct mounted absolute
  routes or `routes![...]` registration. All `src/api/**` changes and
  `src/main.rs` are also in the high-signal file/stat sections so registration
  and mount changes remain visible for review.
- **CI conventions**: `.github/workflows/ci.yml` uses
  `actions/checkout@v6`, `persist-credentials: false`, explicit least-privilege
  permissions, `ubuntu-latest`, and 2-space YAML indentation. Match these.
- **Script conventions**: repository scripts use `#!/usr/bin/env bash`,
  `set -euo pipefail`, and resolve `ROOT_DIR` from `BASH_SOURCE[0]`. Local macOS
  has Bash 3.2, so do not use Bash 4-only arrays or parameter features.
- **Web vault**: `scripts/fetch-web-vault.sh` consumes
  `dani-garcia/bw_web_builds/releases/latest`, which intentionally excludes
  prereleases. The report's top-level web-vault value uses the same endpoint.
- **GitHub repo**: `nommyt/vaultur` is public with Issues enabled. The report
  contains only public upstream facts. Do not put Vaultur vulnerability
  analysis or private deployment details in it.
- **Scheduling**: GitHub scheduled workflows run only from the default branch
  and can be disabled after 60 days without public-repository activity. The
  workflow keeps `workflow_dispatch` for smoke tests and recovery.
- **Completed-plan policy**: `plans/README.md` says completed plan files are
  deleted and their `DONE` rows remain as history. Follow that policy in the
  final step.

## Scope

**Create:**

- `.vaultwarden-pin`
- `scripts/upstream-drift-report.sh`
- `.github/workflows/upstream-drift.yml`

**Modify at completion:**

- `plans/README.md` — status row only
- delete `plans/003-upstream-drift-tracker.md` after the row is `DONE`

**Do not modify:**

- `test/route-parity.spec.ts` — detection only; fixture regeneration belongs
  with a future pin bump
- `.github/workflows/ci.yml`
- `wrangler.jsonc`, `src/**`, `README.md`, or other scripts
- any pre-existing dirty-worktree files
- GitHub issues or labels during local implementation

## Git workflow

- Suggested branch: `advisor/003-upstream-drift-tracker`.
- One commit is sufficient, with an imperative subject such as
  `Add weekly upstream-drift tracker`.
- Do not commit, push, dispatch the workflow, or open a PR unless the operator
  explicitly asks.

## Commands and prerequisites

| Purpose        | Command                                                                    | Expected result                                         |
| -------------- | -------------------------------------------------------------------------- | ------------------------------------------------------- |
| Pin validation | `grep -cE '^[0-9a-f]{40}$' .vaultwarden-pin`                               | `1`                                                     |
| Bash syntax    | `bash -n scripts/upstream-drift-report.sh`                                 | exit 0, no output                                       |
| Executable bit | `test -x scripts/upstream-drift-report.sh`                                 | exit 0                                                  |
| Live report    | `bash scripts/upstream-drift-report.sh > /tmp/drift-report.md`             | exit 0; requires `gh`, `jq`, `git`, auth/token, network |
| YAML syntax    | `npx --yes js-yaml@4.1.0 .github/workflows/upstream-drift.yml > /dev/null` | exit 0                                                  |
| Repo gates     | `pnpm format:check && pnpm typecheck`                                      | both exit 0                                             |

Before the live report, verify:

```bash
command -v gh
command -v jq
command -v git
gh auth status
```

`GH_TOKEN` may be used instead of keyring auth, but never print or persist it.

## Steps

### Step 1: Create the pin

Create `.vaultwarden-pin` with exactly this line and a trailing newline:

```text
d6a3d539ed13352085ca7dfa63c49017d86c419b
```

Do not add a comment or substitute current upstream `main`.

Verify:

```bash
grep -cE '^[0-9a-f]{40}$' .vaultwarden-pin
test "$(tr -d '[:space:]' < .vaultwarden-pin)" = \
  d6a3d539ed13352085ca7dfa63c49017d86c419b
```

Both commands must exit 0; the first prints `1`.

### Step 2: Create the bounded, complete report script

Create `scripts/upstream-drift-report.sh` with this exact content:

```bash
#!/usr/bin/env bash
# Generates a bounded Markdown report on stdout for Vaultwarden source drift
# and official Bitwarden release signals. Read-only: it calls public GitHub
# APIs and clones Vaultwarden into a temporary directory.
#
# Requires: bash, gh (authenticated or GH_TOKEN), jq, git, network.
# Consumed by .github/workflows/upstream-drift.yml and safe to run locally.
set -euo pipefail
export LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="$(tr -d '[:space:]' < "$ROOT_DIR/.vaultwarden-pin")"
UPSTREAM="dani-garcia/vaultwarden"

if ! [[ "$PIN" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: .vaultwarden-pin must contain one full 40-char commit SHA" >&2
  exit 1
fi
for command_name in gh jq git; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "error: required command not found: $command_name" >&2
    exit 1
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The local clone is authoritative. Unlike GitHub's compare API, git does not
# truncate a long-lived pin at 250 commits or 300 changed files.
git clone --quiet "https://github.com/$UPSTREAM.git" "$tmp/vw"
if ! git -C "$tmp/vw" cat-file -e "$PIN^{commit}" 2>/dev/null; then
  echo "error: pinned SHA $PIN is not present in Vaultwarden" >&2
  exit 1
fi
upstream_head="$(git -C "$tmp/vw" rev-parse origin/main)"
if ! git -C "$tmp/vw" merge-base --is-ancestor "$PIN" "$upstream_head"; then
  echo "error: pinned SHA is not an ancestor of upstream main" >&2
  exit 1
fi
ahead="$(git -C "$tmp/vw" rev-list --count "$PIN..$upstream_head")"

cap_lines() {
  local input="$1"
  local limit="$2"
  local output="$3"
  local count
  count="$(wc -l < "$input" | tr -d '[:space:]')"
  head -n "$limit" "$input" | cut -c 1-240 > "$output"
  if ((count > limit)); then
    printf '... (%d additional lines omitted)\n' "$((count - limit))" >> "$output"
  fi
}

# Newest first, bounded so an old pin cannot overflow a GitHub issue body.
if ((ahead == 0)); then
  commits_text="(none)"
else
  git -C "$tmp/vw" log --max-count=50 --format='%h %s' \
    "$PIN..$upstream_head" > "$tmp/commits.raw"
  cap_lines "$tmp/commits.raw" 50 "$tmp/commits.txt"
  if ((ahead > 50)); then
    printf '... (%d older commits omitted)\n' "$((ahead - 50))" >> "$tmp/commits.txt"
  fi
  commits_text="$(cat "$tmp/commits.txt")"
fi

# Broad enough to surface API registration/mount, authentication, crypto,
# config, schema, and model changes without claiming every source change is
# protocol relevant.
git -C "$tmp/vw" diff --name-only "$PIN" "$upstream_head" -- \
  src/main.rs src/api src/auth.rs src/config.rs src/crypto.rs \
  src/db/schema.rs src/db/models > "$tmp/files.raw"
LC_ALL=C sort -o "$tmp/files.raw" "$tmp/files.raw"
cap_lines "$tmp/files.raw" 100 "$tmp/files.txt"
if [[ -s "$tmp/files.txt" ]]; then
  high_signal_files_md="$(sed -E 's|^|- `|; s|$|`|' "$tmp/files.txt")"
else
  high_signal_files_md="_(none)_"
fi

routes_at() {
  # Heuristic matching the route-parity fixture's documented attributes.
  # Keep duplicates: identical raw attributes in different modules are
  # distinct signals even though mount prefixes are reconstructed by hand.
  git -C "$tmp/vw" grep -hoE \
    '#\[(get|post|put|delete)\("[^"]+"' "$1" -- src/api \
    | sed -E 's/^#\[([a-z]+)\("([^"]*)".*$/\1 \2/' \
    | LC_ALL=C sort
}

routes_at "$PIN" > "$tmp/routes-pin.txt"
routes_at "$upstream_head" > "$tmp/routes-main.txt"
if [[ ! -s "$tmp/routes-pin.txt" || ! -s "$tmp/routes-main.txt" ]]; then
  echo "error: route extraction returned no routes; the heuristic has rotted" >&2
  exit 1
fi
if diff -u "$tmp/routes-pin.txt" "$tmp/routes-main.txt" > "$tmp/routes.diff"; then
  route_diff="(no route-attribute changes)"
else
  grep -E '^[+-][^+-]' "$tmp/routes.diff" > "$tmp/routes-changed.raw" || true
  if [[ ! -s "$tmp/routes-changed.raw" ]]; then
    echo "error: route files differ but no changed route lines were extracted" >&2
    exit 1
  fi
  cap_lines "$tmp/routes-changed.raw" 100 "$tmp/routes-changed.txt"
  route_diff="$(cat "$tmp/routes-changed.txt")"
fi

git -C "$tmp/vw" diff --stat=120,80 "$PIN" "$upstream_head" -- \
  src/main.rs src/api src/auth.rs src/config.rs src/crypto.rs \
  src/db/schema.rs src/db/models > "$tmp/stat.raw"
cap_lines "$tmp/stat.raw" 60 "$tmp/stat.txt"
if [[ -s "$tmp/stat.txt" ]]; then
  diff_stat="$(cat "$tmp/stat.txt")"
else
  diff_stat="(no high-signal changes)"
fi

latest_stable_json() {
  gh api "repos/$1/releases/latest" \
    | jq -ce '
      if ((.tag_name | type) != "string" or
          (.published_at | type) != "string")
      then error("malformed latest release")
      else {tag: .tag_name, publishedAt: .published_at}
      end'
}

recent_releases_json() {
  local repo="$1"
  local count="$2"
  gh api "repos/$repo/releases?per_page=100" \
    | jq -ce --argjson count "$count" '
      [.[] | select(.draft == false)] as $releases
      | if (($releases | length) == 0 or
            any($releases[];
              ((.tag_name | type) != "string" or
               (.published_at | type) != "string" or
               (.prerelease | type) != "boolean")))
        then error("empty or malformed release feed")
        else [$releases[] |
          {tag: .tag_name,
           publishedAt: .published_at,
           prerelease: .prerelease}]
          | sort_by([.publishedAt, .tag]) | reverse | .[0:$count]
        end'
}

release_summary() {
  jq -r '"`\(.tag)` (" + (.publishedAt | split("T")[0]) + ")"' <<< "$1"
}

release_list() {
  jq -r '.[] |
    "- `\(.tag)` (" + (.publishedAt | split("T")[0]) + ")" +
    (if .prerelease then " — prerelease" else "" end)' <<< "$1"
}

vw_release_json="$(latest_stable_json "$UPSTREAM")"
web_release_json="$(latest_stable_json dani-garcia/bw_web_builds)"
server_releases_json="$(recent_releases_json bitwarden/server 4)"
clients_releases_json="$(recent_releases_json bitwarden/clients 8)"
android_releases_json="$(recent_releases_json bitwarden/android 6)"
ios_releases_json="$(recent_releases_json bitwarden/ios 6)"

vw_release="$(release_summary "$vw_release_json")"
web_release="$(release_summary "$web_release_json")"
server_releases="$(release_list "$server_releases_json")"
clients_releases="$(release_list "$clients_releases_json")"
android_releases="$(release_list "$android_releases_json")"
ios_releases="$(release_list "$ios_releases_json")"

# Hash every value displayed as state. Upstream-derived source sections are
# represented by upstream_head; all displayed release feeds are included.
state_id="$({
  printf '%s\n' "$PIN" "$upstream_head"
  printf '%s\n' "$vw_release_json" "$web_release_json"
  printf '%s\n' "$server_releases_json" "$clients_releases_json"
  printf '%s\n' "$android_releases_json" "$ios_releases_json"
} | git hash-object --stdin)"

cat > "$tmp/report.md" <<EOF
<!-- drift-state $state_id -->
# Upstream drift report

- **Pinned Vaultwarden**: \`${PIN:0:9}\` ([.vaultwarden-pin](../blob/main/.vaultwarden-pin))
- **Upstream main**: \`${upstream_head:0:9}\`
- **Upstream commits ahead**: **$ahead**
- **Latest stable Vaultwarden release**: $vw_release
- **Latest stable bw_web_builds release**: $web_release

## Upstream commits since the pin (newest first, max 50)

\`\`\`text
$commits_text
\`\`\`

## High-signal files changed (max 100)

$high_signal_files_md

## Route-attribute drift heuristic (pin to main, max 100 lines)

This compares raw \`#[get/post/put/delete]\` attributes and preserves
duplicates. It does not reconstruct Rocket mount prefixes or prove route
registration; inspect \`src/api/**\` and \`src/main.rs\` changes above.

\`\`\`diff
$route_diff
\`\`\`

## High-signal diff stat (max 60 lines)

\`\`\`text
$diff_stat
\`\`\`

## Recent official Bitwarden releases (publication ordered)

**bitwarden/server**:
$server_releases

**bitwarden/clients** (web / browser / desktop / CLI):
$clients_releases

**bitwarden/android**:
$android_releases

**bitwarden/ios**:
$ios_releases

---
_Action: review and port relevant changes. When Vaultur is caught up, bump
\`.vaultwarden-pin\` to the reviewed upstream SHA and regenerate the
route-parity fixture in the same PR, then manually dispatch this workflow._

_Generated by \`scripts/upstream-drift-report.sh\` via
\`.github/workflows/upstream-drift.yml\`. The issue is public; keep
Vaultur-specific security analysis out of this report._
EOF

report_bytes="$(wc -c < "$tmp/report.md" | tr -d '[:space:]')"
if ((report_bytes > 60000)); then
  echo "error: report is $report_bytes bytes; keep it below 60000" >&2
  exit 1
fi
cat "$tmp/report.md"
```

Make it executable:

```bash
chmod +x scripts/upstream-drift-report.sh
```

Verify:

```bash
bash -n scripts/upstream-drift-report.sh
test -x scripts/upstream-drift-report.sh
```

Both must exit 0 with no output.

### Step 3: Live-run and inspect the report

Run only after the prerequisite commands pass:

```bash
bash scripts/upstream-drift-report.sh > /tmp/drift-report.md
```

Verify all of these:

```bash
head -n 1 /tmp/drift-report.md
grep -c '^## ' /tmp/drift-report.md
grep -F '**bitwarden/server**' /tmp/drift-report.md
grep -F '**bitwarden/clients**' /tmp/drift-report.md
grep -F '**bitwarden/android**' /tmp/drift-report.md
grep -F '**bitwarden/ios**' /tmp/drift-report.md
wc -c < /tmp/drift-report.md
```

Expected:

- the first line matches `^<!-- drift-state [0-9a-f]{40,64} -->$`;
- there are exactly five `##` headings;
- every official release subsection is present;
- the report is at most 60,000 bytes;
- `Upstream commits ahead` is internally consistent with the commit section.
  Do not hard-code the current count: it was 11 during the 2026-07-15 review
  and will continue to change.

Inspect the report once. Commit subjects and tags must be public upstream facts,
and no secret/token may appear.

### Step 4: Create the race-safe rolling-issue workflow

Create `.github/workflows/upstream-drift.yml`:

```yaml
name: Upstream drift

on:
  schedule:
    # Avoid the busiest start-of-hour window for scheduled Actions.
    - cron: "17 7 * * 1" # Mondays 07:17 UTC
  workflow_dispatch:

permissions:
  contents: read
  issues: write

concurrency:
  group: upstream-drift
  cancel-in-progress: false

jobs:
  report:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - name: Generate report
        env:
          GH_TOKEN: ${{ github.token }}
        run: bash scripts/upstream-drift-report.sh > report.md
      - name: Create or update rolling issue
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          title="Upstream drift report"
          gh label create drift --repo "$GITHUB_REPOSITORY" --force \
            --description "Upstream Vaultwarden and Bitwarden drift tracking" \
            --color 5319e7

          matches="$(gh issue list --repo "$GITHUB_REPOSITORY" \
            --state all --limit 1000 --json number,title,state,labels \
            --jq '[.[] | select(.title == "Upstream drift report")]')"
          match_count="$(jq length <<< "$matches")"
          if ((match_count > 1)); then
            echo "error: multiple exact rolling issues exist; refusing to guess" >&2
            exit 1
          fi

          new_state="$(sed -n '1p' report.md)"
          if ((match_count == 0)); then
            gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" \
              --label drift --body-file report.md
            exit 0
          fi

          num="$(jq -r '.[0].number' <<< "$matches")"
          issue_state="$(jq -r '.[0].state' <<< "$matches")"
          has_drift_label="$(jq -r \
            'any(.[0].labels[]; .name == "drift")' <<< "$matches")"
          if [[ "$has_drift_label" != "true" ]]; then
            gh issue edit "$num" --repo "$GITHUB_REPOSITORY" --add-label drift
          fi
          old_state="$(gh issue view "$num" --repo "$GITHUB_REPOSITORY" \
            --json body --jq '.body | split("\n")[0]')"
          if [[ "$new_state" == "$old_state" ]]; then
            echo "No state change; leaving issue #$num untouched."
            exit 0
          fi

          if [[ "$issue_state" != "OPEN" ]]; then
            gh issue reopen "$num" --repo "$GITHUB_REPOSITORY"
          fi
          gh issue edit "$num" --repo "$GITHUB_REPOSITORY" \
            --body-file report.md
          state_id="${new_state#<!-- drift-state }"
          state_id="${state_id% -->}"
          gh issue comment "$num" --repo "$GITHUB_REPOSITORY" \
            --body "Upstream or release state changed; report refreshed (\`$state_id\`)."
```

Why each guard is required:

- `concurrency` prevents schedule/manual races from creating duplicates.
- `gh label create --force` is idempotent but does not suppress real
  permission/API failures.
- `--limit 1000` avoids `gh issue list`'s default 30-item truncation. The title
  lookup does not depend on the label, so a manually removed label cannot
  cause a duplicate; the workflow restores that label explicitly.
- searching `--state all` reuses a closed rolling issue; it reopens only when
  state actually changes.
- more than one exact issue is an explicit failure, not an arbitrary choice.
- the first-line state digest avoids unchanged edits; a changed-state comment
  triggers subscriber notifications.
- `split("\n")[0]` avoids a `gh ... | head` pipeline/SIGPIPE hazard under
  `pipefail`.

Validate YAML syntax without installing a project dependency:

```bash
npx --yes js-yaml@4.1.0 .github/workflows/upstream-drift.yml > /dev/null
```

Expected: exit 0, no output. Do not run the issue-management block locally.

### Step 5: Run repository gates and review scope

If dependencies are not already installed, run:

```bash
pnpm install --frozen-lockfile
```

Then run:

```bash
pnpm format:check
pnpm typecheck
git diff --check -- \
  .vaultwarden-pin scripts/upstream-drift-report.sh \
  .github/workflows/upstream-drift.yml plans/README.md
git status --short -- \
  .vaultwarden-pin scripts/upstream-drift-report.sh \
  .github/workflows/upstream-drift.yml plans/README.md \
  plans/003-upstream-drift-tracker.md
```

Expected: both project gates and `git diff --check` pass. The scoped status
shows only the three new artifacts plus the plan-index/completed-plan cleanup
from Step 6. Do **not** require global `git status` to be clean; this repository
already has unrelated in-progress changes. Review the global status only to
confirm those changes were preserved.

### Step 6: Close and remove the completed plan

Only after Steps 1–5 pass:

1. change plan 003's row in `plans/README.md` from `TODO` to `DONE`;
2. leave the historical audit/backlog text intact;
3. delete `plans/003-upstream-drift-tracker.md`.

Verify:

```bash
grep -n '| 003 ' plans/README.md
test ! -e plans/003-upstream-drift-tracker.md
```

The row must say `DONE`; the second command exits 0.

## Test plan

No Vitest spec is appropriate: the artifacts are Bash/GitHub Actions tooling
that deliberately talks to live GitHub, while the application suite runs in
workerd. Required local verification is:

1. exact pin content;
2. Bash syntax and executable mode;
3. one authenticated live report with structure, feeds, and size assertions;
4. pinned `js-yaml` parse of the workflow;
5. `pnpm format:check`, `pnpm typecheck`, and scoped diff review.

After merge, the maintainer must manually dispatch **Upstream drift** once and
confirm:

- exactly one `drift`-labeled issue is created or reused;
- its first line is the state marker and its five report sections render;
- a second unchanged dispatch does not edit or comment;
- the maintainer subscribes to the issue so future changed-state comments
  produce notifications.

Do not perform that mutating smoke test as part of local implementation.

## Done criteria

- [ ] `.vaultwarden-pin` contains exactly
      `d6a3d539ed13352085ca7dfa63c49017d86c419b` plus a newline.
- [ ] `bash -n scripts/upstream-drift-report.sh` and
      `test -x scripts/upstream-drift-report.sh` pass.
- [ ] A live report exits 0, has a valid state marker, exactly five sections,
      every official release feed, and at most 60,000 bytes.
- [ ] Source drift comes from the local Git clone, verifies the pin is an
      ancestor, and does not use GitHub's compare endpoint.
- [ ] Release feeds sort by publication time and the state digest covers
      Vaultwarden/web stable releases plus server/clients/Android/iOS lists.
- [ ] Route extraction preserves duplicate attributes and the report labels it
      as a heuristic rather than an exhaustive mounted-route table.
- [ ] Workflow YAML parses and includes least-privilege permissions,
      a 15-minute timeout, concurrency, exact-issue uniqueness, closed-issue
      reuse, state-change notification comments, and no swallowed label errors.
- [ ] `pnpm format:check`, `pnpm typecheck`, and scoped `git diff --check` pass.
- [ ] No GitHub issue, label, workflow, commit, push, or PR was mutated locally.
- [ ] `plans/README.md` says plan 003 is `DONE`, and this plan file is deleted.

## STOP conditions

Stop and report; do not improvise if:

- any of the three target artifacts already exists before implementation;
- a changed CI/script/route-parity seam invalidates this plan's assumptions;
- `gh`, `jq`, `git`, GitHub auth/token, or network is unavailable for the live
  run;
- the fixed pin is missing from upstream or is no longer an ancestor of
  `origin/main`;
- route extraction returns no routes at either ref or produces an
  uninterpretable diff;
- a required GitHub API/release endpoint errors or returns malformed/null data;
- the bounded report still exceeds 60,000 bytes;
- YAML syntax, format, typecheck, or diff checks fail on work outside this
  plan's scope;
- the post-merge workflow finds multiple exact rolling issues.

## Maintenance notes

- **Catching up is atomic**: port reviewed upstream behavior, regenerate the
  route-parity fixture, and bump `.vaultwarden-pin` in the same PR. A pin bump
  without the port converts visible drift into false confidence.
- **The route section is a tripwire, not a parser**: route registration and
  mount changes may not alter raw attributes. Always inspect high-signal
  `src/api/**` and `src/main.rs` changes before declaring parity.
- **Release feeds are signals**: tags indicate when compatibility expectations
  may have moved; they do not replace reading actual client/server changes.
- **Stable versus prerelease is deliberate**: top-level Vaultwarden and
  `bw_web_builds` match GitHub's latest-stable endpoint. Recent official
  Bitwarden lists include prereleases and label them.
- **The issue is public**: report only upstream facts. Keep exploitability,
  Vaultur deployment details, and vulnerability triage private.
- **Subscribe after the first dispatch**: changed-state comments trigger
  notifications for subscribers; body edits alone are not the alert channel.
- **Scheduled-workflow liveness**: public-repository schedules can be disabled
  after 60 days of inactivity. Re-enable and manually dispatch if that occurs.
- **Regex rot is expected eventually**: if Vaultwarden moves away from Rocket
  attributes, the workflow should fail until the heuristic and route-parity
  maintenance process are redesigned together.
