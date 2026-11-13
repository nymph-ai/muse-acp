# NymphAI muse-acp fork

This repository is a source fork of https://github.com/BrokkAi/muse-acp. NymphAI's
Fabric runs Muse Code sessions through muse-acp (nymph-ai/nymphai
`fabric/HARNESSES.md`, `fabric/SESSIONS.md`), and its session image takes
muse-acp from this fork's releases, not upstream's.

## Branches

- `fabric` is the maintained branch: upstream's newest release plus the fork's
  commits on top of it. Every fork release is tagged on it.
- `master` follows upstream and carries no fork commits.

The fork's commits, oldest first (on v0.21.0; the refused-turn drive handover, BrokkAi/muse-acp#452, was
released upstream in v0.21.0 and dropped):

| Change | Upstream pull |
| --- | --- |
| A resume refused `sessionInUse` (ACP `session/load`, the re-attach after a host restart) asks for the drive once and resumes again (nymph-ai/nymphai#5818) | none yet |
| While a turn is still to settle, the host's idle status is not sent as a v2 `state_update`: the first idle after a turn is the terminal's, with its stop reason (nymph-ai/nymphai#7283) | none yet |
| A message keeps one id live and on every replay: a user message the id of the turn command that inserted it, any other message its host item id (nymph-ai/nymphai#7283) | none yet |
| Releases are published from `fabric` under fork tags, with no npm package (this file, `FORK_RELEASE`, `scripts/release.py`, the workflows) | fork only |

An upstream pull is a courtesy. Nothing here waits for one to merge; when
upstream releases a change the fork carries, the rebase drops the fork's copy.

## Releases

A fork release is tagged `v<upstream version>-<FORK_RELEASE>`, for example
`v0.21.0-nymph.1`: the Cargo version stays upstream's, and the file
`FORK_RELEASE` holds the suffix. The release workflow is upstream's, aimed at
this repository: pushing `fabric` runs the `ci` and `release` preflights, and
pushing the tag at that commit publishes the six archives
(`muse-acp-<tag>-<target>`) and their checksums. To cut one:

1. Land the change on `fabric` and bump `FORK_RELEASE` (`nymph.3` to `nymph.4`)
   in the same push. Wait for that commit's `ci` and `release` push runs.
2. `git tag -a v<version>-<FORK_RELEASE> -m ... <commit>` and push the tag.

nymph-ai/nymphai's harness pins (`fabric/harnesses/pins`, feed
`muse-acp-github-release`) take the newest fork release on their next run.

## Taking upstream changes

When upstream releases `vX.Y.Z` (the pins report it as an action):

```sh
git fetch upstream --tags
git branch archive/fabric-before-vX.Y.Z fabric
git switch fabric
git rebase --onto vX.Y.Z <old upstream tag> fabric
```

Resolve conflicts in source. Drop a fork commit whose change upstream released.
Reset `FORK_RELEASE` to `nymph.1`, update the table above, push `fabric` with
`--force-with-lease`, wait for the preflights, and tag `vX.Y.Z-nymph.1`. Check
`git merge-base --is-ancestor vX.Y.Z fabric` before tagging.
