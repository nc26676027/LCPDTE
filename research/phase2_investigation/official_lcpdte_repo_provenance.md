# Official LCPDTE Repository Provenance

Verification date: 2026-08-29 (Asia/Shanghai).

The paper points to the author repository `https://github.com/thrudgelmir/LCPDTE`. The working checkout's configured origin is the user fork `https://github.com/nc26676027/LCPDTE`.

## Frozen identities

- local technical-audit pin: `f5ff611f7c023f7ec4d06af6cecaa8b5d33da607`;
- pin author: Dongjin Park (`44523463+thrudgelmir@users.noreply.github.com`);
- official HEAD observed on 2026-08-29: `d8308d55aba5a5647082b5b8efb3226ffc1c0ebe`;
- ancestry: the local pin is the direct parent/ancestor of the observed official HEAD;
- distance: one commit;
- complete changed-file set: `README.md` only, 2 insertions and 2 deletions;
- technical source difference between the two commits: none.

The README-only commit changes the run instruction from entering a `dt_go/` subdirectory to running from repository root. It does not alter Go, model, parameter or build source.

## Reproduction commands

```powershell
git ls-remote https://github.com/thrudgelmir/LCPDTE.git HEAD
git show -s --format=fuller f5ff611f7c023f7ec4d06af6cecaa8b5d33da607
git fetch --no-tags --depth=2 https://github.com/thrudgelmir/LCPDTE.git d8308d55aba5a5647082b5b8efb3226ffc1c0ebe
git merge-base --is-ancestor f5ff611f7c023f7ec4d06af6cecaa8b5d33da607 d8308d55aba5a5647082b5b8efb3226ffc1c0ebe
git rev-list --count f5ff611f7c023f7ec4d06af6cecaa8b5d33da607..d8308d55aba5a5647082b5b8efb3226ffc1c0ebe
git diff --name-status f5ff611f7c023f7ec4d06af6cecaa8b5d33da607 d8308d55aba5a5647082b5b8efb3226ffc1c0ebe
git diff --stat f5ff611f7c023f7ec4d06af6cecaa8b5d33da607 d8308d55aba5a5647082b5b8efb3226ffc1c0ebe
```

## Evidence boundary

Paper facts retain paper page anchors. Claims about exact Go operation counts, short-circuits, packing differences or effective parameter literals are source-audit results tied to the frozen commit and function/line anchors. The official repository relationship establishes code provenance; it does not turn a source-derived result into a claim made by the paper.
