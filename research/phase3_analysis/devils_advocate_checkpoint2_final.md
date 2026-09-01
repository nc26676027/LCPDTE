# Devil's Advocate Checkpoint 2 — Final Rerun

Date: 2026-08-29  
Mode: independent read-only, bounded Stage-1 closure review  
Final verdict: **PASS**  
Final findings: **0 Critical / 0 Major / 0 Minor**

## Scope

The rerun independently checked the 96-query counterexample ledger, the
25-source synthesis corpus, source/code provenance, HEGIDE, Character Block
Encodings and Sparse-THI novelty boundaries, the four R0 execution schedules,
both claim-intent manifests, and the downstream security/experiment gates.
Historical audit reports were retained as immutable records rather than
rewritten to look current.

## First-pass findings and dispositions

The first final-pass review returned `REVISE` with 0 Critical, 1 Major, and 3
Minor findings:

1. **Major — stale three-schedule R0 preregistration.** `rq_brief.md`,
   `methodology_blueprint.md`, and `preregistration_amendments.md` still used a
   combined eager-candidate label. **Fixed:** all three now freeze
   `h=min(g,D-d)`, `S=2^d`, `K=2^h-1` and separately register sequential
   active CT--CT, eager active-supernode CT--CT, eager all-supernode
   CT--plaintext, and state-aware fused-LUT schedules.
2. **Minor — query-map scope was overstated.** **Fixed:** the search record now
   states that only family E has a candidate discovery/verification route map;
   the missing A--D mappings cannot be reconstructed without invention.
3. **Minor — a 15-source sentence was not marked historical.** **Fixed:** the
   tension-pair inventory is labeled as the 15-source historical core and
   links the 25-source DA2 inventory.
4. **Minor — Kim's publication correction was absent from the Chinese report.**
   **Fixed:** the report distinguishes the old ledger's 13/15 count from the
   corrected historical-core count of 14 peer-reviewed works plus one
   preprint.

## Final verification

The same independent reviewer performed a targeted rerun after the changes and
reported `PASS` with 0 Critical, 0 Major, and 0 Minor findings. Mechanical
checks additionally confirm 96 unique query IDs, 25 unique annotated source
headings, matched reference/anchor counts in both synthesis artifacts, valid
claim-manifest schemas, and parseable research JSON/YAML.

## Residual advisories

- Families A--D lack recoverable per-candidate discovery routes, so the search
  remains a rerunnable bounded search rather than an immutable or exhaustive
  result set.
- The four R0 schedules are a frozen design/accounting contract. The older Go
  eager/fused cost placeholders remain ineligible for benchmark evidence.
- This verdict closes only the Stage-1 Devil's Advocate checkpoint. Unreleased
  baselines, the complete encrypted backend, independent security-estimator
  transcripts, matched performance experiments, and novelty conclusions remain
  subject to downstream gates.
