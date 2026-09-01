# Literature Search and Screening Protocol

## Scope

The review supports two coupled questions: (1) non-interactive homomorphic private decision-tree evaluation, especially comparison/traversal/packing costs; and (2) exact or discrete integer and Boolean computation over CKKS, especially functional bootstrapping, representation conversion, and machine-word throughput.

Search date: 2026-08-29 (Asia/Shanghai). Coverage window: 2017--2026 for CKKS/discrete-CKKS work and 2015--2026 for PDTE, with older seminal works admitted only when needed to define a primitive or security model.

## Sources Searched

1. IACR ePrint records and PDFs for cryptographic preprints and author-posted conference versions.
2. ACM Digital Library / official DOI records for ACM CCS and WAHC papers.
3. Springer / official DOI records for LNCS conference papers.
4. Official conference accepted-paper lists when publication metadata is newer than indexing services.
5. Authoritative GitHub repositories and release/commit history for implementation claims.
6. Backward citation search from the two focal manuscripts, followed by exact-title/DOI verification.
7. Search-engine discovery restricted by domain, used only to locate primary records; snippets are not technical evidence.

## Reproducible Queries

Discovery queries executed verbatim:

```text
site:eprint.iacr.org private decision tree evaluation PROBONITE FASTER BPDTE homomorphic encryption
site:dl.acm.org private decision tree evaluation homomorphic encryption SortingHat Level Up
site:eprint.iacr.org discrete CKKS bootstrapping small integers CKKS BLEACH
site:iacr.org CKKS arithmetic logic unit large integers REFHE CPL 2026
"Level Up: Private Non-Interactive Decision Tree Evaluation" DOI
"SortingHat: Efficient Private Decision Tree Evaluation" DOI
"Faster Private Decision Tree Evaluation for Batched Input" DOI
"Bootstrapping Small Integers With CKKS" DOI
```

Backward-citation terms extracted from the focal papers include `PROBONITE`, `SortingHat`, `Level Up`, `FASTER`, `BPDTE`, `Bootstrapping Bits with CKKS`, `Bootstrapping Small Integers with CKKS`, `BLEACH`, `General Functional Bootstrapping Using CKKS`, `REFHE`, and `CPL`.

DA2 checkpoint 2 first added 70 counterexample-oriented queries across four combinations: multiway/radix homomorphic decision trees, encrypted-index selection/rotation, CKKS comparator overflow/borrow, and A2B/discrete-CKKS PDTE. Its independent rerun added 26 generic private-function/private-program/oblivious-processor and exact character-block queries, producing 96 total. The exact query, date, engine/target database, `raw hit count = unavailable`, candidate disposition, and family-E discovery/verification route map are preserved in `da2_major1_query_ledger.md`. Per-candidate query routes for families A--D were not retained and cannot be reconstructed without invention. The search interface did not expose index-wide totals; displayed result counts were not treated as raw totals.

## Eligibility

### Include

- A primary paper that introduces, analyzes, or empirically evaluates a non-interactive PDTE construction used as a baseline or conceptual dependency by LCPDTE.
- A primary paper that introduces a CKKS discrete/integer/Boolean representation, cleanup, functional bootstrap, representation conversion, or large-integer ALU relevant to Gao--Zheng or the proposed port.
- A standards/security paper needed to interpret the stated 128-bit or exact-computation security claims.
- An authoritative implementation repository directly associated with an included paper or the local Lattigo dependency.
- English-language full text with enough detail to reconstruct the relevant algorithm or parameter claim.

### Exclude

- Interactive-only PDTE unless it defines the threat-model boundary or a baseline explicitly used in the focal paper.
- Generic encrypted-ML papers without a reusable decision-tree or discrete-CKKS primitive.
- Surveys, blogs, paper lists, citation aggregators, and search snippets as technical evidence; they may locate a primary source only.
- Duplicate versions, retaining the newest author-approved version while recording the peer-reviewed venue relation.
- Performance claims without a recoverable parameter set, workload definition, or primary artifact.

## Screening and Evidence Rules

- Title/abstract screening is followed by full-text screening for every included source.
- A paper may be included for algorithmic context without being included in quantitative synthesis.
- Quantitative comparisons require matched semantics, security level, packing capacity, workload, and hardware-normalized reporting. Otherwise the source contributes qualitative evidence only.
- Every DOI, ePrint identifier, version date, and repository commit is verified against a primary or authoritative record before final bibliography lock.
- Technical claims are extracted from the full paper and, where available, checked against authoritative code. Indexing metadata and search snippets cannot support an algorithmic claim.

## Screening Ledger (Original Stage 1)

| Stage | Count | Notes |
|---|---:|---|
| Records surfaced by the two domain-restricted search batches | 24 | Includes primary PDFs, metadata aggregators, unrelated false positives, and duplicates. |
| Additional records from backward citation search | 20 | Candidate set from the two focal bibliographies; not all are within review scope. |
| Duplicates/secondary-only/unrelated records excluded at discovery | 22 | Includes duplicate BPDTE/SortingHat results, blogs/lists, interactive-only or unrelated FHE papers. |
| Title/abstract candidates retained after discovery exclusions | 22 | Two focal sources plus PDTE, discrete-CKKS, security, and implementation dependencies. |
| Title/abstract candidates excluded before acquisition | 7 | Out-of-scope primitive families, interactive-only context, or no reconstructable evidence for this RQ. |
| Full texts assessed | 15 | Every assessed item was acquired as a local primary PDF and layout-preserving text derivative. |
| Full texts excluded | 0 | All acquired items contributed to at least one preregistered subtopic; quantitative eligibility is decided claim by claim. |
| Sources selected for the original synthesis | 15 | The original ledger reported thirteen established peer-reviewed venues and two preprints; `kim2025integer` is corrected below to TCHES 2025. |

The original discovery layer did not retain the titles, URLs, ranks or row-level reasons for the seven title/abstract exclusions. `search_strategy.md`, `candidate_bibliography.md`, and `source_verification.md` therefore cannot recover their identities. They remain `EX-01` through `EX-07` with fields marked `not retained`; the auditable reconstruction protocol is in `da2_major1_query_ledger.md`. A future reconstruction must be labeled with its new date and cannot be represented as the original seven because search indexes drift.

## DA2 Major 1 Supplemental Screening

| Stage | Count | Notes |
|---|---:|---|
| Exact counterexample queries executed | 96 | 18 multiway/radix, 21 encrypted-index, 12 comparator, 19 A2B/discrete-CKKS PDTE, and 26 generic PFE/private-program/character-block queries. |
| Raw database hit totals | unavailable | Codex Web Search did not expose totals; this is an interface limitation, not a zero-hit result. |
| Material candidates receiving exact-primary-record disposition | 18 | Thirteen from the first supplement plus HEGIDE, PPFE, Faster Logical Operations, Sparse Hermite and Character Block Encodings. |
| New sources included for bounded DA2 synthesis | 10 | Seven from the first supplement plus HEGIDE, Sparse Hermite and Character Block Encodings. |
| Context-only or excluded material candidates | 8 | The prior six plus PPFE and Faster Logical Operations, excluded by interaction/scheme/target mismatch. |
| Existing record corrected | 1 | IACR's ePrint page for `kim2025integer` states that it was published in TCHES 2025. |
| Updated synthesis corpus | 25 | Twenty-one established peer-reviewed publications and four official-record preprints (`liang2024bpdte`, `cheon2026embedding`, `alexandru2026sparsehermite`, `dumezy2026characterblock`). |

This remains a focused, rerunnable bounded review, not a PRISMA systematic review. Queries, domains and dates are recorded, but complete result-page snapshots, ranks and per-query result exports are not; reproducibility therefore applies to rerunning the protocol, not reproducing an immutable search-engine result set. The supplement was designed to find counterexamples to a proposed combination, not to estimate prevalence or produce an exhaustive field census. Its findings are updated by the generic PFE/private-program search family in `da2_major1_query_ledger.md` before any exact-composition statement is released.

## Distributional Coverage Advisory

`DISTRIBUTIONAL_SKEW_ADVISORY`: computational/formal cryptographic systems studies constitute 25/25 final sources (100%). The concentration is expected from an implementation, correctness and cost RQ; no expansion to qualitative or social-science method families was made. No single publication year or venue family reaches the 70% threshold.
