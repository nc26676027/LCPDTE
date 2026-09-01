# Source Verification Ledger

Verification date: 2026-08-29 (Asia/Shanghai).

## Focal Sources

The focal ePrint identities, version dates, authors, PDF hashes, and visual checks are frozen in `source_manifest.md`. Their technical claims were reconstructed from full text and authoritative source code in `lcpdte_paper_code_map.md` and `gao_paper_code_map.md`.

## DOI Registry Capture

The DOI resolver was inaccessible through the browser layer, so DOI metadata was captured read-only from the Crossref REST registry using the exact DOI (or an exact-title query when the DOI was initially unknown). The returned title, author set, publisher, venue, and publication date agreed with the focal papers' reference lists.

| Work | DOI | Registry title / venue result | Outcome |
|---|---|---|---|
| PROBONITE | `10.1145/3560827.3563377` | ACM WAHC 2022 proceedings article; Azogagh, Delfour, Gambs, Killijian | verified |
| SortingHat | `10.1145/3548606.3560702` | ACM CCS 2022 proceedings article; Cong, Das, Park, Pereira | verified |
| Level Up | `10.1145/3576915.3623095` | ACM CCS 2023 proceedings article; Akhavan Mahdavi, Ni, Linkov, Kerschbaum | verified |
| FASTER PDTE | `10.1007/978-3-031-71073-5_1` | Springer SCN 2024 chapter; Cong, Kang, Nicolas, Park | verified |
| Bootstrapping Small Integers with CKKS | `10.1007/978-981-96-0875-1_11` | ASIACRYPT 2024 chapter; Bae, Kim, Stehle, Suvanto | verified |
| Bootstrapping Bits with CKKS | `10.1007/978-3-031-58723-8_4` | EUROCRYPT 2024 chapter; Bae, Cheon, Kim, Stehle | verified |
| BLEACH | `10.1007/s00145-023-09483-1` | Journal of Cryptology article; Drucker, Moshkowich, Pelleg, Shaul | verified |
| General Functional Bootstrapping Using CKKS | `10.1007/978-3-032-01881-6_10` | CRYPTO 2025 chapter; Alexandru, Kim, Polyakov | verified |
| Sparse-secret CKKS bootstrapping | `10.1007/978-3-031-09234-3_26` | ACNS 2022 chapter; Bossuat, Troncoso-Pastoriza, Hubaux | verified |
| Application-Aware Approximate HE | `10.62056/ayl83z10k` | IACR Communications in Cryptology article; Alexandru, Al Badawi, Micciancio, Polyakov | verified |
| Nested-RNS large integers | `10.1007/978-3-032-01881-6_11` | CRYPTO 2025 chapter; Boneh, Kim | verified |

Crossref verification establishes bibliographic identity, not technical correctness. A source remains `full-text-pending` in the candidate bibliography until its relevant claims are extracted from the primary manuscript.

### DA2 supplemental official-record capture

The first seven counterexample supplements were verified directly against the official publisher, IACR/ePrint, IEEE, Springer, or author-posted arXiv artifact and remain web-only. The rerun additionally acquired and hashed HEGIDE, Sparse Hermite, and Character Block Encodings for the synthesis corpus, plus PPFE and Faster Logical Operations as context-only screens; their local provenance is recorded in `source_manifest.md`.

| Citation key | Identity / publication evidence | Technical evidence boundary | Outcome |
|---|---|---|---|
| `lee2025heaanid3` | Tech Science DOI `10.32604/cmc.2025.064161`, volume 84(2), pp. 3673--3705, 2025 | Publisher Introduction states categorical multiway children; Section 8.4 discusses node/slot growth | verified, peer reviewed |
| `lu2021pegasus` | IACR ePrint 2020/1606 states publication at IEEE S&P 2021; IEEE Xplore document 9519408 | IACR paper abstract and Application II support CKKS--FHEW switching and private decision-tree use | verified, peer reviewed |
| `shin2024hbdt` | IACR ePrint 2024/529 states publication at ESORICS 2024; Springer DOI `10.1007/978-3-031-70896-1_11` | Official abstract supports encrypted model/input and addition-only path evaluation | verified, peer reviewed |
| `petrean2024mkrf` | Springer DOI `10.1007/s10207-024-00823-1`, *International Journal of Information Security* 23 (2024) | Publisher Sections 1.1 and 4.1.3--4.3.1 support encrypted tree LUT and encrypted-index selection | verified, peer reviewed |
| `cheon2025treelut` | IACR ePrint 2024/087 records DOI `10.4134/JKMS.j240423` and journal publication | Official abstract supports complexity and CKKS proof-of-concept claims | verified, peer reviewed |
| `cheon2026embedding` | author-posted arXiv:2606.03191v3, dated 2026-06-07 | Official abstract supports IVE, `O(p)` vector generation and plaintext-table scope | verified existence; preprint-only |
| `cha2026radix` | IACR ePrint 2025/1740 states major revision of an IACR EUROCRYPT 2026 publication | Official abstract supports two-step `O(log k)` carry, unique radix restoration and comparison support | verified, peer reviewed |
| `kim2025integer` correction | IACR ePrint 2025/066 states “Published by the IACR in TCHES 2025” | Local PDF pp. 11--13 supports `Carry(ct-ct')+1` and the proof range `-t < z_i < t` | publication status corrected to peer reviewed |

## Repository Records

| Repository | Role | Pin status |
|---|---|---|
| `thrudgelmir/LCPDTE` | paper-linked author repository | observed HEAD `d8308d55aba5a5647082b5b8efb3226ffc1c0ebe`; one README-only commit ahead of the audit pin |
| `nc26676027/LCPDTE` | working fork / focal Lattigo implementation | `f5ff611f7c023f7ec4d06af6cecaa8b5d33da607` verified; authored by Dongjin Park; direct ancestor of official HEAD; no technical-source diff |
| `tsinghua-ideal/fhe-simd-alu` | focal Gao--Zheng OpenFHE implementation | `08f1eb87434e7be072cba889270a8400bbffc08e` source pin verified; clean build attempt documented; runnable oracle blocked by Clang, NTL/GMP headers, HEXL, tcmalloc and unavailable WSL sudo credentials |
| `tuneinsight/lattigo` | target substrate | module `v6.1.1`; four local vendor patches verified |

The official/fork ancestry commands and exact README-only diff are archived in `official_lcpdte_repo_provenance.md`.

## Primary-Artifact Verification Outcome

- **Scholarly sources in the synthesis corpus:** 25
- **Original full texts acquired locally and inspected:** 18
- **Additional official primary artifacts inspected online:** 7
- **Established peer-reviewed venue:** 21
- **Preprint-only caveat:** 4
- **Rejected as fabricated or predatory:** 0

Two further locally acquired papers (`zhou2026ppfe` and
`kim2026fasterlogical`) were screened as mandatory context but remain outside
the 25-source synthesis denominator because their interaction or representation
model is not matched to the frozen non-interactive triangle/PDTE composition.

The seven-level evidence vocabulary was designed primarily for empirical sciences. For this technology RQ, a formal cryptographic construction accompanied by controlled implementation measurements is classified as Level III; a definitions-only theoretical paper is assessed against cryptography's field-specific gold standard rather than forced into an inapplicable RCT ladder. Overall grades express fitness for the claims used here.

| Citation key | Design level / evidence form | Venue | Method / artifact | Currency | COI / funding signal | Overall | Verification verdict |
|---|---|---|---|---|---|---|---|
| `park2026lcpdte` | III: formal system + controlled benchmarks | CCS / IACR primary record: pass | code available; paper/code discrepancies audited | A | no material undisclosed conflict found | B | primary full text and code verified; local claims require remeasurement |
| `gao2026alu` | III: formal system + controlled benchmarks | CRYPTO / IACR primary record: pass | authoritative code pinned; version/build caveats | A | no material undisclosed conflict found | A-/B+ | primary full text/code verified; source reports OpenFHE 1.4.0 versus paper 1.4.2 |
| `azogagh2022probonite` | III | ACM WAHC: pass | protocol + implementation | B | no material undisclosed conflict found | B | DOI and full text verified |
| `cong2022sortinghat` | III | ACM CCS: pass | protocol + implementation/data benchmarks | B | no material undisclosed conflict found | A-/B+ | DOI and full text verified |
| `mahdavi2023levelup` | III | ACM CCS: pass | protocol + SEAL benchmarks | A | no material undisclosed conflict found | A-/B+ | DOI and full text verified |
| `cong2024faster` | III | SCN/Springer: pass | protocol + dataset benchmarks | A | no material undisclosed conflict found | A-/B+ | DOI and full text verified |
| `liang2024bpdte` | III | preprint-only: warn | protocol/benchmark, no verified code | A | stated institutional funding; no additional conflict established | C+ | real primary source; include with peer-review/artifact caveat |
| `bae2024bits` | III | EUROCRYPT: pass | formal bootstrap + implementation | A | CryptoLab affiliations disclosed; no basis for downgrade | A | DOI and full text verified |
| `bae2024small` | III | ASIACRYPT: pass | formal bootstrap + implementation | A | CryptoLab affiliations disclosed; no basis for downgrade | A | DOI and full text verified |
| `drucker2024bleach` | III | Journal of Cryptology: pass | error analysis + applications | A | IBM affiliations disclosed; no basis for downgrade | A-/B+ | DOI and full text verified |
| `alexandru2025functional` | III | CRYPTO: pass | formal LUT/noise analysis + OpenFHE benchmarks | A | Duality/Altbridge affiliations disclosed; no basis for downgrade | A | DOI and full text verified |
| `kim2025integer` | III | TCHES 2025 / IACR: pass | formal construction + benchmarks | A | no material undisclosed conflict found | B+ | local primary full text verified; publication status corrected; cross-system timing caveat retained |
| `boneh2025nested` | III | CRYPTO: pass | formal construction + controlled benchmarks | A | funding disclosed; no basis for downgrade | A | DOI and full text verified |
| `bossuat2022sparse` | III | ACNS: pass | security/noise analysis + implementation | B | Tune Insight/EPFL affiliations disclosed; no basis for downgrade | A | DOI, ePrint and full text verified |
| `alexandru2026application` | field-gold-standard theoretical definitions | IACR CiC: pass | definitions and implementation guidance | A | industry/academic affiliations disclosed; no basis for downgrade | A | DOI and full text verified |
| `lee2025heaanid3` | III | CMC peer-reviewed article: pass | CKKS construction + implementation/UCI experiments | A | funding and no-COI statements visible in publisher full text | B | official publisher full text verified; direct multiway antecedent, different representation/threat-model scope |
| `lu2021pegasus` | III | IEEE S&P: pass | scheme switching + implementation/applications | B | disclosure assessment limited to inspected primary records | A-/B+ | IACR/IEEE identity and PDTE application verified; hybrid CKKS--FHEW caveat |
| `shin2024hbdt` | III | ESORICS: pass | CKKS training/inference + GPU experiments | A | disclosure assessment limited to inspected primary records | B+ | official IACR/Springer records verified; no Gao triangle/A2B claim |
| `petrean2024mkrf` | III | IJIS/Springer: pass | MK-TFHE construction + experiments | A | disclosure assessment limited to inspected publisher record | B | publisher full text verified; 110-bit/cross-scheme and exponential-table caveats |
| `cheon2025treelut` | III | JKMS: pass | RLWE algorithms + CKKS proof of concept | A | disclosure assessment limited to inspected primary records | A-/B+ | IACR/DOI record and abstract verified; selector primitive, not ML tree |
| `cheon2026embedding` | III | arXiv preprint: warn | CKKS algorithm + implementation/case study | A | disclosure assessment limited to inspected preprint record | C+/B- | author-posted primary preprint; plaintext-table and no-peer-review caveats |
| `cha2026radix` | III | EUROCRYPT 2026 / IACR: pass | radix carry construction + experiments | A | disclosure assessment limited to inspected IACR record | A-/B+ | official IACR record verified; radix rather than triangle representation |
| `dumezy2026hegide` | III | ACM CCS 2026 / IACR: pass | private-program processor + OpenFHE proof of concept + direct decision-tree benchmark | A | affiliations visible; no material undisclosed conflict found | B | official full text and CCS list verified; source is not yet public; throughput depends on full MIMD occupancy |
| `alexandru2026sparsehermite` | III | ePrint preprint: warn | formal noise-cleaning construction + OpenFHE experiments | A | author affiliations/funding disclosed in full text | B-/C+ | official full text verified; code promised after formal publication and sparse-secret estimates are explicitly evolving |
| `dumezy2026characterblock` | III | ePrint preprint: warn | formal representation + Lattigo experiments | A | affiliations visible; no material undisclosed conflict found | B-/C+ | official full text verified; title absent from CCS 2026 accepted list; code promised but not located |

## Flagged Sources and Claim Boundaries

### `park2026lcpdte`

- **Issue:** The paper promotes `O(p sqrt(2^D))` from a key-switch/relinearization analysis to broader server-complexity language. Separately, the frozen `f5ff611` source audit counts `Theta(p 2^d)` tensor multiplications/additions at depth `d` in `tree/main_tree.go:84-210`. Several equations/algorithm lines are transcription-inconsistent.
- **Severity:** Medium for total-complexity claims; Low for the implemented OBO/GenOH/BSGS mechanisms.
- **Recommendation:** Keep as the focal source, but cite the narrower cost claim and preserve the source-derived exact operation count.

### `gao2026alu`

- **Issue:** The public `EvalLessThan` implements sign of modular subtraction without overflow correction; committed examples cover nearby positive values rather than signed boundaries. The code/version string differs from the paper environment.
- **Severity:** High for an unqualified general comparison API; Low for the triangle algebra and conversions.
- **Recommendation:** Port the representation and conversions, but expose only range/signedness-aware comparison contracts and test overflow exhaustively.

### `liang2024bpdte`

- **Issue:** No peer-reviewed venue was established from the verified record; cross-system performance comparisons are sensitive to hardware, packing and security assumptions.
- **Severity:** Medium for headline speedups; Low for algorithmic context.
- **Recommendation:** Include as a supporting primary preprint, not as a decisive quantitative baseline.

### `kim2025integer` and `cha2026radix`

- **Issue:** Both are peer-reviewed discrete/radix CKKS integer-computer antecedents. Kim's comparison is range-justified through carry on radix digits; Cha et al. improve carry scaling. Neither implements Gao triangle encoding, but both preclude an unqualified first-CKKS-integer-comparator claim.
- **Severity:** High for novelty wording; Low for retaining a triangle-specific implementation hypothesis.
- **Recommendation:** Cite both in comparator design and benchmark a declared same-width borrow, widening, or radix-carry route. Do not describe subtraction-and-sign as generally overflow safe.

### `lee2025heaanid3`, `lu2021pegasus`, and `shin2024hbdt`

- **Issue:** These establish multiway CKKS, hybrid CKKS/FHEW, and encrypted-model CKKS decision-tree antecedents respectively. Their computation models differ, but the differences narrow rather than erase the prior art.
- **Severity:** High for broad “first multiway/CKKS/A2B PDTE” language.
- **Recommendation:** Restrict novelty to the exact Gao--Zheng triangle/discrete-CKKS composition, Lattigo realization, proved comparator contract, and any matched measured improvement.

### `cheon2025treelut`, `petrean2024mkrf`, and `cheon2026embedding`

- **Issue:** Encrypted-query selection and tree-to-LUT evaluation already have CKKS and TFHE/MK-TFHE constructions. Table privacy, representation and fanout differ; IVE is preprint-only and assumes a plaintext table.
- **Severity:** High for a first-encrypted-index claim; Medium for selector performance generalization.
- **Recommendation:** Treat tree-LUT and IVE as selector baselines, Petrean--Potolea as a tree-specific encrypted-index boundary, and charge table size/model privacy explicitly.

### `dumezy2026hegide`

- **Issue:** HEGIDE already provides a discrete-CKKS, private-program/private-data oblivious processor and directly benchmarks a depth-4 private binary decision tree. Its ALU follows Kim-style radix digits, evaluates the whole instruction set and flattened paths, and reports throughput only after filling `N=2^16` MIMD slots; one program's reported end-to-end latency is almost eight hours. The paper states that public source release is planned, subject to approval.
- **Severity:** High for broad private-program/private-tree priority language; Medium for transferring its amortized latency to one-query PDTE.
- **Recommendation:** Use it as the general processor and full-path batch baseline. Preserve the narrower distinction between HEGIDE and a specialized Gao-triangle/LCPDTE OBO evaluator, and compare both latency and occupied-batch throughput when code becomes available.

### `alexandru2026sparsehermite` and `dumezy2026characterblock`

- **Issue:** Sparse Hermite changes the noise-cleaning/functional-bootstrap frontier; Character Block Encodings changes the representation itself and supplies single-level LUTs plus low-depth radix comparison in Lattigo. Both official records are preprints and both papers defer public code release.
- **Severity:** High for claiming a first or uniquely efficient discrete-CKKS LUT/comparator; Medium for selecting an implementation substrate before matched tests.
- **Recommendation:** Treat Sparse Hermite as a bootstrap/noise-margin sensitivity baseline and Character Blocks as a mandatory representation/comparator/R0-FusedLUT baseline. Compare complete word packing, conversion cost, levels, refreshes and secure parameters rather than headline LUT depth.

### Cross-paper performance records

- **Issue:** PDTE and integer/FHE studies vary in scheme, native OS, compiler, thread count, security target, slots, word width, batch utilization, model semantics and whether setup/keys are counted.
- **Severity:** High if pooled as a single ranking.
- **Recommendation:** No meta-analysis or direct global league table. Use cross-paper values only to motivate local matched experiments and operation-count hypotheses.

## Predatory-Journal and Retraction Alerts

No retraction signal was found in the inspected official records. The established conference/journal relations are recorded per source rather than inferred from an ePrint alone. `liang2024bpdte`, `cheon2026embedding`, `alexandru2026sparsehermite`, and `dumezy2026characterblock` remain explicitly preprint-only on their official records; none is mislabeled as peer reviewed. Venue status supports bibliographic classification, not automatic acceptance of technical or performance claims.

## Reference-Existence Verification Audit

- Original Tier 1: all eleven DOI-bearing related works resolved in Crossref with matching title, authors, venue and year. Four supplemental DOI-bearing works were checked on the official publisher/IACR records.
- Primary-record tier: the original no-DOI/ePrint works have acquired primary PDFs and exact title/author checks. Seven first-round supplemental sources were checked through official records without local snapshots. HEGIDE, Sparse Hermite, Character Block Encodings and the two context-only required screens were acquired locally with hashes in `source_manifest.md`.
- Tier 0 Semantic Scholar: one exact-title search for the new LCPDTE paper returned a low-similarity false positive (`Constant-Round Private Decision Tree Evaluation for Secret Shared Data`, 2023) and was rejected by the required title/year rule. The next request encountered HTTP 429 after retry; the remaining S2 batch is logged as `[S2-API-UNAVAILABLE/RATE-LIMITED]`. No entry is labeled `S2_VERIFIED` from that degraded run.
- Deduplication: title and DOI/ePrint/arXiv identifier checks found no duplicate scholarly work inside the 25-source corpus. Local PDF hashes cover the original 15 sources and the five DA2-rerun full texts.

## Verification Limitations

- Crossref and publisher metadata establish bibliographic identity, not correctness of a technical claim. Original annotations were checked in local primary PDFs; supplemental claims were limited to passages in official full text, official abstracts, or named paper sections.
- The 96-query interface exposed no raw hit totals. The query ledger records `unavailable` rather than a fabricated count, so this focused supplement cannot support a PRISMA flow or an exhaustiveness claim.
- No external source can certify the security of a future local parameter literal. The local total Q/P chain, secret distributions and estimator version must be audited after implementation.
- Conflict assessment is limited to disclosures/affiliations visible in the primary texts; it is not an investigation of private financial relationships.
