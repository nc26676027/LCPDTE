# Annotated Bibliography

Status: ARS Stage 1 / Phase 2 investigation artifact plus the DA2 Major 1 counterexample supplement. The original 15-source annotations were checked against locally acquired primary PDFs. Of the ten sources later added to the 25-source synthesis, seven were checked against official publisher, IACR/ePrint, IEEE, Springer, or author-posted arXiv records, while HEGIDE, Sparse Hermite, and Character Block Encodings were also acquired locally and hashed. Page numbers refer to local PDFs only; web-only records use named sections or the official abstract as their locator. PPFE and Faster Logical Operations were additionally acquired and screened as context-only sources outside the 25-source denominator.

## Search Strategy and Screening Summary

- Databases and records: IACR ePrint, ACM/Springer DOI metadata, official conference lists, and backward citations from the two focal papers.
- Scope: non-interactive PDTE; comparison, traversal and SIMD packing; discrete/integer/Boolean CKKS; functional bootstrapping; security/failure-probability interpretation.
- Dates: PDTE 2015--2026 and discrete CKKS 2017--2026, with the final included corpus concentrated in 2022--2026 because the relevant primitives are recent.
- Inclusion: primary full text with reconstructable algorithm, parameter, security or benchmark evidence directly bearing on the research question.
- Exclusion: interactive-only protocols, generic encrypted ML, secondary surveys, duplicate versions, snippets, and performance records lacking a recoverable workload/parameter context.
- Original screening: 44 discovery/backward-citation records; 22 duplicates, secondary pages and clear topical false positives removed at discovery; 7 further title/abstract candidates excluded; 15 full texts assessed and included. The identities of those seven exclusions were not retained and cannot be recovered without invention; see `da2_major1_query_ledger.md`.
- DA2 supplement and independent rerun: 96 exact counterexample queries, with raw database totals recorded as `unavailable` because the search interface did not expose them; 18 material candidates received row-level disposition, and 10 were added to the bounded synthesis. PPFE and Faster Logical Operations were retained as context-only screens rather than added to that denominator.
- Included corpus: 25 scholarly sources; 21 have an established peer-reviewed venue (84%). `liang2024bpdte`, `cheon2026embedding`, `alexandru2026sparsehermite`, and `dumezy2026characterblock` are explicitly preprint-only.

### Distributional coverage advisory

`DISTRIBUTIONAL_SKEW_ADVISORY`: computational/formal cryptographic systems studies account for 25/25 included sources (100%). This is a coverage-distribution signal, not a defect: it follows directly from the implementation-and-cost RQ. No expansion to qualitative or social-science methods is warranted. Publication years and venue families do not cross the 70% concentration threshold.

## A. Focal Protocols

### `park2026lcpdte`

Park, D., Cha, G., & Lee, J.-W. (2026). *LCPDTE: Low-complexity private decision tree evaluation over homomorphic encryption*. IACR Cryptology ePrint Archive, 2026/1263. https://eprint.iacr.org/2026/1263

- **Relevance:** Focal PDTE protocol and source checkout.
- **Key findings:** CKKS bit-plane SIMD, OBO comparison scheduling, GenOH, BSGS selection, and level-major batched bootstrapping (Algorithms 1--5, pp. 5--9). The paper's square-root traversal statement is supported for key switches/relinearizations, while the checkout still performs `Theta(p 2^d)` tensor multiplications/additions at depth `d` (Appendix B.2, pp. 14--15, plus source audit).
- **Method:** Formal algorithm design, asymptotic analysis, and controlled benchmarks on synthetic and XGBoost forests.
- **Quality:** Technology Level III; overall **B**. Peer-reviewed/current and accompanied by code, but the paper lacks a simulation proof, a numerical failure bound, and a complete parameter-estimator transcript; several pseudocode and paper/code discrepancies are material to reproduction.
- **Use:** Primary evidence for the baseline's semantics, scheduling, and claims; quantitative claims are re-measured locally before comparison.

### `gao2026alu`

Gao, M., & Zheng, H. (2026). *FHE for SIMD arithmetic logic units with amortized O(1) bootstrapping per ciphertext*. IACR Cryptology ePrint Archive, 2026/233. https://eprint.iacr.org/2026/233

- **Relevance:** Focal `Z_{2^n}` triangle representation and CKKS arithmetic/Boolean conversion toolbox.
- **Key findings:** Defines `R[X]/(X^n-X+2)`, triangle encoding/strict coefficient-first decoding, full/short multiplication, A2A, A2B/B-A2B, B2B and B2A (Definitions 9--19 and Algorithms 1--2, pp. 15--23, 47--48). Batched A2B amortizes bootstrapping only when all `n/w` input ciphertexts are available. Source `LessThan` is subtraction followed by sign extraction and is not correct across two's-complement overflow boundaries.
- **Method:** Formal construction/noise analysis, OpenFHE implementation, and width-scaling benchmarks.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed, current, theorem-backed and code-backed; the public checkout identifies OpenFHE 1.4.0 while the paper states 1.4.2, and its examples do not give process-failing exhaustive tests.
- **Use:** Primary algebraic and semantic oracle. Per-ciphertext timings are never imported without normalizing physical ciphertext count and logical words.

## B. Private Decision-Tree Evaluation

### `azogagh2022probonite`

Azogagh, S., Delfour, V., Gambs, S., & Killijian, M.-O. (2022). PROBONITE. In *Proceedings of the 10th Workshop on Encrypted Computing & Applied Homomorphic Cryptography* (pp. 23--33). ACM. https://doi.org/10.1145/3560827.3563377

- **Relevance:** Establishes the non-interactive, one-branch-only TFHE traversal alternative.
- **Key findings:** Evaluates `d` comparisons for a depth-`d` tree instead of all `2^d` nodes, using functional bootstrapping to advance an encrypted path (abstract p. 1; comparison table and conclusion p. 9).
- **Method:** Protocol construction, complexity comparison, and implementation measurements.
- **Quality:** Technology Level III; overall **B**. Peer-reviewed primary evidence, but TFHE representation and one-query traversal differ from the SIMD CKKS target.
- **Use:** Qualitative traversal baseline; cross-scheme wall-clock values are not pooled with local Lattigo timings.

### `cong2022sortinghat`

Cong, K., Das, D., Park, J., & Pereira, H. V. L. (2022). SortingHat. In *Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security* (pp. 563--577). ACM. https://doi.org/10.1145/3548606.3560702

- **Relevance:** Major prior non-interactive PDTE using plaintext-threshold comparison and homomorphic traversal.
- **Key findings:** Introduces a fast ciphertext--plaintext comparator, homomorphic traversal, and optional FiLIP transciphering (abstract p. 1). Reported server speedups are contextualized by scheme, precision and packing; the conclusion reports 20--90x versus then-current baselines (p. 24).
- **Method:** Formal protocol plus implementation and dataset benchmarks.
- **Quality:** Technology Level III; overall **A-/B+**. Strong peer-reviewed baseline, but its comparator precision/layout and transciphering choices are not semantically identical to LCPDTE.
- **Use:** Primary design baseline for server-plaintext-threshold comparison and traversal, not a directly normalized timing point.

### `mahdavi2023levelup`

Akhavan Mahdavi, R., Ni, H., Linkov, D., & Kerschbaum, F. (2023). Level Up: Private non-interactive decision tree evaluation using levelled homomorphic encryption. In *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security* (pp. 2945--2958). ACM. https://doi.org/10.1145/3576915.3623095

- **Relevance:** Leveled-HE high-precision comparator and PDTE baseline used by later batched protocols.
- **Key findings:** Extends XCMP and range-cover comparison to arbitrary precision and proposes XXCMP-PDTE/RCC-PDTE (contributions p. 2; conclusion p. 12). SIMD is used to accelerate both batching and aspects of a single inference.
- **Method:** Protocol construction and Microsoft SEAL benchmark study.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed and reproducible at the algorithm level; scheme/precision/key material differ from CKKS bootstrap designs.
- **Use:** Comparison-operator and communication baseline; imported performance remains qualitative unless re-instantiated.

### `cong2024faster`

Cong, K., Kang, J., Nicolas, G., & Park, J. (2024). Faster private decision tree evaluation for batched input from homomorphic encryption. In *Security and Cryptography for Networks* (pp. 3--23). Springer. https://doi.org/10.1007/978-3-031-71073-5_1

- **Relevance:** Closest prior high-throughput PDTE baseline cited by LCPDTE.
- **Key findings:** Batched RCC and constant-weight comparisons combine with adapted SumPath; the paper reports up to 72x comparator speedup at 16 bits and up to 17x PDTE speedup over Level Up for batch 16,384 (abstract p. 1; conclusion p. 17). Server response complexity becomes constant in tree depth, but computation still depends on the chosen traversal and model.
- **Method:** Leveled-FV construction and controlled dataset/parameter benchmarks.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed and well scoped; its response-size claim is not a total-runtime claim.
- **Use:** Primary batched comparison/traversal baseline and warning against conflating communication with server work.

### `liang2024bpdte`

Liang, H., Lu, H., Guo, Y., Wang, G., Yu, H., Zhang, H., An, B., Li, J., & Su, L. (2024). *BPDTE: Batch private decision tree evaluation via amortized efficient private comparison*. IACR Cryptology ePrint Archive, 2024/619. https://eprint.iacr.org/2024/619

- **Relevance:** Broad comparison of batchable high-precision PDTE/comparator variants.
- **Key findings:** Proposes three private comparisons and six BPDTE schemes; the technical distinction among TECMP, RDCMP and CDCMP matters more than a single headline timing (contributions and Table 1, pp. 1--2).
- **Method:** Preprint protocol suite, proofs, and benchmarks.
- **Quality:** Technology Level III; overall **C+**. Full primary text is available, but no peer-reviewed venue was established and no authoritative code artifact was verified for this review.
- **Use:** Supporting context only; not admitted as a hard performance baseline without independent implementation evidence.

## C. Discrete CKKS and Functional Bootstrapping

### `bae2024bits`

Bae, Y., Cheon, J. H., Kim, J., & Stehlé, D. (2024). Bootstrapping bits with CKKS. In *Advances in Cryptology -- EUROCRYPT 2024* (pp. 94--123). Springer. https://doi.org/10.1007/978-3-031-58723-8_4

- **Relevance:** Dedicated CKKS bit bootstrap underlying high-throughput Boolean paths.
- **Key findings:** Develops bit-specific CKKS bootstraps and gate bootstrap variants, including compatibility with DM/CGGI formats (abstract p. 1; performance framing p. 3). Its advantage grows with many identical packed operations; thin or lightly filled batches lose amortization.
- **Method:** Formal algorithms, numerical analysis and single-thread implementation benchmarks.
- **Quality:** Technology Level III; overall **A**. Peer-reviewed, recent and directly relevant, with explicit parameter/performance context.
- **Use:** Basis for Boolean bootstrap alternatives and for the batch-utilization accounting rule.

### `bae2024small`

Bae, Y., Kim, J., Stehlé, D., & Suvanto, E. (2024). Bootstrapping small integers with CKKS. In *Advances in Cryptology -- ASIACRYPT 2024* (pp. 330--360). Springer. https://doi.org/10.1007/978-981-96-0875-1_11

- **Relevance:** Small-integer/root-of-unity functional bootstrap alternative.
- **Key findings:** SI-BTS maps canonically embedded small integers to roots of unity and supports arbitrary functions; BB-BTS batches bit ciphertexts (abstract p. 1, technical overview pp. 4--7). Reported 8-bit LUT amortization assumes 2^12 input LWE ciphertexts and 128-bit parameters.
- **Method:** Formal bootstrap construction, precision analysis and performance experiments.
- **Quality:** Technology Level III; overall **A**.
- **Use:** Competing functional-bootstrap route; it does not itself provide Gao's machine-word arithmetic triangle.

### `drucker2024bleach`

Drucker, N., Moshkowich, G., Pelleg, T., & Shaul, H. (2024). BLEACH: Cleaning errors in discrete computations over CKKS. *Journal of Cryptology, 37*(1). https://doi.org/10.1007/s00145-023-09483-1

- **Relevance:** Establishes error-cleaning as the mechanism enabling deep discrete CKKS circuits.
- **Key findings:** Shows how cleaning can support deep or unbounded Boolean/integer circuits under correctable-error conditions and integrates discrete and approximate computation (abstract p. 1; research questions p. 3; conclusion p. 30). Efficiency is application- and parallelism-dependent.
- **Method:** Error analysis plus benchmarked Boolean/integer applications.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed journal evidence; BLEACH is a methodology rather than a drop-in full machine-word ALU.
- **Use:** Theoretical/engineering basis for explicit error margins and cleaning gates.

### `alexandru2025functional`

Alexandru, A., Kim, A., & Polyakov, Y. (2025). General functional bootstrapping using CKKS. In *Advances in Cryptology -- CRYPTO 2025* (pp. 304--337). Springer. https://doi.org/10.1007/978-3-032-01881-6_10

- **Relevance:** General multi-value LUT via CKKS and trigonometric Hermite interpolation; closest foundation to the local patched multi-polynomial bootstrap.
- **Key findings:** Supports arbitrary functions over `Z_p`, zero-derivative Hermite noise cleaning, multi-value LUTs and multi-precision extensions (contributions p. 6; Algorithm 1 and analysis pp. 20--25). The paper explicitly leaves a fair comparison with specialized leveled sign methods unresolved (p. 11).
- **Method:** Formal interpolation/noise/complexity analysis and OpenFHE benchmarks.
- **Quality:** Technology Level III; overall **A**.
- **Use:** Primary source for multi-output LUT design and a counterweight to assuming a general LUT is automatically the best comparison primitive.

## D. Integer-Computer Alternatives

### `kim2025integer`

Kim, J. (2025). Efficient homomorphic integer computer from CKKS. *IACR Transactions on Cryptographic Hardware and Embedded Systems*. Author version: IACR Cryptology ePrint Archive, 2025/066. https://eprint.iacr.org/2025/066

- **Relevance:** Closest pre-Gao CKKS route to full unsigned machine-word operations.
- **Key findings:** Uses decomposition plus modular reduction to support unsigned addition, multiplication, comparison and shifts; bootstrapping count grows linearly with word width for fixed digit width (technical overview pp. 3--5; implementation discussion p. 19; conclusion p. 21).
- **Method:** Formal construction and performance comparison against TFHE/BGV-BFV systems.
- **Quality:** Technology Level III; overall **B+**. The official ePrint record states that the work was published by IACR in TCHES 2025. Cross-paper timing comparisons still inherit environment, packing and security differences.
- **Use:** Alternative design point and evidence that radix decomposition improves comparisons while paying width-proportional refresh cost.

### `boneh2025nested`

Boneh, D., & Kim, J. (2025). Homomorphic encryption for large integers from nested residue number systems. In *Advances in Cryptology -- CRYPTO 2025* (pp. 338--370). Springer. https://doi.org/10.1007/978-3-032-01881-6_11

- **Relevance:** Large arbitrary-modulus CKKS integer alternative.
- **Key findings:** Uses slot-wise CRT and a nested RNS hierarchy to reach very large moduli; it explicitly identifies a tradeoff: CRT improves large-modulus arithmetic/throughput, while radix approaches retain more efficient comparison, shifts and arbitrary functions (pp. 23--24). Benchmarks focus primarily on modular multiplication (Tables 6--8, pp. 26--27).
- **Method:** Formal construction and controlled modular-arithmetic benchmarks.
- **Quality:** Technology Level III; overall **A**.
- **Use:** Negative/contrast evidence: it is not the natural PDT comparator substrate despite excellent large-integer multiplication.

## E. DA2 Counterexamples and Selector Alternatives

The ten sources in this section were added by the 2026-08-29 DA2 counterexample search and rerun. Seven official primary artifacts were inspected online without local acquisition; HEGIDE, Sparse Hermite, and Character Block Encodings were acquired locally with hashes recorded in `source_manifest.md`.

### `lee2025heaanid3`

Lee, D., Shin, H., Choi, J., & Lee, Y. (2025). HEaaN-ID3: Fully homomorphic privacy-preserving ID3-decision trees using CKKS. *Computers, Materials & Continua, 84*(2), 3673--3705. https://doi.org/10.32604/cmc.2025.064161

- **Relevance:** Direct counterexample to an unqualified claim that multiway or categorical FHE decision trees are new.
- **Key findings:** The publisher full text states that HEaaN-ID3 handles nominal and ordinal categorical variables and creates as many children as a selected variable has categories (Introduction). Training and inference remain encrypted and use CKKS SIMD across nodes; Section 8.4 also identifies exponential node/slot growth with maximum category count and depth.
- **Method:** Fully homomorphic ID3 training and inference with modified Gini impurity, approximate nonlinear CKKS routines, SIMD implementation, and UCI experiments.
- **Quality:** Technology Level III; overall **B**. Peer-reviewed primary article with implementation measurements. It studies categorical ID3 and a different training/threat-model problem, not Gao triangle/A2B or the frozen LCPDTE composition.
- **Use:** Mandatory multiway-CKKS related work and scalability counterexample; not a matched performance point.

### `lu2021pegasus`

Lu, W.-J., Huang, Z., Hong, C., Ma, Y., & Qu, H. (2021). PEGASUS: Bridging polynomial and non-polynomial evaluations in homomorphic encryption. In *2021 IEEE Symposium on Security and Privacy*. IEEE. https://eprint.iacr.org/2020/1606

- **Relevance:** Direct hybrid CKKS/FHEW private decision-tree antecedent.
- **Key findings:** PEGASUS switches packed CKKS ciphertexts to extracted FHEW ciphertexts for LUT/non-polynomial evaluation and repacks them. Its private-decision-tree application is single round and evaluates edge comparisons, path sums, and leaf LUTs (Application II).
- **Method:** Scheme switching, conversion algorithms, LUT evaluation, implementation benchmarks, and application demonstrations; author code is published at <https://github.com/Alibaba-Gemini-Lab/OpenPEGASUS>.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed IEEE S&P paper with code; the route is hybrid CKKS--FHEW rather than A2B within Gao-style discrete CKKS.
- **Use:** Prevents a broad “first CKKS arithmetic/Boolean mixed PDTE” claim; provides a scheme-switching baseline class.

### `shin2024hbdt`

Shin, H., Choi, J., Lee, D., Kim, K., & Lee, Y. (2024). Fully homomorphic training and inference on binary decision tree and random forest. In *Computer Security -- ESORICS 2024*. Springer. https://doi.org/10.1007/978-3-031-70896-1_11

- **Relevance:** Direct CKKS decision-tree antecedent with encrypted models and encrypted inputs.
- **Key findings:** The official ePrint abstract states that inference evaluates paths using only additions even when models and inputs are encrypted, with constant multiplicative depth.
- **Method:** CKKS-based homomorphic training/inference, modified Gini impurity, random-forest extension, and GPU experiments.
- **Quality:** Technology Level III; overall **B+**. Peer-reviewed ESORICS paper. Its tree representation and inference mechanism are not Gao triangle/A2B and need semantic matching before timing comparison.
- **Use:** Establishes that CKKS private decision-tree evaluation itself is not a new category.

### `petrean2024mkrf`

Petrean, D.-E., & Potolea, R. (2024). Random forest evaluation using multi-key homomorphic encryption and lookup tables. *International Journal of Information Security, 23*, 2023--2041. https://doi.org/10.1007/s10207-024-00823-1

- **Relevance:** Direct tree-to-LUT and encrypted-index selection antecedent with encrypted model and client features under different keys.
- **Key findings:** Each tree is compiled into an encrypted decision LUT; `MKEvalLUTVerticalPacking` selects the classification at an encrypted binary-decomposed feature index (Sections 4.1.3--4.3.1). The table contains `2^M` entries, making model size an explicit boundary.
- **Method:** MK-TFHE construction, vertical packing, noise/error analysis, and UCI/random-model experiments.
- **Quality:** Technology Level III; overall **B**. Peer-reviewed primary article with full method and experiments. It uses MK-TFHE and reports a 110-bit estimator point, not the target CKKS/128-bit setting.
- **Use:** Tree-specific encrypted-index baseline and evidence that whole-tree LUT compilation trades traversal for exponential storage.

### `cheon2025treelut`

Cheon, J. H., Choe, H., & Park, J. H. (2025). Tree-based lookup table on batched encrypted queries using homomorphic encryption. *Journal of the Korean Mathematical Society*. https://doi.org/10.4134/JKMS.j240423

- **Relevance:** Direct CKKS encrypted-query selection primitive relevant to branch, node, or leaf lookup.
- **Key findings:** For an encrypted LUT of size `n`, the official abstract reports `O(log n)` comparisons and `O(n)` multiplications; for a plaintext LUT it reports `O(log n)` comparisons, `O(sqrt(n))` ciphertext multiplications and `O(n)` scalar multiplications. A CKKS proof of concept evaluates 512-entry tables.
- **Method:** Tree-structured RLWE LUT algorithms, complexity analysis, and CKKS proof-of-concept implementation.
- **Quality:** Technology Level III; overall **A-/B+**. Peer-reviewed journal relation and DOI are recorded by IACR. The “tree” is a selection tree, not an ML decision tree.
- **Use:** Mandatory matched selector baseline before claiming an encrypted-index or rotation innovation.

### `cheon2026embedding`

Cheon, J. H., Jang, D., Kang, J., & Rhee, H. (2026). *Private embedding lookup with encrypted compact queries under fully homomorphic encryption* (arXiv:2606.03191v3) [Preprint]. https://arxiv.org/abs/2606.03191

- **Relevance:** Very recent CKKS encrypted-scalar-index selection alternative.
- **Key findings:** Independent Vector Evaluation replaces a one-hot vector with successive powers of one encrypted index and a precomputed DCT change of basis, reducing vector generation from `O(p log p)` to `O(p)` in the authors' accounting (official abstract). The reported speedup is application- and table-model-specific.
- **Method:** CKKS algorithm, change-of-basis error control, implementation, and encrypted FastText case study.
- **Quality:** Technology Level III; overall **C+/B-**. Primary author-posted preprint, not peer reviewed as of the search date. It selects from a server plaintext embedding table and is not PDTE.
- **Use:** Exploratory selector baseline; never presented as peer-reviewed or as an encrypted-model result.

### `cha2026radix`

Cha, G., Park, D., & Lee, J.-W. (2026). Improved radix-based approximate homomorphic encryption for large integers via lightweight bootstrapped digit carry. In *Advances in Cryptology -- EUROCRYPT 2026*. Author major revision: IACR ePrint 2025/1740. https://eprint.iacr.org/2025/1740

- **Relevance:** Current radix/discrete-CKKS carry and comparison alternative.
- **Key findings:** The official ePrint abstract gives a two-step digit-carry algorithm with `O(log k)` bootstraps, reports three to six bootstraps to restore unique radix representations after 32--2048-bit multiplication, and identifies comparison as an enabled non-arithmetic operation.
- **Method:** Radix CKKS construction, bootstrapped carry/reduction algorithms, formal analysis, and large-integer experiments.
- **Quality:** Technology Level III; overall **A-/B+**. The official record identifies the manuscript as a major revision of an IACR EUROCRYPT 2026 publication. It targets radix words, not Gao triangle encoding.
- **Use:** Current comparison/carry baseline and a direct limit on unqualified “first CKKS integer comparator” claims.

### `dumezy2026hegide`

Dumezy, J., Ye, N., Clet, P.-E., Chakraborty, O., & Boudguiga, A. (2026). HEGIDE: A MIMD oblivious processor for private function evaluation over CKKS. *ACM CCS 2026*. https://eprint.iacr.org/2026/1187

- **Relevance:** Closely adjacent discrete-CKKS private-program/private-data execution and a direct private decision-tree benchmark.
- **Key findings:** HEGIDE encrypts instructions and addresses, executes a public fixed Read--Execute--Write processor circuit, and leaks the padded cycle count, memory size, word size, and ISA (full paper §§2.4 and 4.5). It adopts Kim-style radix digits, evaluates every ISA operation before oblivious result selection, and flattens branches. Section 6.3 evaluates a depth-4 binary tree by executing all 15 internal nodes: 60 HEGIDE cycles, about 28,400 s full-batch latency, and about 433 ms amortized per program over `2^16` MIMD slots.
- **Method:** Formal semi-honest obliviousness argument, OSReM memory design, OpenFHE v1.4.2 proof of concept, compiler, and same-machine comparisons with Phantom/VSP.
- **Quality:** Technology Level III; overall **B**. Peer-reviewed CCS paper and locally verified full text. The implementation is not public in the paper version; the throughput result requires near-full MIMD occupancy and one-program latency is almost eight hours.
- **Use:** Mandatory general-processor/full-path private-tree baseline. It prohibits broad private-program/private-tree priority claims but does not implement Gao triangle/A2B or LCPDTE OBO/BSGS.

### `alexandru2026sparsehermite`

Alexandru, A., Kim, A., Polyakov, Y., & Zheng, H. (2026). Sparse Hermite interpolation method for discrete-CKKS functional bootstrapping. *IACR ePrint 2026/1026* [Preprint]. https://eprint.iacr.org/2026/1026

- **Relevance:** Current functional-bootstrap and noise-cleaning substrate for discrete CKKS; directly relevant to a Lattigo port's correctness margin and bootstrap choice.
- **Key findings:** Sparse-THI supplies arbitrary-order trigonometric Hermite cleaning, introduces a noise-capacity metric, and compares AKP/BKSS/Sparse-THI under one OpenFHE pipeline (full paper §§3--6). First-order Sparse-THI is reported close to AKP total latency while improving noise capacity; higher orders trade an extra level for stronger cleaning.
- **Method:** Closed-form interpolation/noise analysis and OpenFHE v1.5.1 experiments with explicit sparse-secret-estimate caveats.
- **Quality:** Technology Level III; overall **B-/C+**. Official primary preprint with local full text; public code is promised only after formal publication.
- **Use:** Bootstrap/noise-ablation baseline, not a PDTE or triangle-word priority claim.

### `dumezy2026characterblock`

Dumezy, J., & Suvanto, E. (2026). Character block encodings for discrete CKKS: Single-level LUTs and low-depth arithmetic. *IACR ePrint 2026/1200* [Preprint]. https://eprint.iacr.org/2026/1200

- **Relevance:** Direct Lattigo representation, LUT, modular-arithmetic and comparator baseline that is closer to the planned fused/radix operator path than a generic bootstrap paper.
- **Key findings:** A value occupies a character-basis block of CKKS slots; unary LUTs become affine plaintext transforms at one level, selected modular laws become one multiplication, and finite-state radix scans give equality/comparison depth `3+ceil(log2 d)` (full paper §§3, 5--6). The Lattigo evaluation reports, among other rows, 64-bit radix-4 comparison and explicit throughput/packing costs (Tables 1 and 8). Conversion from standard discrete CKKS into a character block still requires nonlinear evaluation/functional bootstrap (§3.8).
- **Method:** Representation theorems, error-growth analysis, prefix-scan arithmetic and a single-thread Lattigo prototype; OpenFHE is used only for separate bootstrap comparisons.
- **Quality:** Technology Level III; overall **B-/C+**. Official record remains a preprint, its title is absent from the CCS 2026 accepted list, and the paper says the code will be made public but no authoritative release was located.
- **Use:** Mandatory comparator and `R0-FusedLUT` baseline. Any gain must charge the extra slots per block, conversions, levels, rotations and refresh schedule.

## F. Security and Correctness Interpretation

### `bossuat2022sparse`

Bossuat, J.-P., Troncoso-Pastoriza, J., & Hubaux, J.-P. (2022). Bootstrapping for approximate homomorphic encryption with negligible failure-probability by using sparse-secret encapsulation. In *Applied Cryptography and Network Security* (pp. 521--541). Springer. https://doi.org/10.1007/978-3-031-09234-3_26

- **Relevance:** Security/failure-probability basis used by modern CKKS bootstrap parameter sets.
- **Key findings:** Combines a dense main secret with a low-modulus sparse encapsulated secret so the main homomorphic capacity is not dictated by a globally sparse key (contributions p. 4). The reported example reaches 128-bit security and failure probability about `2^-138.7`, but only for its complete documented parameter/noise setup (abstract p. 1; evaluation pp. 16--20).
- **Method:** Security/noise analysis and bootstrap implementation experiments.
- **Quality:** Technology Level III; overall **A**.
- **Use:** Requires our manifest to archive both secret distributions, low-level switching modulus, total Q/P chain and failure model; a lone `N` value is insufficient.

### `alexandru2026application`

Alexandru, A., Al Badawi, A., Micciancio, D., & Polyakov, Y. (2026). Application-aware approximate homomorphic encryption. *IACR Communications in Cryptology, 2*(4). https://doi.org/10.62056/ayl83z10k

- **Relevance:** Formal boundary for calling an approximate/discrete CKKS instantiation correct and secure for a declared application.
- **Key findings:** Adds an application specification to correctness/security, permitting explicit circuits, bootstrapping locations and error estimation rather than relying on an application-agnostic label (abstract p. 1; contributions p. 5). Exact and approximate correctness require different games/estimators (pp. 7--8).
- **Method:** Cryptographic definition and implementation-guideline paper.
- **Quality:** Field-gold-standard theoretical primary work; overall **A**.
- **Use:** Governs the acceptance contract: fixed workload/domain, error estimator, parameter tuple and failure interpretation must travel together.

## Search and Verification Limitations

- This is a focused full-mode review plus a counterexample supplement, not a systematic review or meta-analysis.
- The original 15 source PDFs are locally frozen. Seven first-round supplemental artifacts remain official-web-only. Five DA2-rerun papers (HEGIDE, PPFE, Faster Logical Operations, Sparse Hermite and Character Block Encodings) are locally acquired and hashed; only HEGIDE, Sparse Hermite and Character Blocks enter the 25-source synthesis corpus.
- Semantic Scholar title search produced a false-positive candidate for the new LCPDTE title and the unauthenticated batch then hit HTTP 429; Tier-0 S2 status is therefore degraded, not silently recorded as verified. The original DOI-bearing entries were checked against Crossref and all 15 original primary PDFs were acquired and inspected; supplemental identities use the official records listed in `source_manifest.md`.
- Codex Web Search exposed no raw-total count for the 96 supplemental queries. `unavailable` is preserved per row in `da2_major1_query_ledger.md`; it does not mean zero hits.
- Cross-paper latency numbers use different schemes, machines, compilers, security definitions and batch filling. They support design hypotheses but are excluded from the local secure Pareto frontier unless re-instantiated under matched conditions.
- Publication status for the two 2026 focal papers follows the authoritative ePrint/conference records available on the acquisition date; proceedings pagination may not yet exist.
