# Candidate Bibliography and Verification Ledger

Status legend: `primary-verified` means title/authors/version or DOI has been checked against a primary/authoritative record; `full-text-pending` means the bibliographic record is known but the relevant technical passage still needs extraction; `code-pending` means an implementation link is known but not yet pinned or built; `context-only` means a real primary source was inspected but is outside the frozen final-corpus criteria.

| ID | Work | Venue / record | Role | Peer reviewed | Status |
|---|---|---|---|---:|---|
| PDTE-1 | Park, Cha, Lee, *LCPDTE: Low-Complexity Private Decision Tree Evaluation over Homomorphic Encryption* | ACM CCS 2026; IACR ePrint 2026/1263 | Focal protocol and local repository | Yes | primary-verified; full text inspected |
| ALU-1 | Gao, Zheng, *FHE for SIMD Arithmetic Logic Units with Amortized O(1) Bootstrapping per Ciphertext* | CRYPTO 2026; IACR ePrint 2026/233, major revision | Focal integer/Boolean CKKS construction | Yes | primary-verified; full text and code inspected; checkout pinned; clean build externally blocked |
| PDTE-2 | Azogagh et al., *PROBONITE* | WAHC 2022; DOI `10.1145/3560827.3563377`; ePrint 2022/936 | One-branch-only comparison/traversal ancestor | Yes | DOI metadata and full text verified |
| PDTE-3 | Cong et al., *SortingHat* | ACM CCS 2022; DOI `10.1145/3548606.3560702`; ePrint 2022/757 | Packed/transciphered PDTE baseline | Yes | DOI metadata and full text verified |
| PDTE-4 | Akhavan Mahdavi et al., *Level Up* | ACM CCS 2023; DOI `10.1145/3576915.3623095`; arXiv 2309.06496 | Leveled-HE comparison/PDTE baseline | Yes | DOI metadata and full text verified |
| PDTE-5 | Cong et al., *Faster Private Decision Tree Evaluation for Batched Input from Homomorphic Encryption* | SCN 2024; DOI `10.1007/978-3-031-71073-5_1`; ePrint 2024/662 | Fast prior amortized baseline named by LCPDTE | Yes | DOI metadata and full text verified |
| PDTE-6 | Liang et al., *BPDTE: Batch Private Decision Tree Evaluation via Amortized Efficient Private Comparison* | IACR ePrint 2024/619 | RCC/RDCMP and batch comparison baseline | Not established from current record | primary PDF and full text verified; preprint-only caveat |
| DCKKS-1 | Bae et al., *Bootstrapping Bits with CKKS* | EUROCRYPT 2024; DOI `10.1007/978-3-031-58723-8_4`; ePrint 2024/767 | Bit bootstrap and discrete CKKS basis | Yes | DOI metadata and full text verified |
| DCKKS-2 | Bae et al., *Bootstrapping Small Integers with CKKS* | ASIACRYPT 2024; DOI `10.1007/978-981-96-0875-1_11`; ePrint 2024/1637 | Small-integer functional bootstrap | Yes | DOI metadata and full text verified |
| DCKKS-3 | Drucker et al., *BLEACH: Cleaning Errors in Discrete Computations over CKKS* | Journal of Cryptology 37(1); DOI `10.1007/s00145-023-09483-1` | Error cleaning and Boolean CKKS | Yes | DOI metadata and full text verified |
| DCKKS-4 | Alexandru, Kim, Polyakov, *General Functional Bootstrapping Using CKKS* | CRYPTO 2025; DOI `10.1007/978-3-032-01881-6_10` | General LUT/function bootstrap | Yes | DOI metadata and full text verified |
| INT-1 | Kim, *Efficient Homomorphic Integer Computer from CKKS* | TCHES 2025; IACR ePrint 2025/066 | Digit/radix CKKS integer and range-aware carry/comparison alternative | Yes | primary PDF/full text verified; publication status corrected from the official ePrint record |
| INT-2 | Boneh, Kim, *Homomorphic Encryption for Large Integers from Nested Residue Number Systems* | CRYPTO 2025; DOI `10.1007/978-3-032-01881-6_11` | Large-integer alternative and discrete bootstrap dependency | Yes | DOI metadata and full text verified |
| SEC-1 | Bossuat, Troncoso-Pastoriza, Hubaux, *Bootstrapping for Approximate Homomorphic Encryption with Negligible Failure-Probability by Using Sparse-Secret Encapsulation* | ACNS 2022; DOI `10.1007/978-3-031-09234-3_26`; ePrint 2022/024 | Sparse-secret and failure-probability basis for parameter claims | Yes | DOI metadata and full text verified |
| SEC-2 | Alexandru et al., *Application-Aware Approximate Homomorphic Encryption: Configuring FHE for Practical Use* | IACR Communications in Cryptology 2(4), 2026; DOI `10.62056/ayl83z10k` | Application-aware correctness/security interpretation | Yes | DOI metadata and full text verified |
| CODE-1 | `tsinghua-ideal/fhe-simd-alu` | GitHub | Authoritative Gao--Zheng implementation | N/A | checkout and submodules pinned; source inspected; clean build transcript preserved |
| CODE-2 | `tuneinsight/lattigo` v6.1.1 plus four local patches | GitHub / local vendor tree | Target implementation substrate | N/A | version and local patch delta verified |

## DA2 Major 1 Supplemental Inclusions

| ID | Work | Venue / record | Role | Peer reviewed | Status |
|---|---|---|---|---:|---|
| PDTE-7 | Lee et al., *HEaaN-ID3: Fully Homomorphic Privacy-Preserving ID3-Decision Trees Using CKKS* | *Computers, Materials & Continua* 84(2), 2025; DOI `10.32604/cmc.2025.064161` | Direct multiway/categorical CKKS tree counterexample | Yes | official publisher full text inspected; primary-verified |
| PDTE-8 | Lu et al., *PEGASUS: Bridging Polynomial and Non-polynomial Evaluations in Homomorphic Encryption* | IEEE S&P 2021; ePrint 2020/1606; IEEE Xplore 9519408 | Direct hybrid CKKS--FHEW private-tree antecedent | Yes | IACR/IEEE record and paper decision-tree application inspected; author code record verified |
| PDTE-9 | Shin et al., *Fully Homomorphic Training and Inference on Binary Decision Tree and Random Forest* | ESORICS 2024; ePrint 2024/529 | Direct CKKS encrypted-model/encrypted-input tree antecedent | Yes | IACR publication relation and primary abstract/full paper inspected |
| PDTE-10 | Petrean, Potolea, *Random Forest Evaluation Using Multi-Key Homomorphic Encryption and Lookup Tables* | *International Journal of Information Security* 23, 2024; DOI `10.1007/s10207-024-00823-1` | Encrypted-model tree-to-LUT and encrypted-index selection antecedent | Yes | Springer full text inspected; primary-verified |
| SEL-1 | Cheon, Choe, Park, *Tree-based Lookup Table on Batched Encrypted Queries using Homomorphic Encryption* | *Journal of the Korean Mathematical Society*; DOI `10.4134/JKMS.j240423`; ePrint 2024/087 | Direct CKKS encrypted-query LUT selector baseline | Yes | official IACR record and abstract complexity inspected; primary-verified |
| SEL-2 | Cheon, Jang, Kang, Rhee, *Private Embedding Lookup with Encrypted Compact Queries under Fully Homomorphic Encryption* | arXiv:2606.03191v3 | Recent CKKS encrypted-scalar-index/IVE selector alternative | No | author-posted preprint inspected; explicitly preprint-only |
| INT-3 | Cha, Park, Lee, *Improved Radix-based Approximate Homomorphic Encryption for Large Integers via Lightweight Bootstrapped Digit Carry* | EUROCRYPT 2026 major revision; ePrint 2025/1740 | Current radix carry/comparison alternative | Yes | official ePrint publication relation and primary abstract inspected |
| PFE-1 | Dumezy et al., *HEGIDE: A MIMD Oblivious Processor for Private Function Evaluation over CKKS* | ACM CCS 2026; ePrint 2026/1187 | Discrete-CKKS private-program/private-data processor and direct depth-4 decision-tree baseline | Yes | official full text locally acquired; source release still planned in paper |
| DCKKS-5 | Alexandru et al., *Sparse Hermite Interpolation Method for Discrete-CKKS Functional Bootstrapping* | ePrint 2026/1026 | Current noise-cleaning/functional-bootstrap substrate and OpenFHE implementation baseline | No | official full text locally acquired; preprint and unreleased-code caveats |
| DCKKS-6 | Dumezy, Suvanto, *Character Block Encodings for Discrete CKKS: Single-Level LUTs and Low-Depth Arithmetic* | ePrint 2026/1200 | Lattigo single-level LUT, native modular-operation and low-depth radix-comparison baseline | No | official full text locally acquired; official record says preprint and code release is future work |

## DA2 Material Candidates Not Added to the Final Corpus

| Candidate | Primary record | Disposition | Reason |
|---|---|---|---|
| Akavia et al., *Privacy-Preserving Decision Trees Training and Prediction* | ePrint 2021/768; DOI `10.1145/3517197` | context-only | CKKS/FHE decision-tree antecedent, but its lightweight interaction violates the frozen non-interactive criterion. |
| Frery et al., *Privacy-Preserving Tree-Based Inference with Fully Homomorphic Encryption* | ePrint 2023/258 | context-only | TFHE tree/RF/GBT inference with a different model-privacy boundary; no target CKKS composition. |
| Bergerat et al., *Parameter Optimization & Larger Precision for (T)FHE* | ePrint 2022/704 | excluded | Radix/CRT and tree-PBS primitive; not ML decision-tree evaluation. |
| Azogagh et al., *RevoLUT* | ePrint 2024/1935 | excluded | General TFHE oblivious LUT/array library, not CKKS PDTE. |
| Azogagh, Delfour, and Killijian, *Oblivious Turing Machine* | ePrint 2023/1643 | excluded | General blind memory/control-flow machinery, not a CKKS decision-tree evaluator. |
| Mazzone et al., *Efficient Ranking, Order Statistics, and Sorting under CKKS* | USENIX Security 2025 official page | context-only | Approximate comparator/rotation framework; not exact modular comparison or secret-index tree selection. |
| Zhou et al., *Preprocessed Private Function Evaluation* | ePrint 2026/1631; ACM CCS 2026 | context-only | Private LUT and index with preprocessing and interactive online execution; not CKKS, non-interactive PDTE or encrypted tree traversal. |
| Kim, *Faster Logical Operations from Discrete CKKS* | ePrint 2026/732 | context-only | Converts BFV/GBFV ciphertexts to discrete CKKS for logical operations; relevant to BFV/BGV baselines but not the target pure-CKKS triangle/tree composition. |

The updated scholarly corpus contains 25 sources. Twenty-one have an established peer-reviewed venue (84%); `liang2024bpdte`, `cheon2026embedding`, `alexandru2026sparsehermite`, and `dumezy2026characterblock` are explicitly preprint-only on their official records. `zhou2026ppfe` and `kim2026fasterlogical` were screened and retained as context-only, outside the 25-source synthesis denominator. Code repositories remain outside this denominator. The supplement is a focused counterexample search, not a claim of exhaustive or systematic-review coverage.
