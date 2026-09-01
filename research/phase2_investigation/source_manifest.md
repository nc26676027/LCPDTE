# Primary-Source Manifest

This manifest freezes the two principal manuscripts used for algorithm reconstruction. The PDF is the visual authority for mathematical notation, diagrams, pseudocode, and tables; the layout-preserving text is a searchable derivative and is never treated as an independent source.

| Source | Authors | Primary record | Local PDF | SHA-256 | Bytes / pages | Verification |
|---|---|---|---|---|---:|---|
| *LCPDTE: Low-Complexity Private Decision Tree Evaluation over Homomorphic Encryption* | Dongjin Park, Gyeongwon Cha, Joon-Woo Lee | IACR ePrint 2026/1263; received 2026-06-16, approved 2026-06-19; ACM CCS 2026 publication indicated by IACR and SIGSAC | `research/sources/eprint-2026-1263-lcpdte.pdf` | `AFA3F85BDE2E39EFB3D00665813381423D0AE2AD980650701B3315F32B0A947D` | 1,351,309 / 15 | Title/authors and metadata checked against IACR/SIGSAC; Algorithms 1--5 and Tables 4--6 checked in rendered PDF pages; searchable derivative generated with `pdftotext -layout`. |
| *FHE for SIMD Arithmetic Logic Units with Amortized O(1) Bootstrapping per Ciphertext* | Mingyu Gao, Hongren Zheng | IACR ePrint 2026/233, revision dated 2026-06-08; record identifies a major revision of the CRYPTO 2026 publication | `research/sources/eprint-2026-0233-fhe-simd-alu.pdf` | `DB361D68D8B4DF66EAAD287588AA38EDDCEA01D1812B13487F75742D98B807AD` | 940,139 / 48 | Title/authors and metadata checked against IACR; Definitions 9--15, A2B/B-A2B algorithms, security/parameter and benchmark tables checked in rendered PDF pages; searchable derivative generated with `pdftotext -layout`. |

## Authoritative URLs

- LCPDTE manuscript record: <https://eprint.iacr.org/2026/1263>
- CCS 2026 accepted-paper list: <https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html>
- Gao--Zheng manuscript record: <https://eprint.iacr.org/2026/233>
- Gao--Zheng authoritative code: <https://github.com/tsinghua-ideal/fhe-simd-alu>

## DA2 Supplemental Primary Records

These records were inspected through official sources on 2026-08-29. The first five rows below were acquired locally after the independent DA2 rerun; the older seven-row supplement remains official-web-only and is labeled accordingly.

| Citation key | Official primary record | Publication status | Technical locator used | Local snapshot |
|---|---|---|---|---|
| `dumezy2026hegide` | <https://eprint.iacr.org/2026/1187>; CCS 2026 accepted-paper list | ACM CCS 2026 | full paper §§1.2--1.3, 2.4, 4, 6.1--6.3 and App. C--D | `research/sources/hegide_2026_1187.pdf`; 828,751 bytes / 35 pages; SHA-256 `878EB134EB8091812237DE1F538555371D27BD773A60CEA5BAB28494C54856C7` |
| `alexandru2026sparsehermite` | <https://eprint.iacr.org/2026/1026> | official record: preprint | full paper §§1.1, 3--6 and Tables 1, 4--5 | `research/sources/sparse_hermite_2026_1026.pdf`; 2,006,440 bytes / 46 pages; SHA-256 `ACF9422E8A21E0BC891D305A6B49234EF87F4A25ECB277A7F159B90816C98C9F` |
| `dumezy2026characterblock` | <https://eprint.iacr.org/2026/1200> | official record: preprint; not present by title on the CCS 2026 accepted-paper list | full paper §§1, 3, 5--7 and Tables 1, 4, 6, 8 | `research/sources/character_block_2026_1200.pdf`; 846,901 bytes / 43 pages; SHA-256 `80D2331362C40F3FA4FF1185E06EF2134EC81F3D259C2B8084A5BC6B16D2FA7E` |
| `zhou2026ppfe` | <https://eprint.iacr.org/2026/1631>; DOI `10.1145/3830454.3832657` | ACM CCS 2026 | full paper §§1, 3--6 and App. C | `research/sources/ppfe_2026_1631.pdf`; 2,256,510 bytes / 21 pages; SHA-256 `0B41EB5532FD8EFCF524FB492DAC2C85F40011788E48386BE83A1AD6AFEE895F` |
| `kim2026fasterlogical` | <https://eprint.iacr.org/2026/732> | official record: preprint | full paper abstract, construction and comparison sections | `research/sources/faster_logic_2026_0732.pdf`; 564,744 bytes / 28 pages; SHA-256 `B832FED79DC5E9B44B1BD3E639869B99F519EAB4B1248EEAD2406198973B633A` |
| `lee2025heaanid3` | <https://doi.org/10.32604/cmc.2025.064161> | *Computers, Materials & Continua* 84(2), peer-reviewed journal article, 2025 | Publisher full text, Introduction and Section 8.4 | not acquired |
| `lu2021pegasus` | <https://eprint.iacr.org/2020/1606>; <https://ieeexplore.ieee.org/document/9519408> | IEEE S&P 2021, peer reviewed | IACR paper, Application II: Private Decision Tree Evaluation | not acquired |
| `shin2024hbdt` | <https://eprint.iacr.org/2024/529>; <https://doi.org/10.1007/978-3-031-70896-1_11> | ESORICS 2024, peer reviewed | IACR official abstract and Springer publication record | not acquired |
| `petrean2024mkrf` | <https://doi.org/10.1007/s10207-024-00823-1> | *International Journal of Information Security* 23, peer-reviewed journal article, 2024 | Publisher Sections 1.1 and 4.1.3--4.3.1 | not acquired |
| `cheon2025treelut` | <https://eprint.iacr.org/2024/087>; <https://doi.org/10.4134/JKMS.j240423> | *Journal of the Korean Mathematical Society*, peer reviewed | IACR official abstract and publication metadata | not acquired |
| `cheon2026embedding` | <https://arxiv.org/abs/2606.03191> | arXiv v3 preprint, not peer reviewed | Author-posted abstract | not acquired |
| `cha2026radix` | <https://eprint.iacr.org/2025/1740> | official record: major revision of an IACR EUROCRYPT 2026 publication | IACR official abstract and publication metadata | not acquired |

The existing `kim2025integer` local PDF remains frozen below. Its official record, <https://eprint.iacr.org/2025/066>, states “Published by the IACR in TCHES 2025”; the old preprint-only label is superseded.

## Reproducibility Notes

- Acquisition date: 2026-08-29 (Asia/Shanghai).
- The repository checkout used for the local CCS implementation is `f5ff611f7c023f7ec4d06af6cecaa8b5d33da607` on `main`; the upstream ALU checkout is pinned at `08f1eb87434e7be072cba889270a8400bbffc08e` on its default `fhe-simd-alu` branch, with submodule commits recorded in `upstream_oracle/provenance_build_source_map.md`.
- Page counts were confirmed during PDF inspection. Hashes were calculated over the exact local PDF bytes.
- Web records establish identity, version, authorship, and publication status. Technical claims are accepted only after confirmation in an official full text or abstract, the manuscript, authoritative source code, or a local measurement artifact. Abstract-only verification is labeled and is not used for finer claims than the abstract supports.

## Related-Work Full-Text Corpus

These PDFs are primary scholarly texts selected for full-text screening. Inclusion in the corpus does not imply that every paper will remain in the final synthesis; eligibility and use are recorded separately in the search and screening ledger.

| Local PDF | SHA-256 | Bytes / pages |
|---|---|---:|
| `research/sources/2022-0757-sortinghat.pdf` | `6D72D26C43F8B32A915D6498ECAEFF2C490001D14BE0AE867146103BDA310AB7` | 583,595 / 27 |
| `research/sources/2022-0024-sparse-secret-bootstrap.pdf` | `37863DF80532A7FEDCB65DFBF87A756D6CB08EE0D6FC51925C07CE2E9078F717` | 499,908 / 22 |
| `research/sources/2022-0936-probonite.pdf` | `A0B29B33538978FAF7F56E99E461175ECF1D12122E91EBF5C1C54FDCC1D94FB8` | 1,003,680 / 11 |
| `research/sources/2022-1298-bleach.pdf` | `ECE74A91A30F70D55B721F218EE9CD4F90FAC54849117D5AC62196CFE72A1B8D` | 1,795,930 / 39 |
| `research/sources/2023-2309.06496-level-up.pdf` | `4B3FF4A8E4D61C48F82B44EE495143DE9CEE97E0952478969FD6F4D7D1723AB7` | 1,037,587 / 14 |
| `research/sources/2024-0203-application-aware-he.pdf` | `A116CB905754E8A918964C1CFE60AD7DAE9D9A3965E68064A4F9E62734F44E6D` | 815,329 / 38 |
| `research/sources/2024-0619-bpdte.pdf` | `D5258BF2098728AA65D97BFEA4B9829E40DFBB8D8AD5292A862767A8D00CC779` | 1,174,663 / 19 |
| `research/sources/2024-0662-faster-pdte.pdf` | `624A7945C241333E7CC87C67C02F04CC9DEA98F20AAC368B65499AB8EEF8CAEF` | 758,048 / 22 |
| `research/sources/2024-0767-bootstrap-bits.pdf` | `B6D5BAE88A6E5E84E76CCDF336838D78A2F4E1A5E59254C3776FEDE16A1C4692` | 860,532 / 36 |
| `research/sources/2024-1623-general-functional-bootstrap.pdf` | `72F3CE0A332D79B5C5A58F6DC9117B3DE20AED8AAB73B119C69F700A58F8C629` | 964,428 / 52 |
| `research/sources/2024-1637-bootstrap-small-integers.pdf` | `B86FA885D71434B7D240BFCB2996F1895391D8F2AB04587B41772A7B209707F9` | 677,286 / 30 |
| `research/sources/2025-0066-integer-computer.pdf` | `B82F6B6DBE224B8063D4D34B7A68E6736CE29DD4E56B3952F2835B52635991E7` | 644,181 / 26 |
| `research/sources/2025-0346-nested-rns.pdf` | `7A26E911B00368DACE336F4324E8E3F036927A57683CF5FBEA1E26EE19777EF5` | 753,591 / 31 |

All thirteen files have matching `pdftotext -layout` derivatives. The PDF remains the authority for notation and tables.
