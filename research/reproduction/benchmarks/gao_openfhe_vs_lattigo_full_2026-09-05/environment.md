# Acceptance environment

- Physical CPU: AMD Ryzen 7 H 255 with Radeon 780M Graphics; 16 logical CPUs exposed to WSL.
- WSL: Ubuntu 22.04.5 LTS, kernel `6.18.33.1-microsoft-standard-WSL2`, x86_64.
- WSL limit: 24 GiB memory and 8 GiB swap (`C:\Users\26676\.wslconfig`).
- Linux memory view: `MemTotal=24,608,408 KiB`, `SwapTotal=8,388,608 KiB`.
- Go: `go1.23.11 linux/amd64`; Lattigo build used `GOAMD64=v4`.
- C++: Ubuntu Clang 14.0.0; OpenFHE 1.4.0 with Intel HEXL 1.2.6 and native optimization.
- LCPDTE source: `1a3542521bffe640880c4d85ef75ae98770e698d`, clean at build.
- Pinned fhe-simd-alu source: `08f1eb87434e7be072cba889270a8400bbffc08e`, clean before and after driver injection.
- Focused OpenFHE driver SHA-256: `b2d9240dda138f040eaf76ee7afe55499474f1f9c6ec3184468b125bde23f87f`.
- Focused OpenFHE binary SHA-256: `9df7dffb381ab4202f69bf58f89f00a4df036915c75f6c3f41bfc93912eac79d`.
- Lattigo benchmark binary SHA-256: `905fe0b25ed90e43c256446f9d064426b8d7558569e7c135392b76ac395b8a7b`.

Run order (UTC):

1. OpenFHE build: 2026-09-04 16:36:00–16:36:45.
2. Lattigo build: 2026-09-04 16:36:58–16:37:08.
3. OpenFHE benchmark: 2026-09-04 16:37:27–16:45:21.
4. Lattigo benchmark: 2026-09-04 16:45:53–16:50:07.

The two benchmark processes ran serially without concurrent repository tests or agent work.
OpenFHE's whole process took 7:53.33 and peaked at 24,078,556 KiB RSS. Lattigo's
whole process took 4:14.15 and peaked at 18,537,824 KiB RSS. These lifecycle values
are recorded separately and are not substituted for the prepared-online sample ratios.

