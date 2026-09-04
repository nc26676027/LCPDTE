# LCPDTE

Code for the paper:
> **Low-Complexity Private Decision Tree Evaluation over Homomorphic Encryption**
> *ACM CCS 2026*

Implementation of the **LCPDTE** protocol — a CKKS-based non-interactive Private Decision Tree Evaluation (PDTE) scheme with end-to-end server complexity O(p · √2^D), where D is the tree depth and p is the input bit-length.

---

## Integer CKKS library

The supported Go library entry point is
`github.com/nc26676027/LCPDTE/ckksint`. It packages the Gao--Zheng modular
integer representation, full 8-bit A2B/B2A, signed comparison, and the
canonical Route-B selected-child depth-2 evaluator behind a client/server API.
Runnable programs are under [`examples/ckksint`](examples/ckksint); the API is
documented in [`ckksint/README.md`](ckksint/README.md).

```bash
go test -count=1 ./ckksint
go run ./examples/ckksint/basic
go run ./examples/ckksint/conversion
go run ./examples/ckksint/depth2
go run ./examples/ckksint/routeb_depth2
```

`routeb_depth2` is the full N=2^16 workflow: setup and key generation, client
encryption, server evaluation, client decryption, and an independent plaintext
check. The other three examples use the small `DemoOnly` profile for fast API
experiments.

Compare the complete 8-bit A2B call with Gao et al.'s OpenFHE result:

```bash
go run ./cmd/compare-ckksint \
  -openfhe-log research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04/gao_openfhe_bench8_source.log \
  -lattigo-json research/reproduction/route_b/route_b_l11_a2b_full_2026-09-01.json
```

The report includes call latency, effective integer throughput, lane count,
ring dimension, word width, warmup/repeat policy, and source provenance. The
recorded source-artifact and same-host results are under
[`research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04`](research/reproduction/benchmarks/gao_openfhe_vs_lattigo_2026-09-04).

---

## Requirements

**Go 1.23.11** (the version declared by `go.mod`) or a compatible newer Go
toolchain.

```bash
go version
```

The upstream LCPDTE experiments target Linux. The integer CKKS library and its
acceptance examples are also tested on Windows.

---

## Experimental Environment

All results in the paper were obtained on the following hardware:

| Component | Spec |
|-----------|------|
| CPU | AMD Ryzen 9 7900X |
| RAM | 128 GB |
| OS | Linux |

> **Note:** Some experiments (e.g., `obo` and `bsgs` at large depths) require significant RAM. At D=12, our method uses approximately 34 GB. Variants without BSGS or OBO may exceed 128 GB and are expected to fail on smaller machines.

---

## Running Experiments

Run experiments from the repository root:

```bash
go run . -m <mode>
```

| Flag | Alias | Description |
|------|-------|-------------|
| `-mode <mode>` | `-m <mode>` | Select experiment mode |

**Examples:**
```bash
go run . -m tree
go run . -mode boosting
```

---

## Experiment Modes

The `MODE` variable (set via `-m`) selects which experiment to run. The table below maps each mode to the corresponding paper results.

| Mode | Paper Reference | Description |
|------|----------------|-------------|
| `tree` | Table 5, Figure 1–5 | Main single-tree evaluation. Produces Table 5 and Figures 1–2 directly. Also serves as the **blue reference line** in Figures 3, 4, and 5 (using CMP/BTS/TRAV breakdown from the output). |
| `obo` | Figure 3 (orange) | Produces the **w/o OBO** line in Figure 3 (all-node O(2^D) comparison baseline). Reports `avg_meanAbs` and `global_maxAbs` only; `matchRate=0%` is expected, as this mode checks comparison accuracy only, not end-to-end tree evaluation. |
| `bsgs` | Figure 4 (orange) | Produces the **w/o BSGS** line in Figure 4 (naive O(2^D) traversal baseline). |
| `boosting` | Figure 5 (orange) | GBDT evaluation with level-major evaluation and batched bootstrapping (K=8, T=8). Reports total runtime across all components; Figure 5 (orange) is derived by taking the BTS time from the output and dividing by K to obtain per-tree BTS time. |
| `parse` | Table 6 | End-to-end validation on pre-trained XGBoost models (Credit Card Fraud dataset, D∈{8,10,12}, K=8). |

---

## Key Parameters

Defined in `main.go`:

| Variable | Description |
|----------|-------------|
| `GEN.K` | Number of trees for batched bootstrapping. `K = 1` = standard (non-batched) setting. Must satisfy `K ≤ T`. |
| `D` | Maximum tree depth to evaluate (default: 12). Experiments iterate depths 2, 3, ..., D. Set to a smaller value to run only low-depth experiments and reduce total runtime. (`parse` mode is unaffected; it always runs D∈{8,10,12}.) |
| `T` | Number of trees (for `boosting` mode) |

---

## Runtime

**Approximate wall-clock runtimes** (on the reference hardware, N=32768 slots):

> The output summary reports *amortized* time per slot (ms/slot). Total wall-clock time is `amortized_time × 32768`.

| D | `tree` | `obo` | `bsgs` | `boosting` | `parse` |
|---|--------|-------|--------|------------|---------|
| 2 | 37 s | 20 s | 38 s | 164 s | — |
| 3 | 64 s | 53 s | 60 s | 319 s | — |
| 4 | 99 s | 122 s | 87 s | 494 s | — |
| 5 | 130 s | 247 s | 113 s | 681 s | — |
| 6 | 178 s | 533 s | 148 s | 965 s | — |
| 7 | 227 s | 1073 s | 190 s | 1287 s | — |
| 8 | 294 s | 2168 s | 248 s | 1726 s | 1816 s |
| 9 | 395 s | 4330 s | 351 s | 2479 s | — |
| 10 | 585 s | 9855 s | 571 s | 3865 s | 2926 s |
| 11 | 874 s | 19726 s | 1021 s | 6134 s | — |
| 12 | 1383 s | OOM | OOM | 10082 s | 5770 s |

> **Warning:** Full reproduction of all paper figures (`tree`, `obo`, `bsgs`, `boosting` across D=2–12) requires running many depth settings and may take **tens of hours** in total.

---

## Sanity Check (`MODE = parse`)

Pre-trained XGBoost models and preprocessed data are provided for the [Credit Card Fraud Detection](https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud) dataset (Kaggle, CC BY-SA 4.0).

### Provided Files

| Path | Description |
|------|-------------|
| `xgbdata/xgb_model_d{8,10,12}.json` | Trained XGBoost models (depth 8, 10, 12) |
| `xgbdata/pred_d{8,10,12}.bin` | Plaintext model prediction outputs (ground truth) |
| `x_test.bin` | Preprocessed input test data (N=32768 queries) |

These files were generated by `xgboost/xgboost_test.ipynb` using `xgboost/creditcard.csv`.

> **Note:** The raw dataset (`creditcard.csv`) is not included due to its license. It can be downloaded from Kaggle. Running the notebook is only necessary if you want to retrain or modify the models — the provided files are sufficient to reproduce Table 6 as-is.

### Expected Result

Across all settings, the protocol should yield **MatchRate ≥ 99.95%** between plaintext and encrypted evaluation, as reported in Table 6.

### Python Dependencies (for notebook only)

```
python, ipython, xgboost, pandas, numpy
```

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

This project incorporates its patched [Lattigo v6.1.1](https://github.com/tuneinsight/lattigo)
source under [`lattigo`](lattigo) (Apache 2.0). Keeping the fork inside the
LCPDTE module gives repository builds and external `ckksint` consumers the
same implementation.
