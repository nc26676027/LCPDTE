# Route-B signed-int8 depth-2 selected-child reproduction report

Date: 2026-09-01  
Status: accepted author-side functional reproduction artifact; security unverified

## Outcome

The Lattigo N16/L11 Route-B implementation now executes the complete
source-ordered depth-2 schedule for a public binary-tree model: compare the
root, restore its encrypted branch selector, select exactly one encrypted
child feature and threshold, compare that child, and select one of four real
leaves. The canonical run evaluates 512 SIMD queries, covers the complete
signed-byte root domain twice, exercises all four paths and the three equality
classes, and validates all 2,048 decrypted output slots with zero mismatches.

The registered predicate is `x >= t`; equality therefore follows branch one.
The frozen model is:

```text
feature IDs = [0, 1, 2]
thresholds  = [0, -4, 3]
leaves      = [-1.25, 2.5, -3.75, 5]
```

The online graph performs no decryption oracle and no plaintext branch
decision before producing the final ciphertext.

## Circuit

```text
root CT-PT comparison at L20/S
  -> complete two-round 8-bit A2B
  -> inverse-root-weighted sign phase at L3/S
  -> supplemental L3-to-L1 STC + observed MR0/C2S
  -> Gao periodic Boolean recovery
  -> exact sign conditioning and b0 = 1 - sign at L7/q7
  -> encrypted child feature and public threshold selection at L6/S
  -> low-ingress tree-aware A2Sign
  -> child b1 = 1 - sign at L3/S
  -> l00 + alpha*b0 + beta*b1 + gamma*b0*b1 at L1/q7
```

The root conversion retains the frozen complete A2B circuit. The child
conversion is the registered A2Sign ablation: it executes the low-ingress
special-`b0` transform, mask, second STC/MR0, two Gao rounds and the required
`ID0/16` high-half update, but omits the low-core and final high-core
self-removal values that a signed comparison does not consume. This is an
implemented tree-specific reduction in work, not yet a repeated performance
claim.

## Canonical evidence

Artifact:
`research/reproduction/route_b/route_b_signed8_depth2_selected_child_2026-09-01.json`

| Field | Measured value |
|---|---:|
| JSON bytes | 296,089 |
| JSON SHA-256 | `4a7fbd447dc8e127ff5392c3b3f22bf4a9f420edf4c30622445db76e965abbb2` |
| Queries / root-domain values | 512 / 256 |
| Output slots | 2,048 |
| Path counts `[00,01,10,11]` | `[127,129,130,126]` |
| Root / selected-left / selected-right equality cases | `2 / 2 / 2` |
| Mismatches | 0 |
| Accuracy tolerance | `5e-4` |
| Maximum real absolute error | `5.917360885732137e-7` |
| Maximum imaginary magnitude | `3.2190798723753435e-7` |
| Build wall time | 6.2207717 s |
| Setup wall time | 26.4030390 s |
| Online wall time | 73.7762091 s |
| Postprocess wall time | 0.6222472 s |
| Whole lifecycle wall time | 101.7464627 s |
| Build peak RSS | 3,273,859,072 B |
| Post-install peak RSS | 6,613,004,288 B |
| Post-evaluation peak RSS | 13,889,568,768 B |
| DFT-construction counter delta | `[0,0,0,4]` |

Authenticated identities:

| Item | SHA-256 |
|---|---|
| Selected-child report | `93876cd488dc3b9b7d9e1535ceec34c82a80a537391a2240fd52b31ca5036d1d` |
| Capacity plan | `4b5b8c4a936182f636e8cffb09c1aa848c8e4d851bfa83fc84aeee0aaf9a83cc` |
| Output ciphertext payload | `f2a8f02c896d6823740ea2e75b664030c5910ed75128a124a048334707f266c8` |
| Root periodic Boolean report | `ddfac852459bfdcbceee6ebff6f2accbdf811d15f6e5b628779920a4127def2a` |
| Child A2Sign report | `19fab5ebc007a4d181b614c403280cfec62286f566a155c6b73eabafc27724c4` |
| Supplemental L3-to-L1 STC | `bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a` |
| Root phase source / compiled transform | `c69767e8c57d7ac30e45f439444f98a151110612c86093987782204820c88a25` / `f9b7cad75ec046891cb4dd065634661bcd94102a3690f21aa2d7cf6088abb556` |
| Canonical model / feature binding | `373329565bb8d92693362edfb2969f8d37d61028be0f0f9510b033c33d2a2432` / `eb808b03ab6eef1d5939e798039d16f1c65debc4515567910b341d2f7d0a547c` |
| Canonical parameters | `c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816` |

The four terminal operands are separately bound by
`e80c7642...5cb5c93`, `e7cac5d2...178a31`, `9e049fc6...4ecea1`, and
`409a2fff...6f58`.

## Exact level and scale spine

The report binds 32 ciphertext states. All states are degree one, batched,
NTT-form and use N16/L11 dimensions.

| Stage | Level | Exact scale |
|---|---:|---|
| Three feature inputs; root difference | 20 | `S = 0x1p+43` |
| Root high-nibble MSB | 5 | `S` |
| Root phase | 3 | `S` |
| Root phase STC / normalized C2S | 1 / 17 | `S / S` |
| Root periodic sign | 8 | `0x1.ffff41802e86b69715852fbfcc0f84ecp+42` |
| Conditioned root sign and GE selector | 7 | `q7 = 0x1.ffffce00004p+42` |
| Selected feature, threshold and difference | 6 | `S` |
| Child high MSB / child GE selector | 5 / 3 | `S / S` |
| Terminal product | 3 | `q7*S` |
| Alpha and beta terms | 2 | `q7` |
| Gamma term; selected leaf | 1 | `q7` |

All registered level changes are physical drops or rescales. The only
metadata-only scale normalization is the previously authenticated C2S drift
from `0x1.0000000000000002f2901f1f8cf04128p+43` to `S`, whose absolute
log2 drift is below `2^-40`. Exact-scale comparison uses the numeric value,
precision and rounding mode rather than the historical `big.Float.Acc()`
flag.

## Operation and timing ledger

The selected-child report wall time is 69.6711752 s. Its complete root A2B
takes 30.1297464 s, and the child A2Sign subgraph takes 20.9139054 s. The
first observed MR0 before the selected-child graph takes 5.2413313 s; the
root phase MR0 takes 5.2711436 s. These are nested timings from one canonical
run and must not be added as independent samples.

The wrapper records two public-threshold subtractions, one complete root A2B,
one root phase broadcast, three supplemental slots-to-coefficients calls,
three additional MR0 calls, one periodic Boolean invocation, one root
conditioner product, one encrypted child-feature selector product, one public
threshold-selector product, one A2Sign invocation, one child sign broadcast,
one terminal ciphertext product, three terminal plaintext products, nine
online rescales and two additional relinearizations. The logical peak wrapper
ledger is 20 ciphertexts. Decryption-oracle and plaintext-branch counts are
both zero.

The A2Sign report explicitly records one input drop, one special-`b0`
transform, two half-output rescales, two mask products/rescales, two STCs, two
MR0 invocations, two Gao kernels, one `ID0/16` product/rescale and one
high-core subtraction. It returns one Boolean ciphertext and records both
unused self-removal omissions.

## Capacity evidence

The `signed8-depth2-selected-child` first-operation gate was sampled before
online HE dispatch.

| Field | Bytes |
|---|---:|
| Total physical memory | 33,618,251,776 |
| Available memory at admission | 13,761,712,128 |
| Pre-guard incremental requirement | 2,765,426,432 |
| Guarded requirement | 3,302,297,344 |
| Remaining below the strict 80% limit | 3,735,764,428 |

The final envelope charges the root conditioner, the low-ingress A2Sign
artifacts, three level-3 terminal plaintexts and one level-1 base plaintext.

## Fail-closed diagnostics

No rejected run wrote the canonical artifact. The pre-acceptance sequence
exposed and corrected five independent evidence or semantic errors:

1. The first terminal scale formula used an algebraically different operand
   order. The exact terminal schedule was amended before encrypted
   measurement.
2. Numerically identical `big.Float` values carried different historical
   accuracy flags. Scale identity was narrowed to exact numeric metadata.
3. The A2Sign ledger expected 15 states while the executable graph emitted
   the registered 16 states.
4. The base leaf was initially encoded at `S`; the exact terminal endpoint
   requires `q7`.
5. A complete diagnostic execution produced the complementary tree paths:
   periodic recovery returns the sign bit `[x-t<0]`, while the tree consumes
   `[x-t>=0]`. The preregistration was amended with the exact `1-sign`
   conversion before the accepted run.

Tests reject malformed models and range certificates, foreign feature
bindings, wrong scale/state/operation ledgers, changed transform and operand
identities, output mutations, and replacement of the root public-one operand
with the conditioner operand.

## Descriptive comparison with all-node batching

C73 and C75 now provide two Route-B depth-2 schedules on the same N16/L11
parameter family:

| Schedule | Queries | Comparisons represented per query | Circuit wall | Query throughput |
|---|---:|---:|---:|---:|
| C73 all-node batch | 170 | 3 | 28.8937126 s | 5.884 query/s |
| C75 selected child | 512 | 2 | 69.6711752 s | 7.349 query/s |

These ratios are descriptive single-run values. C73 evaluates 510 node words
in parallel with one complete A2B and spends three words per query; C75 keeps
one word per query but serializes root selector restoration and a second
comparison. A matched repeated benchmark must separate latency, query
throughput, compared-node throughput, key material and memory before making a
performance claim.

## Reproduction and replay

```powershell
go run ./cmd/route-b-signed8-depth2-selected-child `
  -out research/reproduction/route_b/route_b_signed8_depth2_selected_child_2026-09-01.json

go test ./cmd/route-b-signed8-depth2-selected-child `
  -run TestAcceptedRouteBSigned8Depth2SelectedChildArtifactReplaysEverySlot -count=1

go test ./integer/secureeval ./integer/secureprofile -count=1
go vet ./integer/homchain ./integer/secureeval ./integer/secureprofile `
  ./cmd/route-b-signed8-depth2-selected-child
```

The command-package hash-locked replay passes. Focused C75, complete
`secureeval`, `secureprofile`, and relevant vet gates passed during the
canonical run. The complete `homchain` package did not finish within the
30-minute package timeout because its long encrypted integration tests are
co-located; no assertion failure was observed, but this is not recorded as a
pass. Split-suite execution remains a downstream verification gate.

## Evidence boundary

This artifact establishes the declared public-model, signed-int8, trusted
no-overflow, source-ordered selected-child function for one canonical Route-B
batch. It establishes neither private-model security nor ordered-float32
parity with the CCS implementation. It also does not establish arbitrary
depth, representative forests, repeated performance, a speedup over C73 or
BFV/BGV baselines, a radix-tree gain, or a final 128-bit application-security
claim. Those claims remain separate ARS acceptance gates.

