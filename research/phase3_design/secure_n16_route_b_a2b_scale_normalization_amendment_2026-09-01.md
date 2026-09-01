# Secure N16 Route-B A2B scale-normalization amendment

**Date:** 2026-09-01  
**Stage:** ARS Stage 2 engineering gate  
**Status:** registered before any successful canonical first-A2B-round run  
**Scope:** the single metadata boundary between the observed Route-B MR0
output and the frozen Gao N16/L11 kernel input

## Trigger and prior-run disposition

Four first-round composition attempts reached the registered HE path but did
not publish a result JSON.  The first exposed an evaluator-key-wrapper mismatch
and was corrected by deriving a memory-key view from the already authenticated
installed evaluator.  The next two stopped at the Gao kernel's exact input-scale
gate.  All other recorded boundary fields agreed with the frozen contract:
level 17, degree 1, `LogN=16`, batched NTT form, dimensions `(0,11)`, and 2,048
active slots.

The sole discrepancy was the exact scale emitted by the observed
`ModUp -> Trace -> CoeffsToSlots` path:

| Quantity | Registered value |
|---|---|
| observed source | `0x1.0000000000000002f2901f1f8cf04128p+43` |
| kernel target | `0x1p+43` |
| `abs(log2(source/target))` | `2.3052091909425391e-19` |
| admission bound | `2^-40 = 9.094947017729282e-13` |

The observed drift is about 3.95 million times smaller than the bound.  It is a
scale-bookkeeping difference, not a ciphertext-domain or level transition.
After the normalization contract was registered, the fourth attempt executed
the Gao kernel and then exposed an over-constrained report validator: it had
incorrectly required the default scale at both explicit squaring boundaries.
The kernel already proves each rescale against
`previous_scale^2 / Q[previous_level]`; the report now derives and binds those
two exact canonical scales while retaining the default-scale requirement at
the kernel input, polynomial outputs, and recovered ID/MSB outputs.  The four
unsuccessful attempts remain diagnostic events only; they authorize no
correctness, performance, or reproducibility claim.

## Registered normalization

Immediately after retaining an immutable snapshot of the raw MR0 output, the
first-round dispatcher may assign the target scale to a copy of that same
ciphertext metadata.  This assignment is authorized only when all of the
following hold:

1. the source scale exactly equals the registered hexadecimal value above;
2. the target scale exactly equals `0x1p+43`;
3. `abs(log2(source/target)) <= 2^-40`;
4. an equality proof after replacing the scale in both snapshots shows that
   every ciphertext coefficient and every non-scale metadata field is
   unchanged; and
5. the Gao kernel's original exact-`0x1p+43` input gate remains enabled.

Any different source value is rejected even if it happens to fall inside the
numeric bound.  Any bound violation, nil input, failed equality proof, or
downstream report mismatch is terminal under the installed-evaluator lineage.
No rescale, multiplication, `SetScale`, modulus consumption, re-encryption, or
coefficient rewrite is permitted at this boundary.

## Lattigo semantic basis

This operation follows the scale-metadata semantics already used by pinned
Lattigo v6.1.1.  Its bootstrapping implementation assigns the residual default
scale to each `BootstrapMany` output, and its `EvalMod` and `EvalModAndScale`
endpoints assign the bootstrapping default scale directly after their numerical
circuits.  Those assignments do not consume a modulus level.  The registered
operation is narrower: it accepts one exact, observed source/target pair and
proves that only `Ciphertext.MetaData.Scale` changes.

The evidence is bound into the first-round report as:

- a new raw `iter0-mr0-output` state at level 17 carrying the non-target source
  scale and `scale_exact=false`;
- source, target, measured absolute log2 drift, bound, and
  `metadata_only=true` fields; and
- the report digest, which covers those fields and all fourteen ciphertext
  boundaries.

## Claim boundary

This amendment authorizes only the frozen first low-nibble A2B round.  It does
not authorize a second round, a complete 8-bit A2B conversion, comparator or
decision-tree correctness, security equivalence, or a performance claim.  A
successful canonical run must still pass the live capacity gate, installed
resident/evaluator checks, all-slot ID/MSB oracle validation, replay validation,
and evidence-file hashing.
