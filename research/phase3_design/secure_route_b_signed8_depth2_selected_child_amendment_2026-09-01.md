# C75 preregistration — Route-B signed-int8 depth-2 selected-child evaluation

Date: 2026-09-01  
Status: initial graph preregistered before implementation; terminal exact-scale amendment registered before encrypted measurement; sign-to-GE correction registered after rejected diagnostic runs and before accepted measurement  
Scope: public binary-tree model, encrypted signed-int8 features, Lattigo N16/L11 Route B

## Question

Can the source-faithful LCPDTE depth-2 schedule be executed with the secure-parameter Gao conversion chain without evaluating both child comparisons? The circuit must perform one root comparison, select one encrypted child feature and threshold, perform one child comparison, and select one real leaf.

## Fixed model and predicate

- Predicate: `x >= t`; branch `0` is `<`, branch `1` is `>=`.
- Model fields are immutable: feature identifiers `(f0, fL, fR)`, thresholds `(t0, tL, tR)`, and leaves `(l00, l01, l10, l11)`.
- The constructor derives every model operand. The online API admits only the encrypted feature vector bound to those identifiers.
- Signed values use the existing two's-complement `Z_256` encoding and the existing same-width no-overflow certificates.

## Registered circuit

### Root comparison and selector restoration

1. Compute `x[f0] - t0` at `L20/S`.
2. Execute the frozen two-round Route-B A2B and retain its high-nibble MSB at `L5/S`.
3. Replace the ordinary sign broadcast by one four-diagonal phase broadcast. For each word, the MSB in column 3 is mapped to `(a0 b0, a1 b0, a2 b0, a3 b0)`, where `a0..a3` are the low four coefficients of `tau^-1` in `Z_256`. The transform is evaluated at `L4/q4` and rescaled to `L3/S`.
4. Apply the already registered two-factor `L3 -> L1` STC, observed `ScaleDown -> ModUp -> Trace`, and the installed three-factor C2S. Normalize only the already registered sub-`2^-40` C2S scale drift.
5. Evaluate the Gao degree-46 exponential operand, two ciphertext squarings, and the slotwise affine inverse `(z-1)/(exp(2*pi*i*a_j)-1)`. This restores the two's-complement sign `s0=[x[f0]-t0<0]` at `L8/R`, where `R = S^4/(q11^2 q10)`.

The root restoration must not evaluate the Gao ID/MSB LUTs. It is a periodic Boolean reraiser, not a third A2B round.

### Selected operands and child comparison

6. Condition `s0` with an exact plaintext scale `q8 q7 / R`, rescale to `L7/q7`, and form the tree selector `b0=[x[f0]>=t0]=1-s0` by one ciphertext negation and one public-one addition at the same exact scale.
7. Select the encrypted child feature with

   `x1 = x[fL] + b0 * (x[fR] - x[fL])`,

   and select the public-model threshold with

   `t1 = tL + b0 * (tR - tL)`.

   Both outputs must be `L6/S` root-slot words.
8. Compute `x1 - t1` and execute the registered low-ingress sign-only conversion:
   - drop to `L5/S`;
   - special-`b0` Z-to-C at `L5/q5`, producing `L4/S` halves;
   - low-mask/rescale to `L3/S`;
   - reuse the registered `L3 -> L1` STC and observed MR0/C2S;
   - evaluate Gao round 0, subtract `ID0/16` from the retained high half, and evaluate Gao round 1;
   - return only round-1 MSB at `L5/S`.

The sign-only path deliberately omits the full-A2B low-core self-removal and final high-core self-removal because neither is consumed by a signed comparison. This is the registered tree-aware A2Sign ablation.

9. Broadcast and complement the child sign at `L3/S` to obtain `b1 = [x1 >= t1]`.

### Bilinear terminal mux

The four-leaf function is evaluated as

`y = l00 + alpha*b0 + beta*b1 + gamma*b0*b1`,

where `alpha=l10-l00`, `beta=l01-l00`, and `gamma=l11-l10-l01+l00`.

- Use the already conditioned selector `b0` at exact scale `q7` and drop it from L7 to L3 without changing that scale.
- Compute and relinearize `b0*b1` at `L3/(q7*S)` without an intermediate rescale.
- Encode the alpha operand at `L3/q3`, the beta operand at `L3/(q3*q7/S)`, and the gamma operand at `L3/(q3*q2/S)`. The alpha and beta terms each rescale once to `L2/q7`; the interaction term rescales twice, through `L2/(q7*q2)`, to `L1/q7`.
- Drop the two linear terms once and add the `L1/q7` base leaf. The non-power-of-two terminal scale is intentional and numerically close to `S`; all three paths reach it by exact scale algebra, with no metadata retag.
- The output is a real leaf repeated in all four slots of each active word.

This terminal-scale refinement was registered after scale-only TDD exposed a 128-bit `big.Float` rounding residue in the earlier `R -> S` inverse-scale construction and before any encrypted selected-child execution. Leaf plaintext scales use 256-bit metadata precision. The capacity envelope charges three L3 terminal plaintexts plus one L1 plaintext (`14` Q-polynomial levels). A later rejected diagnostic run (zero accepted artifacts) exposed that the periodic decoder returns the sign bit, not the GE branch bit; Amendment B therefore adds the exact `1-s0` step and one L7 public-one plaintext before the next run. The final phase-relative pre-guard/guarded requirement is `2,765,426,432 / 3,302,297,344` bytes.

## Fixed state spine

`root input L20 -> root high L5 -> phase L3 -> STC L1 -> CTS L17 -> periodic L8 -> conditioned L7/q7 -> selected operands L6/S -> child special halves L4 -> child mask L3 -> child STC L1 -> child CTS L17 -> child high L5 -> child GE L3/S -> terminal output L1/q7`.

No metadata-only level raise is permitted. The only metadata-only scale normalization is the already bounded observed C2S drift.

## Required controls

1. Four paths `00, 01, 10, 11` must all occur.
2. `x=t` at the root and at both possible child thresholds must route right.
3. A wrong ordinary all-one broadcast used in place of the `tau^-1` phase broadcast must fail the selector oracle.
4. A child conversion that omits `ID0/16` must fail on at least one signed byte.
5. Model, feature binding, parameter, transform, key, state-ledger, timing-ledger, and output-payload mutations must fail closed.
6. Inputs and cached operands must remain byte-identical.

## Acceptance gate

- One fresh process builds and installs the canonical Route-B artifact, encrypts the bound feature vector, executes the complete selected-child circuit, decrypts, and validates every output slot.
- At least 512 queries are used, with all signed root bytes represented twice, all four paths present, and explicit equality cases for `t0`, `tL`, and `tR`.
- Real and imaginary error tolerance: `5e-4`; mismatch count must be zero.
- Construction counters, process peak RSS, setup/online/post-verification/lifecycle wall times, operation counts, exact state ledger, key inventory, and SHA-256 evidence are recorded.
- The resulting evidence is `security_unverified` until the mandatory independent security/integrity review and an estimator-backed classical-security claim are complete.

## Non-claims

This gate does not establish private-model evaluation, arbitrary-depth trees, float32 parity, a matched speedup over C73 or the BFV/BGV baseline, radix-tree improvement, repeated-run performance, or a final 128-bit security claim.
