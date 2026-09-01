# CKKS security-parameter bundle and estimator-conversion contract

## Purpose

This contract separates four objects that must not be conflated:

1. the accepted `LogN=5` functional Lattigo circuits, which are deliberately insecure;
2. the Gao--Zheng paper summary tuple, whose published aggregate is not an exact Lattigo modulus chain;
3. a new exact Lattigo Gao-compatible candidate, which must be generated and measured locally;
4. the LCPDTE paper and effective-checkout tuples, which have different secret and modulus records.

No tuple becomes benchmark-eligible by inheriting a paper's `128-bit` label. Each local tuple requires its own exact parameter bundle and estimator transcript.

## Immutable bundle schema

The final deterministic bundle emitter must write canonical JSON containing:

- `schema_version`, `tuple_id`, `status`, `provenance`, source commit and generator digest;
- CKKS ring type, `log_n`, exact `N`, slot count and default scale;
- ordered decimal and hexadecimal `Q` and `P` primes;
- exact decimal and hexadecimal products `Q`, `P`, and `QP`, with integer bit lengths and SHA-256 digests;
- the residual/main secret distribution, including exact sparse Hamming weight and balanced sign convention;
- the bootstrapping/encapsulation secret distribution as a separate record;
- error distribution, standard deviation and truncation bound;
- relinearization, Galois, key-switch and bootstrap-key inventory, including every Galois element and decomposition parameter;
- the number of RLWE samples exposed under each secret/modulus pair, plus the derivation of that count;
- exact source/profile/circuit digests for any implementation claimed to use the tuple;
- explicit maturity labels for correctness, estimator status and application-aware security.

The final emitter must reject missing fields rather than serialize zero-value evidence. The current `ParameterManifest` authenticates exact primes, products and declared distributions while listing every missing runtime field. It is eligible for the separately labeled unlimited-sample sensitivity transcript, but it cannot be promoted or renamed as the complete application-security bundle. JSON key order, integer spelling and array order are part of either artifact's digest.

## Frozen tuple identities

### `lattigo-functional-a2b-n8-v1`

- Source: accepted fixed functional circuit.
- `LogN=5`, `LogQ=[50,35x20]`, `LogP=[50]`, default scale `2^35`.
- Status: `FUNCTIONAL-NOT-SECURE`.
- Purpose: prove that the conversion pipeline detects an insecure diagnostic tuple; never rank its performance as secure.

### `gao-paper-summary-2026-233`

- Published aggregate: `N=2^16`, scale 43, multiplicative depth 20, `logQP=1254`, main/ephemeral Hamming weights `192/32`, Gaussian error `sigma=3.2`, seven approximately 50-bit auxiliary primes, hybrid `dnum=3`.
- Status: `PAPER-SUMMARY / EXACT-PRIMES-UNAVAILABLE` until an authoritative OpenFHE emission supplies the complete prime chain and key inventory.
- An estimate using `q=2^1254` is sensitivity evidence, not an exact reproduction transcript.

### `lattigo-gao-compatible-n16-v1`

- Independent Lattigo candidate: standard ring, `LogN=16`, 21 Q primes from Lattigo generator target `LogQ=43`, seven P primes from target `LogP=50`, default scale `2^43`, `Xs=SparseTernary(H=192)`, `Xe=DiscreteGaussian(sigma=3.2,bound=19.2)`. Because Lattigo alternates around `2^b`, an actual prime may have integer bit length `b` or `b+1`; the manifest records every exact value and product rather than substituting the target list.
- Bootstrapping/encapsulation secret: `SparseTernary(H=32)` and separately generated switching keys.
- Status: `PARAMETER-CANDIDATE-UNVERIFIED / ESTIMATOR-SENSITIVITY-COMPLETE / APPLICATION-SECURITY-INCONCLUSIVE`. The exact generated prime chain and unlimited-sample transcript are independently accepted; the evaluator-key/sample inventory and accepted secure circuit profile remain open.
- This is not called source-identical to OpenFHE merely because the aggregate bit lengths match.

The emitter must also support separately named LCPDTE paper and effective-checkout bundles. It may not merge their main-secret weights (`192` in the paper record versus `32768` in the current checkout record), batch packing or depth-dependent modulus chains.

## RLWE-to-LWE conversion

For each independent exposure, the conversion script creates a separate estimator instance:

1. map an RLWE ring of degree `N` to LWE dimension `n=N` under the standard coefficient-embedding heuristic;
2. use the exact integer modulus that protects the exposed sample: `Q` for ciphertext/public-key exposure and `QP` for extended-basis evaluation-key exposure;
3. map balanced sparse ternary weight `H` to `ND.SparseTernary(H/2,H/2,n=N)`; reject odd or unspecified sign splits unless the bundle supplies an explicit alternative;
4. map the discrete Gaussian to `ND.DiscreteGaussian(sigma,n=N)` and retain the implementation truncation bound as auxiliary evidence;
5. use the bundle-derived finite sample count for the primary row and repeat with `m=+Infinity` as a conservative sensitivity row;
6. estimate the main and ephemeral secrets independently at every distinct modulus/sample exposure.

Both exact-sample and unlimited-sample rows must report classical and quantum attack costs. The preregistered hard gate is the minimum classical modeled cost across eligible exact and conservative exposures. The quantum minimum is mandatory reporting, not a post-hoc pass threshold.

## Cost models and transcript

- Classical Core-SVP sensitivity uses the estimator's rough `usvp` and `dual_hybrid` paths with its pinned ADPS16 classical model.
- Quantum sensitivity invokes the same attack families with `ADPS16(mode="quantum")` and records the complete returned fields.
- A full-model follow-up must name every enabled/disabled attack and cost model rather than silently inheriting defaults.
- Stdout, stderr, exit code, wall time, Sage version, estimator commit/content identity, input-bundle digest and conversion-script digest are committed without manual editing.

The estimator decision is one of `PASS`, `FAIL`, or `INCONCLUSIVE`. A modeled RLWE `PASS` does not establish CKKS numerical correctness, sparse-secret encapsulation soundness, protocol security or side-channel resistance; those gates remain separate.

## Acceptance gates

1. Exact bundle generation is deterministic across two fresh invocations.
2. All prime congruence and primality checks required by Lattigo pass.
3. Exact products and bit lengths independently recompute from the ordered prime arrays.
4. Every implementation profile names the bundle digest it actually uses.
5. The estimator script rejects a modified bundle, tool commit/content identity, Sage lock, cost model or output schema.
6. The functional tuple is detected as non-secure, demonstrating that the decision path does not default to `PASS`.
7. No secure-performance table is populated until the exact local tuple passes this contract and its corresponding encrypted correctness gate.
