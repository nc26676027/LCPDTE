# Raw XGBoost compilation boundary

This package is the semantic boundary between `treeio` parsing and an HE tree
evaluator. It does not infer unsupported behavior from convenient zero values.

## Supported model

- finite `float32` numerical thresholds and leaf values;
- branch `0` for `x < threshold`, branch `1` for `x >= threshold`;
- single-output additive forests;
- complete-tree padding with the original leaf copied to every padded
  descendant;
- MSB-first root-to-leaf path as the complete-tree leaf index;
- a common maximum depth for all trees compiled through `CompileModel`.

The padding predicates use public `(feature=0, threshold=0)` placeholders whose
two descendant subtrees contain the same leaf. They therefore cannot change the
plaintext result. They still require at least one input feature.

## Fail-closed exclusions

Compilation rejects non-zero `split_type`, any `default_left=true`, malformed or
cyclic child arenas, `num_output_group` outside the accepted single-output
encodings `{0,1}`, non-zero `tree_info` groups, non-finite thresholds/leaves, and
complete depths above `MaxMaterializedDepth`. The forest oracle rejects NaN and
infinite inputs. Consequently, callers cannot accidentally obtain XGBoost's
missing-value routing from ordinary floating-point comparison behavior.

`Forest.Validate` is also called before every oracle evaluation. It rechecks
finite base-score/margin fields, common tree depth, split feature bounds, and
each exported tree, so mutating a compiled public struct fails closed rather
than bypassing the compiler checks.

The two accumulation oracles check their running margin after every tree.
`RawMargin` rejects float64 overflow/NaN, while `RawMarginFloat32` additionally
rejects a base margin or leaf accumulation that becomes non-finite when cast to
the fixture's float32 arithmetic.

## Base score and output space

`treeio.RawModel` keeps `base_score` but currently discards the serialized
XGBoost objective. `CompileModel` therefore requires `ModelSemantics`:

- `BaseScoreProbability` applies `logit(base_score)` before tree aggregation;
- `BaseScoreRawMargin` adds the serialized value directly;
- `OutputRawMargin` returns the additive margin unchanged;
- `OutputLogisticProbability` applies a sigmoid only after aggregation.

The committed notebook writes predictions using
`bst.predict(dtest, output_margin=True)`. Thus `pred_d{8,10,12}.bin` contains raw
margins. Its matching registration is
`{BaseScore: BaseScoreProbability, Output: OutputRawMargin}`; applying a sigmoid
before comparison would change the target quantity.

`RawMarginFloat32` exists only for bit-level fixture regression because the
saved predictions and leaves are float32. `RawMargin` is the independent
float64 oracle for CKKS experiments and should be compared using a declared
numerical tolerance.
