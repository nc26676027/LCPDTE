# LCPDTE Validation Language

This glossary distinguishes functional checks from the performance and usability evidence required for acceptance.

## Language

**Functional Acceptance**:
Evidence that the supported behavior and failure boundaries produce the expected results under explicitly non-production conditions. It does not establish deployment security or production readiness.
_Avoid_: Production Acceptance, Security Validation

**Production Acceptance**:
Evidence that a complete user workflow runs end to end and that its performance is compared with the designated Gao et al. OpenFHE baseline under matched semantics and workload.
_Avoid_: Deployment Certification, Protocol Security Proof

**End-to-End Example**:
A runnable workflow that performs setup, encryption, server-side evaluation, decryption, and result verification through the supported library boundary.
_Avoid_: Unit Test, Internal Experiment Driver
