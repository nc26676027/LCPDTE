# Secure N16 Route-B live Authority implementation audit — 2026-09-01

## Verdict

**PASS IMPLEMENTATION — 0 Critical / 0 Major / 0 Minor.**

This verdict covers the trusted physical-memory sampler, snapshot-derived `RBAUTH-v1` peak fields, and the live payload-free `RouteBAuthority.AuthorizeBuild` capability. It does not cover `BeginBuild`, factor-artifact construction, receipt minting, evaluation keys, evaluator installation, first-operation preflight, encrypted MR0, or measured RSS.

## Frozen implementation

| Artifact | SHA-256 |
|---|---|
| `integer/secureeval/route_b_auth_wire.go` | `8acd7109426cd29d83d9047e2d6885e8427aae5a10367da06d02c5caafe14b24` |
| `integer/secureeval/route_b_auth_wire_test.go` | `956978ffe8a504cdcf0b96fe727ec1bd08d52490f022c0beadf9454e01222d2e` |
| `integer/secureeval/route_b_capacity_sampler.go` | `971c229f24bcda5f51154bd0b1989a157f717434b13a2c2c02ced14d1a2383827` |
| `integer/secureeval/route_b_capacity_sampler_linux.go` | `46962190927bc41c80258a469f06d87d39c99de0ef0df46f6509d155a0992678` |
| `integer/secureeval/route_b_capacity_sampler_windows.go` | `8b5c567ba09e1b55463f0cfbe1f0b029b6728491947d8347957b5784cfe5fc14` |
| `integer/secureeval/route_b_capacity_sampler_unsupported.go` | `0e73c6450f2db83766a8658fda0a33f8d286fad837bce795cb8673d467e1c2aa` |
| `integer/secureeval/route_b_capacity_sampler_test.go` | `b628721ac7cf48a181253173abe811a0b1556c9059868cd68ae78be4e43bbb17` |
| `integer/secureeval/route_b_capacity_sampler_windows_test.go` | `6ef46bfdaf1c38ede18cf8e9ba8f73499ee8255fb0f591707eed7a5137d9dfc8` |
| `integer/secureeval/route_b_authority.go` | `fc90e111acbf3cbc63da2169f0817e22eda0eebd26cdae80116a3ba148c23175` |
| `integer/secureeval/route_b_authority_test.go` | `efd38f0753147d700b9672403b798126e885e35a867ed2ed0545b8601f34837a` |

## Accepted invariants

1. `NewRouteBAuthority` has no capacity or sampler input. The production sampler is selected by build tag: one `GlobalMemoryStatusEx` call on Windows, bounded `/proc/meminfo` parsing on Linux, and fail-closed behavior elsewhere.
2. The Linux parser accepts exactly one decimal `MemTotal` and `MemAvailable` value in `kB`, rejects malformed, duplicate, missing, oversized, inconsistent, and overflowing inputs, and checks the byte conversion.
3. The four builder peaks are static. Remaining headroom and duplicate-default excess are derived from every admitted sample, including the saturating zero-excess case. The strict projected-use inequality is checked with overflow guards.
4. Authority copies share one private owner, random owner secret, sampler, stored canonical raw parameters, mutexes, and generation counter. Every attempt reserves a strictly newer nonzero generation before sampling. Sampling or capacity failure consumes that generation and returns no spec or permit.
5. The one-shot capacity capability binds owner, generation, sample time, totals, and a secret-derived snapshot identity. Copies replay the same atomic consume cell; foreign owner/generation, altered identity, invalid totals, and zero sample time fail closed.
6. `AuthorizeBuild` executes capacity sampling/evaluation before canonical parameter preparation and permit minting. A source-AST regression test freezes this order and excludes direct heavyweight encoder, evaluator, key-generator, evaluation-key, and DFT-matrix constructors from the public method.
7. The live `ArtifactBuildPermit` contains an inert serializable report plus a process-local lineage. The lineage anchors the BuildSpec, BuildPermit, capacity report, capacity permit, owner, mint generation, and sample time; parsing the report cannot reconstruct the live capability.
8. Twelve concurrent calls through copied Authority handles produced twelve distinct generations and lineages under one owner. Generation exhaustion blocks before the sampler, capacity evaluator, parameter preparation, or capability minting.
9. A real production Windows authorization passed the current-host capacity gate and reconstructed the same plan/report/permit digests independently in the test. This is admission evidence, not an artifact-memory or performance measurement.

## Verification transcript

```text
go test ./integer/secureeval -run 'TestRouteBAuthority|TestProductionRouteBAuthority|TestRBAUTHPeak|TestParseLinux|TestProductionPhysical|TestWindowsPhysical' -count=20
ok dt_go/integer/secureeval

go test ./integer/secureeval -count=1
ok dt_go/integer/secureeval

go vet ./integer/secureeval
PASS

GOOS=linux GOARCH=amd64 go test -c -o NUL ./integer/secureeval
PASS

gofmt -d <all scoped files>
empty
```

The Windows host smoke ran successfully rather than taking its capacity-blocked skip branch. The Linux command is a compile-only portability gate; it does not claim a Linux runtime sample.

## Next gate

`BeginBuild` must obtain a fresh capacity capability, atomically consume the authorized lineage, construct the five streamed factors without duplicate resident defaults, mint the observed receipt, and publish exactly one private-uninstalled artifact. No statement in this audit substitutes for that gate.
