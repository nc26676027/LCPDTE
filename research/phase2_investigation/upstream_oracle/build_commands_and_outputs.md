# `fhe-simd-alu` intake and smoke-build log

Run date: 2026-08-29 (Asia/Shanghai)

This file preserves the commands and material outputs used for the upstream intake. The authoritative checkout was not patched.

## Remote pin

```text
> git ls-remote --symref https://github.com/tsinghua-ideal/fhe-simd-alu.git HEAD
ref: refs/heads/fhe-simd-alu HEAD
08f1eb87434e7be072cba889270a8400bbffc08e HEAD

> git clone --branch fhe-simd-alu --single-branch https://github.com/tsinghua-ideal/fhe-simd-alu.git D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu
Cloning into 'D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu'...

> git rev-parse HEAD
08f1eb87434e7be072cba889270a8400bbffc08e

> git rev-parse HEAD^{tree}
9b1ac19b19b70dd9f6a1510e4660a73ed3ca1e72

> git branch --show-current
fhe-simd-alu

> git log -1 --date=iso-strict --format='%H%n%an <%ae>%n%ad%n%s'
08f1eb87434e7be072cba889270a8400bbffc08e
Zenithal <i@zenithal.me>
2026-02-25T15:44:41Z
Fix cmake command
```

## Submodules

```text
> git submodule update --init --recursive

> git submodule status --recursive
 984e3f194862b17916536b5fade40cba6e47a6fe third-party/cereal (heads/main)
 eddb0241389718a23a42db6af5f0164b6e0139af third-party/google-benchmark (v1.9.4)
 52eb8108c5bdec04579160ae17225d66034bd723 third-party/google-test (release-1.8.0-3544-g52eb8108)
 83edb60836d87cf1b406e8846b9059c03031e8f5 third-party/gperftools (gperftools-2.16.90)
```

The superproject was clean after initialization. `build-smoke/` is ignored by the upstream `.gitignore`.

## WSL2 environment

```text
Linux LAPTOP-A8EOL5VM 6.18.33.1-microsoft-standard-WSL2 x86_64 GNU/Linux
Ubuntu 22.04.5 LTS
gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0
g++ (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0
cmake version 3.22.1
GNU Make 4.3

clang: absent
clang++: absent
libntl-dev: not installed
libgmp-dev: not installed (runtime libgmp.so.10 is present; headers are absent)
libomp-dev: 1:14.0-55~exp2, installed
sudo -n true: password required
```

The upstream README specifically requests Clang, NTL/GMP, tcmalloc, OpenMP, and Intel HEXL. A no-source-change, reduced-dependency build was attempted only to determine how far the checkout compiles in the available environment.

## Configure attempt

```text
> cmake -S /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu \
    -B /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu/build-smoke \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED=OFF -DBUILD_STATIC=ON \
    -DBUILD_UNITTESTS=OFF -DBUILD_BENCHMARKS=OFF -DBUILD_EXAMPLES=ON \
    -DBUILD_EXTRAS=OFF -DGIT_SUBMOD_AUTO=OFF \
    -DWITH_OPENMP=ON -DMATHBACKEND=4 -DWITH_NTL=OFF \
    -DWITH_TCM=OFF -DWITH_INTEL_HEXL=OFF

-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is GNU 11.4.0
-- Building in Release mode
-- BUILD_UNITTESTS:    OFF
-- BUILD_EXAMPLES:     ON
-- BUILD_BENCHMARKS:   OFF
-- BUILD_STATIC:       ON
-- BUILD_SHARED:       OFF
-- GIT_SUBMOD_AUTO:    OFF
-- WITH_NTL:           OFF
-- WITH_TCM:           OFF
-- WITH_OPENMP:        ON
-- WITH_INTEL_HEXL:    OFF
-- MATHBACKEND is set to 4
-- Found OpenMP: TRUE (found version "4.5")
-- Configuring done
-- Generating done
```

## First build failure

```text
> cmake --build /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu/build-smoke --target example --parallel 2

[ 78%] Building CXX object src/pke/CMakeFiles/pkeobj.dir/lib/scheme/ckksrns/z-fhe-precompute.cpp.o
z-fhe-precompute.cpp:251:19: error: comparison of integer expressions of different signedness:
  'int64_t' and 'uint64_t' [-Werror=sign-compare]
  251 | if (x <= p / 2 && x != 0) {
cc1plus: all warnings being treated as errors
gmake: *** [Makefile:521: example] Error 2
```

The repository globally enables `-Werror`. To expose any later dependency assumptions without modifying source, CMake was rerun with the narrow compiler override `-DCMAKE_CXX_FLAGS=-Wno-error=sign-compare`.

## Second build failure

```text
> cmake --build /mnt/d/WorkSpace/LCPDTE/research/upstream/fhe-simd-alu/build-smoke --target example --parallel 2

[ 78%] Building CXX object .../z-fhe.cpp.o
[ 80%] Building CXX object .../z-leveledshe-bool.cpp.o
z-leveledshe-bool.cpp:293:39: error: no match for 'operator|' (operand types are
  'bigintdyn::ubint<long unsigned int>' and 'bigintdyn::ubint<long unsigned int>')
z-leveledshe-bool.cpp:323:39: error: no match for 'operator|'
z-leveledshe-bool.cpp:360:39: error: no match for 'operator|'
z-leveledshe-bool.cpp:466:39: error: no match for 'operator|'
z-leveledshe-bool.cpp:490:39: error: no match for 'operator|'

z-leveledshe.cpp:278:17: error: 'intel' has not been declared
  278 | intel::hexl::EltwiseMultMod(op1, op1, op2Vec.data(), n, qiUInt, 1);

gmake: *** [Makefile:521: example] Error 2
```

Interpretation:

- The boolean shift/rotation implementation relies on bitwise OR for `BigInteger`; the repository's requested `MATHBACKEND=6` (NTL) supplies the intended type, whereas the fallback backend used for this diagnostic does not.
- `LeveledZImpl::EvalMultScalarInPlace` calls `intel::hexl::EltwiseMultMod` without a `WITH_INTEL_HEXL` guard, so disabling HEXL cannot produce a complete build.
- The README-faithful build cannot be configured in the present WSL image without installing Clang plus NTL/GMP development files. Passwordless package installation is unavailable. Intel HEXL v1.2.6 can then be built by the repository's `ExternalProject`, and `tcm` is a separate build target.

No high-memory executable or benchmark was run.

## Integrity hashes

```text
LICENSE
D428E7C7309BD982A2A38DCAB077D515FD570B1B5041FBE8B02BEFF062EBCAFD

README.md
701AE598DFFE36BBD7587FD037D38E6A921DDD539993F9D22496BFFE605FA7B3

src/pke/examples/example.cpp
60C4990F507D151A7C61A345B8D2A7C44A82257E17BBD7D932579A59A82F6670

src/pke/examples/benchmark-full.cpp
11C6830F6AD908D1972DAC38E167BF593DE4CA2FF63F16418EB8142A4C747508
```
