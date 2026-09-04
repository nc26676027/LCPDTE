# Gao/OpenFHE 与 Lattigo full-packed A2B 同机验收

## 结论

2026-09-05 的正式验收在同一台 Ryzen 7 H 255 主机、同一 WSL Ubuntu 环境中完成。
先在本机重新编译并校验 pinned Gao/OpenFHE driver，随后无并发地串行运行
OpenFHE、Lattigo。两端均以 public-key encryption 处理 8,192 个 8-bit word
（65,536 bits），执行 1 次已验证 warmup 和 5 次逐轮解密验证的
`prepared-online` A2B；warmup 与全部正式样本均为零失配。

| 后端 | 五次样本（s） | setup（s） | 均值（s） | 中位数（s） | 吞吐（word/s） |
|---|---|---:|---:|---:|---:|
| Gao/OpenFHE | 22.906563, 22.213843, 22.467630, 23.326414, 23.530424 | 147.090131 | 22.888975 | 22.906563 | 357.902 |
| Lattigo | 23.355570, 23.049589, 22.892137, 22.500005, 22.362396 | 111.388395 | 22.831939 | 22.892137 | 358.796 |

严格比较器给出的 Lattigo/OpenFHE 均值延迟比为 `0.997508167`，中位数延迟比为
`0.999370211`，有效吞吐比为 `1.002498057`。均值与中位数两道“不慢于
OpenFHE”门均通过，最终结论为 `PASS`。

独立 `/usr/bin/time -v` 记录的整个 benchmark 进程资源如下；这些生命周期指标
不替代上表的 `prepared-online` 五样本比较。

| 后端 | whole-process wall | 最大 RSS |
|---|---:|---:|
| Gao/OpenFHE | 7:42.65 | 24,014,088 KiB（约 22.90 GiB） |
| Lattigo | 4:15.59 | 16,496,620 KiB（约 15.73 GiB） |

## 精确适配范围

两端 artifact 的 `comparison_scope` 均为
`gao-algorithm-exact-q-p-and-numerical-parameters`。下列 workload、packing、
协议参数和完整有序 Q/P 素数链逐项一致：

- `zN=8`、`w=4`、`N=65536`、32,768 complex slots、8,192 useful words；
- workload `uint8-0to255-x32`，输出为 low4/high4 两个密文；
- Q 为 21 个模数、合计 904 bits，P 为 7 个模数、合计 350 bits；
- scaling/first-modulus target 为 43 bits；精确模数链决定的 actual first Q
  在两端均为 44 bits；
- multiplicative depth 20、large digits 3、主密钥 H=192、临时密钥 H=32；
- RNS decomposition components 3、base-two decomposition 0、level budget
  `[3,2]`、OpenFHE requested BSGS dimensions `[0,0]`、chunk width 4、cutoff -24；
- error sigma 3.19、effective integer bound 39。

后端原生实现字段按事实保留：

| 项目 | Gao/OpenFHE | Lattigo |
|---|---|---|
| actual first Q | 44 bits | 44 bits |
| 误差采样 | OpenFHE DGG；sigma 3.19；configured bound 为原生 `null`；effective bound 39 | bounded discrete Gaussian；sigma 3.19；configured/effective bound 均为 39 |
| 密钥稀疏分布 | balanced sparse ternary，H=192/32 | fixed-H symmetric sparse ternary，H=192/32 |
| key switch | OpenFHE HYBRID，3 components | Lattigo RNS-QP gadget，3 components |
| DFT/BSGS | auto `dim1=[0,0]` | log-BSGS ratio 2，含 special-B0 与 live-output 优化 |
| 安全选择 | `HEStd_128_classic` | external estimator；`full-packed-profile-not-assessed` |

采样器机制及 `error_configured_bound` 的字段语义是两套库的原生差异；比较器要求
两端 sigma 与 effective integer bound 相同，并不伪造 OpenFHE 不存在的 configured
bound。完整逐素数链和所有机器可读参数均保存在两个 v3 benchmark JSON 中。

## 本地复跑

从仓库根目录执行。先完成两个 clean build，再在同一台物理机器、同一 WSL 环境、
相同 `host-id` 下串行运行 OpenFHE→Lattigo；运行期间不要并发执行仓库测试或其他
重负载任务。

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && bash research/benchmarks/gao_openfhe_a2b_full/build_wsl.sh'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 go build -o /tmp/lcpdte-benchmark-ckksint-a2b ./cmd/benchmark-ckksint-a2b'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_GAO_SKIP_BUILD=1 bash research/benchmarks/gao_openfhe_a2b_full/run_wsl.sh -host-id ryzen-7-h-255 -out /tmp/openfhe-v3.json'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 GOMAXPROCS=1 GOGC=100 GOMEMLIMIT=20GiB POST_WARMUP_GC=on LCPDTE_GAO_CPU_PROFILE= /tmp/lcpdte-benchmark-ckksint-a2b -host-id ryzen-7-h-255 -out /tmp/lattigo-v3.json'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && go run ./cmd/compare-ckksint -openfhe-json /tmp/openfhe-v3.json -lattigo-json /tmp/lattigo-v3.json -out /tmp/comparison-v3.json'
```

OpenFHE build 校验 pinned checkout、driver SHA 与 binary SHA；Lattigo benchmark
拒绝非 `GOAMD64=v4`、非单线程、错误 GC/memory policy、启用 profiling 或 dirty
build。比较器重新验证 workload、packing、精确 Q/P 链、共享/原生参数、五个原始
样本和正确性字段。Lattigo 在 warmup 后及每个已验证样本之间回收输出，GC 位于计时
区间之外，与 OpenFHE 在单次 Eval 调用外释放输出的生命周期口径一致。

## 手工端到端测试

公开库示例只导入 `ckksint`，执行 setup/keygen、public-key encryption、服务端 A2B、
客户端 decryption，并核验全部 65,536 bits：

```powershell
go run ./examples/ckksint/gao_full_a2b
```

等价的自动验收入口为：

```powershell
$env:LCPDTE_GAO_FULL_A2B_E2E = "1"
try {
    go test -count=1 -run '^TestGaoFullPackedA2BEndToEnd$' -v ./ckksint
} finally {
    Remove-Item Env:LCPDTE_GAO_FULL_A2B_E2E -ErrorAction SilentlyContinue
}
```

本机正式运行中 OpenFHE 峰值约 22.90 GiB、Lattigo 峰值约 15.73 GiB；验收环境
为 24 GiB WSL memory limit 加 8 GiB swap。两端 build 与 benchmark 合计约 12 分
52 秒，单次 Lattigo 端到端示例通常约 3–5 分钟。

## 证据索引

- `lcpdte-openfhe-v3.json`：本机重编后的 OpenFHE 原始 v3 artifact。
- `lcpdte-lattigo-v3.json`：Lattigo 原始 v3 artifact。
- `lcpdte-comparison-v3.json`：严格比较器输出与最终 `PASS`。
- `*-build.time` / `*-run.time`：独立 `/usr/bin/time -v` 构建和资源记录。
- `*-build-start.txt` / `*-build-end.txt` / `*-run-start.txt` / `*-run-end.txt`：
  UTC 构建与运行顺序。
- `gao-openfhe-a2b-full.build-stamp`：OpenFHE driver/binary 绑定。
- `environment.md`：硬件、工具链、提交和二进制身份。
