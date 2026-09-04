# Gao/OpenFHE 与 Lattigo full-packed A2B 同机验收

## 结论

本机生产验收通过。两端均处理 8,192 个 8-bit word（65,536 bits），使用
`N=65536`、32,768 个 complex slots、1 次已验证 warmup 和 5 次逐轮解密验证的
prepared-online 调用；全部结果零失配。

| 后端 | 五次样本（s） | 均值（s） | 中位数（s） | 吞吐（word/s） |
|---|---|---:|---:|---:|
| Gao/OpenFHE | 26.3093, 24.6022, 24.9413, 23.1328, 22.3423 | 24.2656 | 24.6022 | 337.60 |
| Lattigo | 23.3733, 24.7981, 23.1930, 23.4274, 23.2739 | 23.6131 | 23.3733 | 346.93 |

Lattigo/OpenFHE 的均值与中位数延迟比为 `0.973112` 和 `0.950047`；有效吞吐比为
`1.027631`。严格 gate 要求两个延迟比均不高于 `1.0`，结果为 `pass=true`。

## 对齐范围

共享协议参数完全对齐：`zN=8`、`w=4`、`N=65536`、8,192 words、low4/high4
两个输出密文、Q `21/904 bits`、P `7/350 bits`、深度 20、scale/first-Q target
43 bits、main secret H=192、ephemeral secret H=32、RNS decomposition=3、base-two
decomposition=0、level budget `[3,2]`、chunk width 4 和 cutoff -24。

v3 artifact 同时保存两端的完整有序 Q/P 素数链，并显式保留后端原生差异：

| 项目 | Gao/OpenFHE | Lattigo |
|---|---|---|
| actual first Q | 44 bits | 43 bits |
| 误差采样 | OpenFHE DGG, sigma 3.19, effective bound 39 | bounded DG, sigma 3.2, configured bound 19.2, effective bound 19 |
| key switch | OpenFHE HYBRID, 3 components | Lattigo RNS-QP gadget, 3 components |
| DFT/BSGS | auto `dim1=[0,0]` | log-BSGS ratio 2，含 special-B0 与 live-output 优化 |
| 安全选择 | `HEStd_128_classic` | external estimator；`full-packed-profile-not-assessed` |

这不是逐素数相同或执行图逐操作相同的声明；完整原生参数见两个 benchmark JSON。
C75 的 `CONDITIONAL-PASS` 只绑定 selected-child 电路及其密钥/样本清单，不作为本次
full-packed 性能路径的安全证据。

## 本地复跑

从仓库根目录执行。两个 producer 必须在同一台物理机器、同一 WSL 环境中串行运行，
并使用同一个稳定的 `host-id`。

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && bash research/benchmarks/gao_openfhe_a2b_full/build_wsl.sh'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && LCPDTE_GAO_SKIP_BUILD=1 bash research/benchmarks/gao_openfhe_a2b_full/run_wsl.sh -host-id ryzen-7-h-255 -out /tmp/openfhe-v3.json'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 go build -o /tmp/lcpdte-benchmark-ckksint-a2b ./cmd/benchmark-ckksint-a2b'

wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/WorkSpace/LCPDTE && GOAMD64=v4 GOMAXPROCS=1 GOGC=100 GOMEMLIMIT=20GiB POST_WARMUP_GC=on LCPDTE_GAO_CPU_PROFILE= /tmp/lcpdte-benchmark-ckksint-a2b -host-id ryzen-7-h-255 -out /tmp/lattigo-v3.json'

go run ./cmd/compare-ckksint -openfhe-json /tmp/openfhe-v3.json -lattigo-json /tmp/lattigo-v3.json -out /tmp/comparison-v3.json
```

OpenFHE build 会校验 pinned checkout、driver SHA 与 binary SHA；Lattigo benchmark
会拒绝非 `GOAMD64=v4`、非单线程、错误 GC/memory policy、启用 profiling 或 dirty
build。比较器会重新验证 workload、packing、共享/原生参数、五个原始样本和正确性字段。

## 手工端到端测试

公开库示例只导入 `ckksint`，执行 setup/keygen、public-key encryption、服务端 A2B、
客户端 decryption，并核验全部 65,536 bits：

```powershell
go run ./examples/ckksint/gao_full_a2b
```

等价的自动验收入口为：

```powershell
go test -count=1 -run '^TestGaoFullPackedA2BEndToEnd$' -v ./ckksint
```

本机实测峰值约为 18 GiB；应预留至少 20 GiB 可用内存。完整双后端复跑约 12 分钟，
单次 Lattigo 端到端示例通常约 3–5 分钟。

## 证据索引

- `lcpdte-openfhe-v3.json`：OpenFHE 原始 v3 artifact。
- `lcpdte-lattigo-v3.json`：Lattigo 原始 v3 artifact。
- `lcpdte-comparison-v3.json`：严格比较器输出。
- `*-run.time`：独立 `/usr/bin/time -v` 资源记录。
- `*-run-start.txt` / `*-run-end.txt`：UTC 运行顺序。
- `gao-openfhe-a2b-full.build-stamp`：OpenFHE driver/binary 绑定。
- `environment.md`：硬件、工具链、提交和二进制身份。

