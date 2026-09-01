# Research Question Brief

## Topic Area

在同态加密下进行低复杂度、SIMD 化的私有决策树求值，并研究如何把 Gao 等人的 CKKS `Z_{2^n}` 整数计算方法移植到 Lattigo，以重构比较、分支选择和多叉树遍历。

## Primary Research Question

在预注册的设计集合、匹配预测函数、威胁模型、128-bit 安全约束和整数正确性阈值下，Lattigo 中哪些 CCS-2026/Gao 组合设计位于延迟、峰值内存、bootstrap 数量和在线通信的 Pareto 前沿，且各设计在什么 workload 区间占优？

## FINER Assessment

| Criterion | Score | Justification |
|---|---:|---|
| Feasible | 3/5 | 两篇论文、两个源码基线、现有 Lattigo CKKS/functional-bootstrap 代码和模型数据均可取得；但 OpenFHE 参考构建、Lattigo integer bootstrap 和安全参数资源门尚未通过，完整 D=12 基准还受本机内存约束。 |
| Interesting | 5/5 | 该问题直接连接整数 CKKS、私有 ML 推理、SIMD packing、functional bootstrapping 与树结构复杂度，且当前代码的复杂度主张存在需要论文解释的源代码张力。 |
| Novel | 3/5 | Gao 算子与 CCS 协议的 Lattigo 组合、整数分支索引和 radix-aware traversal 尚未通过系统相关工作检索；当前观察只构成待验证的创新候选。 |
| Ethical | 5/5 | 研究使用公开论文、公开源码和非识别化模型/测试数据，不涉及人体研究；安全参数、失败概率和双用途边界将显式记录。 |
| Relevant | 5/5 | 结果可直接影响 HE 私有推理的延迟、内存、ciphertext 数量、bootstrap 数量和工程可部署性。 |
| **Average** | **4.2/5** | 高于 3.0 门槛，且无单项低于 2；可行性与新颖性在 Phase 2 后重新评分。 |

## Scope Boundaries

### In Scope

- CCS 2026 论文中的 CKKS 私有决策树协议、其 BFV/BGV/HE 相关基线、成本模型、安全/隐私语义和实验。会议官网、作者仓库和已公开摘要已共同表明目标协议本身是 CKKS；不再把用户最初的 BFV/BGV 描述当作已证事实。
- 当前 `nc26676027/LCPDTE` checkout 的 patched-Lattigo CKKS 实现，包括 packing、comparison、parity traversal、functional bootstrap 和实验 harness。
- Gao 等 ePrint 2026/233 及 `tsinghua-ideal/fhe-simd-alu` 中与 `Z_{2^n}` 表示、算术、比较、移位、选择、rounding/refresh 和误差条件有关的算法与代码。
- 在 Lattigo 中进行纯 Go 重实现，并用上游行为向量和独立明文 oracle 验证。
- 三类树设计：现有二叉基线、整数 comparator 替换的二叉树、radix/k-ary 或 feature-fused 整数树。
- 在匹配安全、预测语义、模型精度和 workload 的条件下比较正确率、levels、乘法、rotations、bootstraps、ciphertext 数、通信、延迟和内存。

### Out of Scope

- 将 OpenFHE ciphertext、key 或 RNS 实现直接移植到 Go；OpenFHE 仅作为算法和行为 oracle。
- 把 demo/非安全参数的速度结果表述为 128-bit 安全性能。
- 未实现的网络传输、恶意安全、模型训练隐私、访问模式隐藏和 side-channel 防护。
- 在缺少原始数据或授权时重建 Kaggle 信用卡数据集；使用仓库已提交的模型与派生输入/预测即可。
- 把树拓扑或模型精度变化造成的速度提升误归因于 HE 算子。

### Key Assumptions

- 论文与官方源码能够取得并固定到可审计版本；无法取得的材料将标为未验证，而不是从 README 反推。
- 相对性能结论只在同一主机、同一软件版本、同一参数和同一 workload 内成立。
- `Z_{2^n}` 的“整数正确性”由显式 residue 表示、rounding 区间和失败概率定义，而不是由解密后看似接近整数来代替。
- k-ary 方案必须保持同一预测函数，或将模型转换成本和精度变化单独报告。
- 本机内存不足以无条件执行 README 所述的完整 D=12/高内存 ablation；不安全的运行不会作为完成条件的替代品。

## Frozen Decision Rule

- “Best” 不是单一标量主张；首先报告延迟、峰值内存、bootstrap 数量和在线通信的 Pareto 前沿。
- 正确性与安全性是硬约束；超过预注册内存门限或未通过安全参数核验的配置均不可进入安全性能排名。
- 对部署建议采用词典序规则：在可行配置中先最小化 median online latency，再最小化峰值内存，最后最小化在线通信。
- 在观察比较结果后，不得更改指标、优先级、workload 或排除规则。

## Frozen Threat and Security Model

- 两方、半诚实、非合谋：客户端持有输入与 secret key；服务器持有明文树/森林和叶值，按协议执行。
- 客户端学习预测结果以及公开的树深、树数、特征数、batch/slot 数、密码参数和消息尺寸；服务器学习相同公开元数据、evaluation-key 尺寸与访问到的 ciphertext 形状，但不学习输入明文。
- 本研究不声称抵抗恶意偏离、side channels、服务器通过拒绝服务泄漏、或客户端通过大量授权查询进行模型抽取；这些边界不改变单次协议的正确性测试。
- secure-performance 配置必须记录 scheme、ring degree、完整 Q/P 链（含 bootstrap primes）、secret/error 分布、估算器版本与设置，并达到同一声明的 classical 128-bit 门限。CKKS rounding/bootstrap failure 与 RLWE 安全性、BFV/BGV decryption failure 分开记录。
- classical core-SVP estimate `>=128` bits is the preregistered hard security gate. Quantum estimates are mandatory reporting/advisory fields, with no post-hoc pass threshold in this study.
- 在线 request/response 通信与一次性 setup/evaluation-key 流量分别报告，不允许混加后选择有利口径。

## Frozen Radix Experiment Classes

- **R0 — semantics-preserving radix compilation:** 将预注册数量的连续二叉层组合成 radix 节点，保留每个原始 split predicate 和完全相同的叶映射；通过符号映射或声明量化域上的穷举证明等价，提交数据集仅作回归检查。所有额外 LUT、selector、packing、ciphertext、预处理与 key 成本均计入。
- **R1 — model-changing radix design:** retraining、阈值变化、quantization、pruning 或精度变化均属于独立实验；单独报告模型转换成本和精度，且不把总加速仅归因于 HE 算子。
- R0 测试 radix 固定为 `{2,4,8,16}`，分别组合最多 `{1,2,3,4}` 个连续二叉层。对始于二叉深度 `d` 的一组，冻结 `h=min(g,D-d)`、`S=2^d` 和 `K=2^h-1`；末组按实际 `h` 计费，不通过未计费 dummy 分支扩充。任何其他 radix 只能作为明确标记的探索性结果。
- R0 结构分别映射到四种可计费 schedule：`R0-Sequential` 进行 `h` 次依赖的 blind selection 与 CT--CT 比较；`R0-Eager-Active-CTCT` 对秘密活动 supernode 做 `K` 组 width-`S` attribute/threshold selection 后执行 `K` 次 CT--CT 比较；`R0-Eager-All-CTPT` 执行所有 `S*K` 次 CT--server-plaintext 比较后再秘密选择；`R0-FusedLUT` 仅允许根部同 feature 有限域 LUT，或在 `d>0` 明确计入全部 `S` 个 LUT 与选择器，或证明并计费一个全局 state-aware LUT。每种 schedule 都计入 physical comparator streams、refresh/bootstrap、packing 和 selector；只有结构编译不得称为优化。

## Frozen Correctness Acceptance Criteria

- 测试 unsigned 与 two's-complement signed `Z_{2^n}`，注册 bit widths 为 `{8,16,32,64}`；所有算术 overflow 按模 `2^n` wraparound。Width 4 is removed by pre-benchmark amendment A1; width 128 is exploratory and excluded from the preregistered Pareto decision.
- raw canonical residues are `[0,2^n-1]`. Unsigned interpretation uses the same interval; two's-complement interpretation is `[-2^(n-1),2^(n-1)-1]` with negative values stored as their canonical raw residue modulo `2^n`.
- 对每个归一化表示定义 codeword spacing `d_min`、unique-decoding radius `R=d_min/2`、实测误差 `E` 和 `rho=E/R`。Arithmetic triangle uses `E=||t e||_infinity` and `R=Delta/2`; normalized Boolean bits use spacing 1 and `R=1/2`. 接受条件统一为 `rho<1`、剩余 margin `1-rho>0` 且 residue/Boolean oracle 零不匹配；不再额外、含混地要求 `<R/2`。定理特定的 noise inequalities 另行核验。
- 对 `n<=8` 的可行 unary domain 和 binary operand pairs 做穷举；更大宽度使用三个固定种子、每个宽度/算子至少 `2^15` 个 boundary-heavy cases，覆盖 `0,1,2^{n-1}-1,2^{n-1},2^n-1` 及其相邻值。
- bootstrap failure event 定义为解码 residue 或 selector 与明文 oracle 不同。测试集必须观察到零 failure；同时报告零失败时的单侧 95% 二项分布上界，不能写成“failure-free”。理论失败概率另由参数/误差分析给出。

## Completion Gates

- **Core:** pinned-source 分析；上游 smoke vectors；Lattigo `Z2N` 表示及最小 compare/select/refresh 算子集；matched binary-tree evaluation；确定性正确性测试；在本机可行的 secure benchmarks。
- **Extended:** integer packing/fusion 与 R0 semantics-preserving radix evaluator，含 ablation。
- **Stretch:** 完整 D=12、原论文规模和上游 full-scale 运行。通过只读内存可行性检查后仍不可运行的 stretch 配置记录为缺口，不阻断 Core 完成。

## Sub-questions

1. 两篇论文及其代码分别如何表示值、打包 SIMD 数据、实现比较/选择、安排 bootstrapping，并由哪些具体操作形成其复杂度？
2. Gao 的 `Z_{2^n}` 算子在 Lattigo 上重实现时需要哪些表示、参数、误差和 functional-bootstrap 接口，且它们相对现有 bit-sliced comparator 的具体成本是多少？
3. 在保持模型语义和安全目标一致时，binary、radix/k-ary、整数 child-index 和混合树设计各自在深度、状态规模、selector 成本和 bootstrap 数量上何时占优？

## Candidate Questions Considered

| # | Candidate | FINER Avg | Decision |
|---|---|---:|---|
| 1 | 哪些预注册组合设计形成 Pareto 前沿，且在哪些 workload 区间占优？ | 4.2 | Selected；目标有界、允许多目标权衡，也允许“没有改进”这一结果。 |
| 2 | Gao 整数 comparator 是否比现有 32-bit bit-sliced comparator 更快？ | 4.2 | 过窄；不能回答 traversal、packing 和多叉树是否主导总成本。 |
| 3 | k-ary 树是否总能降低私有树求值复杂度？ | 3.4 | 带有“总能”的错误先验，且忽略模型转换与 selector 成本。 |
| 4 | 能否完整复现两篇论文？ | 4.0 | 是必要工程目标，但不足以形成可检验的设计研究问题。 |

## Epistemic Commitments

- “Reproduced” 只用于论文参数/算法或官方代码路径在本地实际运行并通过预先定义验证的情况。
- “Ported” 指算法语义在 Lattigo 中独立实现并通过跨实现 oracle；不暗示字节级实现等价。
- “Optimized” 要求在匹配语义、安全与 workload 的实验中获得可重复收益。
- “Innovation candidate” 在完整文献检索、实现和 ablation 前始终保持 hypothesis 状态。
