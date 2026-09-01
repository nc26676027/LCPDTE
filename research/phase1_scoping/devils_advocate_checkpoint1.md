# Devil's Advocate Checkpoint 1

## Initial Verdict

**REVISE — no Critical issue; five Major issues.**

1. “最低成本”没有有界目标函数，无法支持全局最优主张。
2. 128-bit security 与双方隐私/泄漏边界没有操作化，跨方案不可比。
3. radix 实验可能通过改变树语义、量化或 retraining 移动目标。
4. integer correctness、overflow、decoding margin 和 failure acceptance 未冻结。
5. D=12/高内存 stretch 项缺少不阻断核心完成的分层标准。

Minor findings: OpenFHE 只应作为 semantic oracle；可行性与新颖性评分应暂降；重复次数需要 warm-up、离散度、超时和 OOM 规则。

## Remediation Applied

- 将 Primary RQ 改为预注册设计集合上的 Pareto-frontier 问题，并冻结词典序部署决策规则。
- 冻结两方半诚实威胁模型、公开元数据、输出泄漏、setup/online 边界及 secure-parameter eligibility。
- 分离 R0 semantics-preserving compilation 与 R1 model-changing design，并冻结 radix 集合与组合规则。
- 冻结 widths、signedness、wraparound、unique-decoding margin、穷举/随机测试和零失败的二项上界报告。
- 定义 Core、Extended、Stretch 完成门；加入 80%-RAM preflight、timeout、warm-up、7/15 次重复与离散度规则。
- FINER 暂调为 Feasible 3/5、Novel 3/5；总分 4.2/5。

## Re-check

**PASS — no Critical or Major findings remain.** The revision substantively closes all five Major issues by bounding the RQ to a preregistered Pareto analysis, operationalizing the threat/security model, separating semantics-preserving R0 from model-changing R1, freezing integer correctness and failure criteria, and defining Core/Extended/Stretch completion gates. Before comparative timing begins, append the remaining source-derived design manifest—batch/slot grid, eligible operator variants, complete cryptographic parameter tuples, representation-specific decoding radii, and pinned security-estimator settings. This is a Minor preregistration completion item and does not block Phase 2 source investigation.
