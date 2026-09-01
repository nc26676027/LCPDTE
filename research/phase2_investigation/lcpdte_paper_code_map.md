# LCPDTE 论文—代码逐项核验与复杂度审计

## 0. 核验对象与证据边界

- 论文：Dongjin Park, Gyeongwon Cha, Joon-Woo Lee, *LCPDTE: Low-Complexity Private Decision Tree Evaluation over Homomorphic Encryption*，ACM CCS 2026 / IACR ePrint 2026/1263。
- 本地 PDF：`D:\WorkSpace\LCPDTE\research\sources\eprint-2026-1263-lcpdte.pdf`
- PDF SHA-256：`AFA3F85BDE2E39EFB3D00665813381423D0AE2AD980650701B3315F32B0A947D`
- PDF 元数据：15 页，生成时间 2026-06-16。
- 对照源码根目录：`D:\WorkSpace\LCPDTE`
- 对照源码 commit：`f5ff611f7c023f7ec4d06af6cecaa8b5d33da607`
- 论文链接的作者仓库：`https://github.com/thrudgelmir/LCPDTE`
- 2026-08-29 作者仓库 HEAD：`d8308d55aba5a5647082b5b8efb3226ffc1c0ebe`
- provenance 关系：本地 pin 由论文作者 Dongjin Park 提交，是作者仓库 HEAD 的直接祖先；唯一后续 commit 只修改 `README.md` 的运行目录说明，技术源码无差异。完整命令与 diff 见 `official_lcpdte_repo_provenance.md`。
- Go module：`dt_go`，Go 1.23.11，Lattigo v6.1.1，见 `go.mod:1-5`。

本文件基于论文全部 15 页、算法 1–6、表 1–6、图 1–5、附录 A–D，以及当前 checkout 的 Go/Lattigo 源码逐项核验。论文页码均指 PDF 物理页码。

## 1. 结论摘要

### 1.1 需要先纠正的方案归属

LCPDTE 本身是 **CKKS** 非交互式 PDTE，不是 BFV/BGV 实现。论文表 2（PDF p.3）把 LCPDTE 标为 CKKS，把主要近期基线 [8,16] 标为 FV，部分更早方案才使用 BGV。当前本地仓库也只有 CKKS/Lattigo 主实现，并未包含论文表 5 的 FV 基线代码。

### 1.2 论文最扎实的贡献边界

论文与源码共同支持以下结论：

1. OBO 将树比较调用数从全节点的 `O(2^D)` 降到每层一次、共 `D` 次。
2. GenOH 与 BSGS 将 traversal 的 **重线性化/密钥切换次数** 降到 `O(p·2^(D/2))`。
3. BSGS 可以流式聚合，使大型 ciphertext 缓冲峰值保持在 `O(2^(D/2))`。
4. level-major 调度允许多棵树共享离散 CKKS batched-bit bootstrap，把 bootstrap 调用数从 `K·D` 降到 `D`。

### 1.3 核心复杂度审计结论

论文摘要、贡献、表 3 和结论将 traversal 描述为总服务器复杂度或 `#Mult = O(p·2^(D/2))`。源码只支持更窄的结论：

- `O(p·2^(D/2))` 是 key switch / relinearization 数量级；
- 总 ciphertext tensor multiplication 与同态加法仍为 `O(p·2^D)`；
- leaf 选择仍包含 `O(2^D)` 次 scalar/ciphertext 项级运算。

论文第 4.4 节（PDF p.9）实际分析的标题和推导对象也是 key-switching complexity；附录 B.2（PDF pp.14–15）更明确写出每层 inner product 涉及 `2^d` 次同态加法。因此，把 key-switch 次数直接提升为端到端总服务器工作量，缺少论文推导和源码支持。

## 2. 威胁模型与协议边界

### 2.1 论文声明

论文第 6.1 节（PDF p.10）采用标准半诚实模型：

- 客户端持有私有 attribute vector；
- 服务器持有私有 decision-tree/GBDT 模型；
- 服务器按协议执行，但尝试从 transcript 推断客户端输入；
- 客户端发送 CKKS ciphertext，并接收加密输出；
- 参数声明达到 128-bit security；
- 协议公开 feature count、feature ordering 和最终输出，不额外公开模型相关信息。

### 2.2 未形式化的安全部分

论文没有提供：

- simulation-based security definition 或 reduction；
- malicious/active security；
- adaptive/chosen-query 下的模型隐私论证；
- 重复查询产生的模型抽取风险分析；
- bootstrap/cleaning failure probability；
- Definition 2.1 中 cleaning 输入噪声界 `B` 的数值实例化；
- evaluation keys、公钥、setup 消息的通信量。

### 2.3 本地代码只是实验 harness

`he/base.go:191-203`（绝对路径 `D:\WorkSpace\LCPDTE\he\base.go:191`）在同一进程内同时创建：

- `SK`、`PK`；
- `Encoder`、`Encryptor`、`Decryptor`；
- bootstrapping evaluation keys；
- server-side evaluator。

因此当前代码验证的是同态计算流程和数值结果，不是强制隔离的 client/server 实现，也不能单独作为 transcript privacy 的实验证据。

## 3. 输入、树模型与 SIMD 编码

### 3.1 论文模型

论文第 2.2 节（PDF p.4）定义：

`M = (T, α, τ, Λ)`，其中：

- `T` 为 binary decision-tree evaluation function；
- `α` 将 decision node 映射到 feature index；
- `τ` 将 decision node 映射到 threshold；
- `Λ` 将 leaf node 映射到 leaf value；
- 节点按 BFS 顺序编号；
- `I_d` 表示深度 `d` 的节点索引集合。

论文为了描述方便假定完整二叉树。实验段称深度 `D` 的 perfect tree 有 `2^D` 个节点（PDF p.10），严格地说完整深度 `D` 二叉树应有 `2^D-1` 个 decision nodes、`2^D` 个 leaves、总计 `2^(D+1)-1` 个节点；该句只能理解为数量级或 leaf 数。

### 3.2 SIMD 行打包

论文第 4.1 节（PDF p.7）：

- 最多 `N/2` 个 query 放入 CKKS slots；
- 同一个 feature 的所有 query 在同一 ciphertext 的对应 slot 对齐；
- 每个 `p`-bit attribute 分解为 `p` 个 bit planes；
- 普通编码发送 `F·p` 个 ciphertext；
- 附录 C 的 complex packing 降为 `F·p/2` 个 ciphertext；
- 服务器返回一个 leaf-value ciphertext。

代码映射：

- `pack/packing.go:27-69`：`PackBundle`；
- `pack/packing.go:72-87`：query-major 输入重排为 feature-major slots；
- `pack/packing.go:89-128`：收集每个 feature 的模型 thresholds；
- `pack/packing.go:242-258`：把 input bits 加密到 SIMD slots；
- `pack/packing.go:232-239`：把 server threshold 编为明文常量 bits。

绝对路径：`D:\WorkSpace\LCPDTE\pack\packing.go`。

### 3.3 float32 处理不是字面“bit casting”

论文第 7.2 节（PDF p.12）称采用 bit casting，在 32-bit integer space 中保留 float32 的精确信息并避免 quantization。

源码 `pack/packing.go:224-230` 实际使用 order-preserving key：

```text
u = Float32bits(x)
if sign(u) = 1: key = ~u
else:           key = u xor 0x80000000
```

它是保持普通有限 float32 数值顺序的双射，而不是只重解释 IEEE-754 位模式。该转换对于用 unsigned lexicographic bit comparator 比较正负 float 是必要的，但存在以下语义边界：

- `-0` 与 `+0` 被映射为不同 key，而普通 float comparison 认为二者相等；
- NaN 被放入某个 total order，而 XGBoost 应按 `DefaultLeft` 处理 missing value；
- infinity 虽有确定位置，但论文未说明特殊值域。

当前提供的 `xgbdata/x_test.bin` 经检查为 `N=32768`、`F=30`，没有 NaN 或 negative zero；三个提供模型也没有 `DefaultLeft=true` 或非零 `split_type`，所以当前 Table 6 数据没有触发上述差异。

### 3.4 complex packing 的论文—代码变体

论文附录 C.1（PDF p.15）写作：

`x_(i,j) ⊕ i·x_(i,p/2+j)`，即前半 bits 放实部、后半 bits 放虚部。

源码 `pack/packing.go:246-256` 则：

- 按 MSB-first 相邻位 `(2j, 2j+1)` 配对；
- 实部与虚部都存 `bit/2`；
- `tree/main_tree.go:212-226` 通过 `x+conj(x)` 与 `i(conj(x)-x)` 恢复精确 0/1 bits。

这个实现保持正确的 MSB 顺序，但不是论文公式的字面实现。论文还称 GEQ 后再次 conjugate/recombine、总计需要 `p` 次 key switching；当前代码只在 unpack 时对 `p/2` 个 packed ciphertext 做 conjugation，没有对应的 post-GEQ recombination 阶段。

### 3.5 树 padding 与模型能力

`pack/packing.go:153-221` 把所有树 padding 到 forest 的最大深度：

- `2^D-1` 个 internal positions；
- `2^D` 个 leaves；
- early leaf 的值复制到整个后继完整子树；
- dummy comparison 的结果不影响最终输出，因为该子树所有 leaves 相同。

语义上这能保持普通 early-leaf 树的输出，但：

- 没有利用稀疏树的实际节点数；
- `DefaultLeft` 被解析于 `treeio/parser.go:120-138`，HE traversal 不使用；
- `SplitType` 被解析但不支持 categorical split。

提供的真实模型每棵树最大深度确实为 8/10/12，但原始节点数仅约 85–155；源码仍按完整深度成本求值。

## 4. Algorithm 1：高精度 GEQ comparator

### 4.1 论文设计

论文第 3 节，算法 1（PDF pp.5–6）试图计算三值函数：

```text
f_p(x,y) =  1, x>y
            0, x=y
           -1, x<y
```

二位 base case 计算：

`L = (x_1-y_1) + I[x_1=y_1]·(x_0-y_0)`，即 Eq. (3)，以及

`R = I[x_1=y_1]·I[x_0=y_0]`，即 Eq. (4)。

利用 bit 输入恒等式：

`I[a=b] = 1-(a-b)^2`。

递归 combine 形式为：

`L = L_0 + L_1·R_0`，`R=R_0·R_1`。

最后用：

`φ(x)=1-(x/2)(x-1)`

把 `{-1,0,1}` 映射成 GEQ bit `{0,1,1}`。进一步优化提前把三值结果缩放为 `y=x/2`，使用：

`φ(y)=1-2y(y-1/2)`。

### 4.2 成本

论文给出：

- base pairs：`p/2` 次 key switching；
- combine：`3·(p/2-1)-log(p/2)` 次；
- 加上最终 relinearization/LUT 后总计 `2p-log p`；
- multiplicative depth 为 `log p+2`；
- 比 RDCMP 的 `3p-2` 少超过三分之一。

### 4.3 源码映射

文件：`tree/cmp.go`，绝对路径 `D:\WorkSpace\LCPDTE\tree\cmp.go`。

- `15-28`：构造 `a[i]=xBits[i]-tBits[i]`；
- `37-68`：融合 base case Eq. (3)、Eq. (4)，复用 `u·v`；
- `72-94`：lazy combine；
- `96-113`：递归 divide-and-conquer，兼容非 `2^k` bit length；
- `117-126`：在 half-scaled 三值结果上执行 `φ`，得到 GEQ bit。

源码实现的是正确的 MSB-first lexicographic recursion，且与论文正文描述的意图一致。

### 4.4 论文 Eq. (2) 与 Algorithm 1 勘误

PDF p.5 的 Eq. (2) 把乘积下标写为：

`p-i ≤ j < p`。

按论文此前的常规 bit 编号，这会包含错误位置甚至包含当前 bit 自身，使非零 difference 被 equality indicator 乘为零；例如 `p=2` 时公式不能给出正确 lexicographic comparison。归纳证明和源码实现的是预期的 carry/lexicographic comparison，而不是该公式的字面形式。意图应接近“当前 bit 的贡献仅在所有更高位相等时生效”。

算法 1 还有以下排版/伪代码错误：

1. `Merge` 的输出说明称 `flag=False` 时返回 `R`，第 19 行实际返回 `L`，且语义上也应返回 `L`。
2. 第 6 行使用未定义的 `Tail=True`，应为 `flag=True`。
3. GEQ 输出处写成 `End ◦ Ecd`，应是 `Enc ◦ Ecd`。
4. 第 5、7 行对 Eq. (2)/(3) 的引用与正文 Eq. (3)/(4) 命名不完全一致。

## 5. Algorithm 2：OBO traversal

### 5.1 论文流程

算法 2（PDF p.7）：

1. 从 root 开始；
2. 对每个深度 `d`，由此前 branch bits `S_0,...,S_(d-1)` 生成 `OH_d`；
3. 用 one-hot 分别选择当前 encrypted attribute bits 和 plaintext threshold bits；
4. 执行一次 ciphertext–ciphertext GEQ；
5. 对 branch bit 执行 discrete CKKS bootstrap/clean；
6. 深度 `D` 时用最终 one-hot 选择 leaf value。

这把比较次数从全节点 `O(2^D)` 降到 `D`，但若显式构造完整 one-hot 并做普通 MulPath，traversal 仍有 `O(2^D)` 项级成本。

### 5.2 主源码映射

主函数：`tree/main_tree.go:229-415`，绝对路径 `D:\WorkSpace\LCPDTE\tree\main_tree.go`。

- `229-245`：为每棵树初始化 even/odd product 与 one-hot state；
- `263-279`：调度最多 `k` 棵树；
- `293-324`：枚举当前深度节点，构造 attribute/threshold bit columns；
- `325-333`：root 直接执行 GEQ；
- `335-350`：后续深度执行 BSGS blind branch selection；
- `352-355`：执行一次 GEQ；
- `362-372`：对一批 branch bits 做 bootstrap；
- `373-384`：把清洗后的 branch bit 加入 even/odd state；
- `389-395`：最终 leaf selection。

源码的顺序是正确的：选择深度 `d` 的节点时只使用旧的 `S_0,...,S_(d-1)`；获得并清洗 `S_d` 后才更新 path state。

## 6. Algorithm 3：GenOH 与 SplitHW

### 6.1 论文设计

算法 3（PDF p.8）维护全部 monomials：

`Prod_d[b] = ∏_(0≤i<d) S_i^(b_i)`。

加入一个新 branch bit 时：

- 第一半 monomials 直接复用 `Prod_(d-1)`；
- 第二半才需要计算；
- SplitHW 把目标 monomial 的 set bits 分成 Hamming weight 尽量相等的两个 disjoint masks；
- 因而 product DAG/butterfly 的 multiplicative depth 为 `O(log d)`；
- 再通过 subtraction butterfly 把 `S_i` monomials 转成含 `1-S_i` 的完整 one-hot，不增加 multiplicative depth。

算法 6（PDF p.15）给出 SplitHW 的显式过程。

### 6.2 源码映射

文件：`tree/prod_method.go`，绝对路径 `D:\WorkSpace\LCPDTE\tree\prod_method.go`。

- `9-43`：`BalancedProducts`；
- `23-40`：内联 SplitHW 等价逻辑；
- `46-64`：`OneHotFromProdsIterative` subtraction butterfly；
- `67-82`：可增量 one-hot helper，当前主路径未调用；
- `tree/main_tree.go:373-383`：按当前深度奇偶更新对应 product state。

论文要求的最终 bit-flip + bit-reversal 没有作为独立函数出现。源码通过 monomial 的 bit 布局与后续 `interleaveIndex` 直接构造 BFS 相容的次序，功能上等价，但不是论文伪代码的逐行实现。

## 7. Algorithm 4：BSGS blind branch selection

### 7.1 因式分解

论文算法 4（PDF pp.8–9）把 branch bits 拆为：

- even：`S_0,S_2,...`，one-hot 长度约 `2^ceil(d/2)`；
- odd：`S_1,S_3,...`，one-hot 长度约 `2^floor(d/2)`。

深度 `d` 的 `2^d` 个节点按奇偶 path bits 交织分组。先对每组与 even one-hot 做 inner product，再用 odd one-hot 聚合所有组。正确性来自：每个完整 path one-hot entry 都可分解为 even 因子与只依赖 group index 的 odd 因子。

### 7.2 源码映射

文件：`tree/main_tree.go`。

- `119-145`：把 even/odd path index interleave 成 BFS node index；
- `148-165`：缓存每个深度的二维 index map；
- `167-210`：`selectByParity` 两阶段 BSGS；
- `84-117`：`select1D` lazy inner product。

### 7.3 Algorithm 4 伪代码勘误

1. 标题和正文同时出现 `BsgsBBS` 与 `BsgsBSS`。
2. 输入只写 encrypted attributes/tree，实际还依赖此前 branch state。
3. 输出声明为一个 `ctout`，第 14 行实际返回 selected attribute bits 与 threshold bits。
4. 算法 5 在比较前用 `S_0,...,S_(d-1)` 调用它，算法 4 第 2/4 行却更新 `S_d`，存在 off-by-one。
5. `for j=0 to p` 与 `for c=0 to 2^floor(d/2)` 写成包含上界，按数组长度应分别为 `<p`、`<2^floor(d/2)`。

源码没有照抄这些错误，而是采用“先 select/compare，再 bootstrap，再 update path state”的正确顺序。

## 8. BSGS 复杂度的源码级精确审计

令：

`M = 2^ceil(d/2)`，`S = 2^floor(d/2)`。

因为源码总有 `len(ohEven) >= len(ohOdd)`，`selectByParity` 在 `tree/main_tree.go:189-198`：

1. 对 `S` 个 columns，各调用一次长度 `M` 的 `select1D`；
2. 对 `S` 个 intermediate ciphertext 再调用一次 `select1D`。

`select1D` 在 `tree/main_tree.go:93-109` 对每一项执行：

`MulNew(oh[i], vals[i])` 和 `AddNew(...)`，

直到整个 inner product 完成后才在 `110-115` 做一次 relinearization/rescale。

### 8.1 每个 encrypted attribute channel 的精确数量级

每层：

`tensorMul = S·M + S = 2^d + 2^floor(d/2)`；

`relinearization = S + 1`。

complex packing 后有 `p/2` 个 encrypted attribute channels，因此 attribute selection 的主项是：

- tensor multiplication/addition：`Θ(p·2^d)`；
- relinearization/key switch：`Θ(p·2^(d/2))`。

### 8.2 threshold 与 leaf

threshold 第一阶段的 values 是 0/1 server constants：

- `he/operations.go:111-120` 会对 0/1 multiplication short-circuit；
- 第一阶段主要成为 one-hot ciphertext 的选择/求和；
- 第二阶段仍有 odd-one-hot × intermediate-ciphertext multiplication，约每 threshold bit 一次 relinearization。

leaf values 是 float constants：

- 第一阶段有 `2^D` 项 scalar/ciphertext multiplications；
- 第二阶段仅需平方根量级的 ciphertext–ciphertext aggregation 与一次 relinearization。

### 8.3 论文复杂度应如何表述

源码支持：

| 成本指标 | 量级 |
|---|---:|
| OBO comparison invocations | `D` |
| key switch/relinearization | `O(p·2^(D/2))` |
| 大型活跃 ciphertext buffers | `O(2^(D/2))` |
| ciphertext tensor products/additions | `O(p·2^D)` |
| final leaf scalar products | `O(2^D)` |

因此论文表 3（PDF p.3）的 `#Mult = O(p·sqrt(2^D))` 不能解释为源码执行的全部 ciphertext multiplication。更准确的表述是：**借助 lazy relinearization，BSGS 把 traversal 的 key-switching complexity 和大 ciphertext materialization 降到平方根量级，但没有消除逐节点 tensor-product/addition 工作。**

这也是后续 Gao `Z_(2^n)` 融合的关键边界：只替换 comparator 不能自动消除 `select1D` 的 `2^d` 项级工作。

## 9. Algorithm 5：level-major 与 batched bootstrap

### 9.1 论文设计

算法 5（PDF p.9）：

- 同一深度依次计算 `K` 棵树的 branch bits；
- 使用 [4] 的 batch-bit bootstrap 一起清洗/刷新；
- bootstrap 调用数从 `K·D` 降至 `D`；
- 论文引用的附加 key-switch 成本为 `O(K·2^(K/2))`。

### 9.2 源码调度

`tree/main_tree.go:263-279` 使用 priority queue 按 remaining depth 选择最多 `k` 棵树。对等深、完整/padded 的 forest，这等价于严格 level-major；异深树则更接近 completion-major，但不同 branch bits 独立，batched bootstrap 本身仍可工作。

`tree/main_tree.go:362-372` 把本批 branch bits 送入 `he.MultiBootstrapCT`。

### 9.3 discrete CKKS bootstrap 映射

文件：`he/bts.go`，绝对路径 `D:\WorkSpace\LCPDTE\he\bts.go`。

- `118-145`：过滤 exact constants，收集真实 ciphertext；
- `66-115`：根据 `Logbase` 选择实数或 complex batched packing；
- `191-238`：SlotsToCoeffs → ScaleDown → ModUp → CoeffsToSlots；
- `240-283`：分别对实/虚支路计算 sin/cos complex exponential；
- `286-319`：Hermite interpolation LUT、多输出 polynomial evaluation；
- `380-410`：纯实 bit packing/extraction；
- `413-451`：实部和虚部各承载一组 bits。

使用的 vendor 扩展：

- `vendor/github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping/evaluator.go:819`：`EvalSinAndScale`；
- 同文件 `:828`：`EvalCosAndScale`；
- `vendor/.../ckks/polynomial/polynomial_evaluator.go:83`：`EvaluateMultiPoly`；
- `vendor/.../common/polynomial/polynomial_evaluator.go:93`：generic multi-polynomial evaluator；
- `vendor/.../ckks/mod1/mod1_evaluator.go:146`：`EvaluateAndScaleNew2`。

### 9.4 实现上限

`he/bts.go:70-72` 强制 `numbatch <= 2*Logbase`：

- 单树参数 `Logbase=1`，最多 2 bits；
- batch 参数 `Logbase=4`，借助实/虚部分组最多 8 bits；
- 超过上限直接 panic。

这比论文对一般 `K` 的描述更具体、更受限。

## 10. 正确性与噪声

### 10.1 正确性链

1. GEQ 在输入为精确 bits 时输出接近 0/1 的 branch bit。
2. 每层 discrete bootstrap 同时恢复 modulus 并执行 error cleaning。
3. GenOH 的 monomial/subtraction identity 生成完整 path one-hot。
4. BSGS 只是对完整 inner product 的因式分解，不改变代数结果。
5. early leaf padding 时整个 dummy 子树 leaf values 相同，因此后续 dummy branch choices 不影响输出。

### 10.2 论文噪声界

附录 B.1（PDF p.14）给出粗略 comparison bound：

`e_cmp < 12·3^(log p)·e`。

附录 B.2（PDF pp.14–15）给出：

`e_bss < (2^d·d^2/4)·e`。

该推导是 dominant-term rough worst-case analysis，没有给出：

- cleaning radius `B`；
- 具体参数下的 failure probability；
- comparison rounding margin；
- security/noise estimator artifact。

特别地，B.2 明确承认 inner product 有 `2^d` 次 homomorphic additions，这与“总 #Mult/总服务器工作为平方根量级”的宽泛表述存在内在张力。

### 10.3 源码错误处理

`he/operations.go` 多处忽略 evaluator error，例如 `:39,59,68,87,96,123,132,180,195`。`he/bts.go:306,312` 也丢弃 `EvaluateMultiPoly` error。对实验复现和参数边界审计，应把这些 error 改为显式返回或 panic，而不能把数值异常只当成最终 MatchRate 问题。

## 11. 参数与 128-bit security 差异

### 11.1 论文表 4

PDF p.10：

| 项 | 论文值 |
|---|---|
| `log N` | 16 |
| `log QP` | 1328–1508 |
| `(h~, h)` | `(192,32)` |
| Base | 45 |
| StC | `39×3` |
| Circuit | `45×8 + 45×log(D)` |
| LUT | `45×(K+1)` |
| EvalExp | `45×8` |
| CtS | `42×3` |
| P | `46×5` |

表注称 `K` 是算法 5 的树数量。

### 11.2 单树源码参数

`he/ckks_param.go:59-113` 与 `he/base.go:47-167`：

- `logN=16`；
- q0=45；
- StC=39×3；
- circuit levels 由 `main.go:28` 的手工 `clv` 表选择；
- single-tree `Logbase=1`、HermiteOrder=1，所以 LUT=45×2；
- EvalMod=45×8；
- CtS=42×3；
- P=46×5。

当 `clv` 从 8 到 12 时，总 `logQP` 正好从 1328 到 1508，与论文范围一致。

但源码使用：

- 主 secret `H=32768`；
- ephemeral secret `h=32`。

这与论文表 4 的 `(192,32)` 不一致。

### 11.3 K=8 batch 参数没有被表 4 完整覆盖

`main.go:79-87`：

- `tree/obo/bsgs` 使用 opt=1、`Logbase=1`；
- `boosting` 使用 opt=0、`Logbase=4`。

batch 参数的 LUT 深度是 `HermiteOrder+Logbase=5`，通过实/虚各打包 4 bits 输出 8 个 branch bits。D=12、`clv=12` 时实际约：

`logQP = 1643`，

不在表 4 的 1328–1508 内。若严格按表中 `LUT=45×(K+1)` 且 `K=8`，又应是 9 层而非源码的 5 层。论文没有清楚说明 complex batched-bit packing 对表 4 中 `K` 的重新解释，也没有给出 K=8 参数的 security-estimator 输出。

## 12. 通信模型

论文与代码统计的是在线 input/output ciphertext：

- 无 complex packing：client input `F·p` ciphertext；
- 有 complex packing：client input `F·p/2` ciphertext；
- server output：1 ciphertext；
- 每个 ciphertext amortize 到 `N/2` 个 query slots。

源码：

- `pack/packing.go:41-47`：`InQuery`；
- `pack/packing.go:41-42,58-69`：`OutQuery=1`；
- `printfuncs.go:52-53,95-121`：以 `CtSize` 估算总字节与每 slot 字节；
- `he/base.go:204-205`：`CtSize` 使用 max-level zero ciphertext 的 `BinarySize()`。

限制：

- setup、public key、relinearization/conjugation/bootstrapping keys 不计；
- output ciphertext 可能不在 max level，却仍用同一 `CtSize`；
- 模型发布/持有成本不计；
- 论文“query size”是 input+output，不是完整协议一次性总通信。

## 13. 实验网格与数值结果

### 13.1 环境与设置

论文第 6 节（PDF pp.9–12）：

- AMD Ryzen 9 7900X；
- RAM 128 GB；
- Lattigo；
- ours 使用 `logN=16`；
- baselines 使用 `logN=15`；
- batch size 对齐到 CKKS 的 32768 slots；
- 主实验为随机 perfect binary tree；
- `D=2,...,12`；
- `p=32`；
- feature dimension 固定为 1；
- 真实模型验证为 XGBoost、K=8、D∈{8,10,12}、32768 queries。

论文没有报告重复次数、方差、置信区间或随机 seed。

### 13.2 表 5

Amortized runtime，ms/query：

| Method | D=2 | D=5 | D=8 | D=12 |
|---|---:|---:|---:|---:|
| Ours | 1.1209 | 3.9627 | 8.9725 | 42.2055 |
| BPDTE-CW | 0.1757 | 1.9633 | 16.9559 | 326.5083 |
| BPDTE-RCC | 0.1583 | 1.7586 | 15.3342 | 439.1848 |
| RDCMP-ASM | 0.6301 | 6.8249 | 56.3396 | 905.1788 |
| RDCMP-ESM | 1.2249 | 12.4789 | 101.6719 | OOM |

论文结论：

- ours 从 D=7 开始快于全部基线；
- D=12 相对 CW 7.74×、RCC 10.4×、ASM 21.45×；
- ESM 在 D=12 超过 128 GB；
- ours query 8.5 KB，CW 71.26 KB，RCC 882.8 KB，ASM 4.13 KB；
- 相比 CW 的通信比为约 8.38×。

### 13.3 图 2–5

- 图 2：D=12 traversal 占总 runtime 81.7%；总 amortized runtime 从 D=2 的 1.12 ms 增长到 D=12 的 42.21 ms。
- 图 3：全节点比较从 D=4 起超过 ours 全流程；D=11 已慢 22.54×；D=12 OOM。
- 图 4：BSGS 与 naive traversal 的 crossover 在 D=11；D=12 naive one-hot OOM。
- 图 5：batch bootstrap 单项快约 3.6×；端到端收益从 D=2 的 1.57× 降到 D=12 的 1.10×。
- 图 5 之前正文误写“Figure 4 shows the effect of batched bootstrapping”，应为 Figure 5。

### 13.4 表 6

| (D,K) | Time (ms/query) | log2(MaxAbs) | MatchRate |
|---|---:|---:|---:|
| (8,8) | 48.38 | -20.09 | 100.00% |
| (10,8) | 79.99 | -20.22 | 99.95% |
| (12,8) | 162.684 | -17.47 | 100.00% |

MatchRate 是 logit/margin 的符号分类一致率，不是所有 leaf/logit 数值在 tolerance 内完全相等。

### 13.5 内存

论文第 7.1 节（PDF p.12）：

- ours 在 D=12 为 33.97 GB；
- all-node、无 BSGS traversal、RDCMP-ESM 都超过 128 GB；
- 论文据此声称 peak ciphertext materialization 为 `O(sqrt(2^D))`。

源码会构造 `xs`/`ts` 的 `O(p·2^d)` 个轻量 Go `he.CT` 引用/常量，但大型 ciphertext buffers 在 `select1D` 中流式累计，因此“大 ciphertext memory 为平方根量级”与源码基本相符；这不等于总项级计算也为平方根量级。

## 14. 当前仓库复现实验的限制

### 14.1 实验配置

`main.go:25-97`：

- `loop=1`，没有重复采样；
- generator seed=0；
- 默认 `P=32`；
- `tree/obo/bsgs` 使用 K=T=1；
- `boosting` 使用 K=T=8；
- 深度循环为 2–12；
- `clv` 是手工表。

### 14.2 五个模式

`printfuncs.go:220-363`：

- `tree`：单树完整协议；
- `obo`：所有 internal nodes 的 comparison-only ablation；
- `bsgs`：通过 `ablation=1` 使用不拆 parity 的完整 one-hot traversal；
- `boosting`：K=8 level-major/batched bootstrap；
- `parse`：三个提供的真实 XGBoost models。

### 14.3 无法直接闭环的论文结果

1. 当前仓库不包含 BPDTE-CW、BPDTE-RCC、RDCMP-ASM、RDCMP-ESM 实现。
2. 没有论文原始 results、CSV 或 plotting scripts。
3. README 称 `tree` 可直接产生表 5/图 1–5，但它只能产生 ours 分量，不能生成图 1 的 baseline curves。
4. `printfuncs.go` 输出 `MaxAbs` 和 MatchRate，不直接输出表 6 的 `log2(MaxAbs)`/`MaxNoise` 列。
5. `treeio/parser.go:58` 对 d8、d10、d12 全部返回常数参数 selector `10`，使 parse mode 没有按模型深度选择 `clv`。
6. 通信只按 max-level `CtSize` 估算 input/output。
7. 当前 Go 包没有测试文件。
8. README 要求 Go 1.26.4，但 `go.mod` 是 Go 1.23.11；README 要求 `cd dt_go`，当前 repo root 已经是 module root。

## 15. 论文—代码映射总表

| 论文组件 | 仓库相对位置 | 绝对位置/起始行 |
|---|---|---|
| 模型 parser | `treeio/parser.go:26-138` | `D:\WorkSpace\LCPDTE\treeio\parser.go:26` |
| 完整树与 padding | `pack/packing.go:153-221` | `D:\WorkSpace\LCPDTE\pack\packing.go:153` |
| SIMD/float bit packing | `pack/packing.go:224-258` | `D:\WorkSpace\LCPDTE\pack\packing.go:224` |
| Algorithm 1 GEQ | `tree/cmp.go:15-128` | `D:\WorkSpace\LCPDTE\tree\cmp.go:15` |
| Algorithm 3 GenOH/SplitHW | `tree/prod_method.go:9-64` | `D:\WorkSpace\LCPDTE\tree\prod_method.go:9` |
| Algorithm 4 BSGS index map | `tree/main_tree.go:119-165` | `D:\WorkSpace\LCPDTE\tree\main_tree.go:119` |
| Algorithm 4 two-stage selection | `tree/main_tree.go:167-210` | `D:\WorkSpace\LCPDTE\tree\main_tree.go:167` |
| Algorithm 2/5 主协议 | `tree/main_tree.go:229-415` | `D:\WorkSpace\LCPDTE\tree\main_tree.go:229` |
| complex unpack | `tree/main_tree.go:212-226` | `D:\WorkSpace\LCPDTE\tree\main_tree.go:212` |
| discrete bootstrap | `he/bts.go:191-319` | `D:\WorkSpace\LCPDTE\he\bts.go:191` |
| batched-bit bootstrap | `he/bts.go:66-145,380-451` | `D:\WorkSpace\LCPDTE\he\bts.go:66` |
| CKKS 参数/密钥 | `he/base.go:47-205` | `D:\WorkSpace\LCPDTE\he\base.go:47` |
| 参数 literals | `he/ckks_param.go:59-113` | `D:\WorkSpace\LCPDTE\he\ckks_param.go:59` |
| all-node ablation | `tree/comparison_only.go:82-150` | `D:\WorkSpace\LCPDTE\tree\comparison_only.go:82` |
| 实验调度 | `main.go:25-97` | `D:\WorkSpace\LCPDTE\main.go:25` |
| 聚合/MatchRate/通信 | `printfuncs.go:52-217,220-363` | `D:\WorkSpace\LCPDTE\printfuncs.go:52` |

## 16. 对 Gao `Z_(2^n)` 融合设计的直接含义

当前实现最自然的三个 seam 是：

1. comparison seam：`tree.CmpGeBits`；
2. branch-selection seam：`selectByParity` / `select1D`；
3. cleaning/functional-bootstrap seam：`MultiBootstrapCT → DiBootstrapMany`。

但复杂度审计给出一个硬约束。以下判断来自冻结 commit `f5ff611` 的 `tree/main_tree.go:84-210` 源码计数，而不是论文单独陈述：

- 只把 32 个 bit ciphertext 的 `CmpGeBits` 换成 packed `Z_(2^n)` integer comparator，可能改变比较器常数和 comparison depth；输入 ciphertext 数是否降低取决于 query count、word packing 和物理 block 数，在论文的 32-bit/32,768-query 满载点两者均为每 feature 16 个 ciphertext；
- 它不会自动消除 `select1D` 在每层对 `2^d` 节点执行的 tensor products/additions；
- 若希望获得真实的端到端渐近改进，需要让 integer/radix state 同时改变 branch selection 的数据结构，例如按 feature/radix 聚合、packed LUT/address selection，或避免逐节点展开；
- 多叉整数树虽然能降低逻辑深度，但 branching factor 会改变 path-state 数量，必须同时分析 `r^d` 的 selector 成本，不能只用“深度减少”推导总复杂度降低。

因此后续实现和论文写作应把以下三类指标分别报告：

1. comparator invocations 与 multiplicative levels；
2. tensor products/additions；
3. relinearizations/key switches、bootstrap 调用和 peak ciphertext memory。

只有这样才能判定 Gao 算子替换究竟带来常数改进、密钥切换改进，还是实际总环运算的渐近改进。
