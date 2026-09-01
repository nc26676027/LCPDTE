# Gao–Zheng SIMD ALU：论文、OpenFHE 实现与 Lattigo 复现映射

## 0. 调查范围与证据边界

本文档核验的主论文为：

> Mingyu Gao and Hongren Zheng, “FHE for SIMD Arithmetic Logic Units with Amortized \(O(1)\) Bootstrapping per Ciphertext,” IACR ePrint 2026/233.

本地论文：

- [eprint-2026-0233-fhe-simd-alu.pdf](D:\WorkSpace\LCPDTE\research\sources\eprint-2026-0233-fhe-simd-alu.pdf)

本地上游代码：

- [fhe-simd-alu](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu)
- 核验 commit：08f1eb87434e7be072cba889270a8400bbffc08e，2026-02-25。

本次工作逐页阅读了 PDF 全部 48 页，并对以下内容进行了 PDF 视觉复核：

- Figure 1、Definitions 7–19、Theorems 1–2：pp. 14–19；
- A2A、A2B、B-A2B、B2B、B2A：pp. 20–23；
- Theorems 3–6、Tables 3–6：pp. 24–28；
- Appendix 中的 CKKS/Boolean 定义、矩阵与噪声证明：pp. 36–46；
- Algorithms 1–2：pp. 47–48。

为避免把复现设计误写成论文主张，本文统一使用三个标签：

- **论文事实**：论文正文、公式、定理、算法或表格明确给出的结论；
- **代码事实**：开源 OpenFHE 分支的实际实现；
- **工程推断**：面向 pure-Go Lattigo 和 private decision tree 的复现或优化设计，论文并未直接提出。

---

## 1. 三种计算表示

### 1.1 Discrete CKKS

**论文事实。** Definition 7（p. 14）对 \(p=2^w\) 定义：

\[
\operatorname{DCKKS.Ecd}_{\Delta,p}(m)=\Delta\frac{m}{p},
\qquad m\in\mathbb Z_p.
\]

一般形态为

\[
\Delta I+\Delta\frac{m}{p}+e,
\]

其中 \(I\) 是小整数 overflow，\(e\) 是近似噪声。

Definition 8（p. 14）的 LUT 为

\[
\operatorname{DCKKS.LUT}_f
\left(\Delta I+\Delta\frac{m}{p}+e\right)
=
\Delta\frac{f(m)}p+e'+e'',
\]

并且

\[
e'=
\frac{\Delta}{p}
O\!\left(
\left(\frac{ep}{\Delta}\right)^{\kappa+1}
\right).
\]

有效条件是 \(|I|<K\) 且 \(ep/\Delta\) 足够小。\(e''\) 是同态 polynomial evaluation 产生的噪声。D-CKKS 可以在共享 polynomial power basis 的情况下同时计算多个 LUT，即 multi-value LUT。

### 1.2 Arithmetic triangle mode

**论文事实。** Definition 9（p. 15）固定

\[
t=X-2,
\qquad
Z_R=\mathbb R[X]/\langle X^n-X+2\rangle,
\]

\[
Z_t=
\mathbb Z[X]/
\langle X^n-X+2,\ X-2\rangle
\simeq \mathbb Z_{2^n}.
\]

若

\[
m=\sum_{i=0}^{n-1}b_i2^i,
\]

则 flatten polynomial 为

\[
[m]_t=\sum_{i=0}^{n-1}b_iX^i.
\]

Eq. (1)（p. 15）说明 carry 和 product overflow 均落入理想 \(\langle t\rangle\)：

\[
[m_1]_t+[m_2]_t
=[m_1+m_2]_t+tI,
\]

\[
[m_1]_t[m_2]_t
=[m_1m_2]_t+tI'+X^nC
\equiv[m_1m_2]_t\pmod{t}.
\]

Definition 10（p. 15）的 triangle encoding 为

\[
\operatorname{ZR.Ecd}_{\Delta,t}(m)
=
\frac{\Delta}{t}[m]_t
=
\Delta\left(
\frac{m}{2^n}
-
\sum_{k=0}^{n-1}
\frac{X^k}{2^{k+1}}
[m]_{0\leq i\leq k}
\right),
\]

其中

\[
[m]_{0\leq i\leq k}=\sum_{i=0}^k b_i2^i.
\]

Definition 11（p. 16）的通用密文消息形态是

\[
f=\Delta I+\frac{\Delta}{t}[m]_t+e.
\]

Definition 12（p. 16）定义解码：

\[
\operatorname{ZR.Dcd}_{\Delta,t}(f)
=
\left\lfloor\frac{t}{\Delta}f\right\rceil(2)
\pmod{2^n}.
\]

必须先逐 polynomial coefficient rounding，再代入 \(X=2\)；若先求值，噪声会被 \(2^i\) 放大。

Theorem 1（p. 16）的正确解码条件是

\[
\|te\|_\infty<\frac{\Delta}{2}.
\]

### 1.3 Boolean flattened mode

**论文事实。** Definition 28（p. 41）定义：

\[
\operatorname{C.Ecd}_{\Delta}(m)
=
\Delta(b_0,\ldots,b_{n-1}).
\]

在 full packing 下，一份 arithmetic ciphertext 含 \(N/n\) 个 logical words。Z-To-C 的 breaking-into-halves 会输出两个 Boolean ciphertext：每个 physical ciphertext 分别保存所有 logical words 的一个 \(n/2\)-bit half；两个 ciphertext 合起来仍表示 \(N/n\) 个 logical words。

这与把“一个 Boolean ciphertext 可独立装 \(N/(2n)\) 个完整 word”理解为同一件事不同。benchmark 的逻辑 slot 数始终是 \(N/n\)。

---

## 2. Arithmetic 运算

### 2.1 Add

**论文事实。** Definition 13（pp. 16–17）：

\[
\operatorname{ZR.Add}(f,f')=f+f'
=
\Delta I''+\frac{\Delta}{t}[m+m']_t+e+e'.
\]

其明文语义是 \(m+m'\bmod 2^n\)，不消耗 multiplication level。

### 2.2 Full multiplication

**论文事实。** Definition 14（p. 17）：

\[
\operatorname{ZR.Mult}(f,f')
=
\frac{1}{\Delta^2}\cdot\Delta t\cdot ff'
=
\Delta I''+\frac{\Delta}{t}[mm']_t+e''.
\]

因为 \(\Delta t\) 或 \(t\) 不能以足够小噪声直接表示，算法做两次 CKKS rescale，因此一个 full multiplication 消耗两个 CKKS levels。

连续 full multiplications 可以融合常量，使用 \(\Delta t^2\)、\(\Delta t^3\) 等，减少单独 scale adjustment。

### 2.3 Short multiplication

**论文事实。** Definition 15（p. 17）若

\[
g=\Delta[m_g]_t+v_g,
\]

则

\[
\operatorname{ZR.MultShort}(f,g)
=
\frac{1}{\Delta}fg
=
\Delta I''+\frac{\Delta}{t}[mm_g]_t+e''.
\]

它只消耗一个 level。Boolean-to-arithmetic branch bit 和 arithmetic leaf/value 相乘时应优先使用该算子。

---

## 3. SIMD homomorphism chain

### 3.1 环和 slots 的对应关系

**论文事实。** Section 4（p. 17）给出的链为

\[
R_Q
\leftarrow R_{\mathbb R}
\simeq\mathbb C^{N/2}
=
(\mathbb C^{n/2})^{N/n}
\simeq
Z_R^{N/n}
\leftarrow_\Delta
Z_t^{N/n}.
\]

- \(\sigma\) 是标准 CKKS embedding，对 \(X^N+1\) 的根求值；
- \(\tau\) 对 \(X^n-X+2\) 的 \(n/2\) 个选定复根 \(\xi_j\) 求值；
- 一个 arithmetic ciphertext 打包 \(\#Z_R=N/n\) 个 machine words。

Definition 16（p. 17）：

\[
\operatorname{RR.Embed}_{Z_R}(f)
=
\sigma^{-1}\tau(f),
\]

\[
\operatorname{ZR.Recover}_{R_R}(g)
=
\tau^{-1}\sigma(g).
\]

Theorem 2（pp. 17–18）给出 embedding 正确性条件：

\[
\|\sigma^{-1}\|\cdot\|\tau\|\cdot B<Q/2,
\qquad B=\|f\|_\infty.
\]

恢复误差上界为

\[
\frac{\|\tau^{-1}\|\cdot\|\sigma\|}{2}.
\]

Proposition 3（p. 18）给出的 rescale 噪声界为

\[
\|\tau^{-1}\|\cdot\|\sigma\|
\cdot\|e_{\mathrm{rescale}}\|.
\]

### 3.2 Z-slot rotation

**论文事实。** Definition 18（p. 18）：第 \(k\) 个 Z-slot 对应 CKKS slot 区间

\[
[kn/2,(k+1)n/2).
\]

所以 logical Z-slot rotation 映射为

\[
\#Z_R.\operatorname{Rotate}_k
=
\operatorname{CKKS.Rotate}_{kn/2}.
\]

### 3.3 Z-To-C 和 C-To-Z

**论文事实。** Definition 19（pp. 18–19）：

\[
h_0
=
2\Re\!\left(
\operatorname{CKKS.LT}_{V_{\tau,0}}(g)
\right),
\]

\[
h_1
=
2\Re\!\left(
\operatorname{CKKS.LT}_{V_{\tau,1}}(g)
\right).
\]

反变换为

\[
g
=
\operatorname{CKKS.LT}_{U_{\tau,0}}(h_0)
+
\operatorname{CKKS.LT}_{U_{\tau,1}}(h_1).
\]

多 logical word 时矩阵是

\[
I_{N/n}\otimes U_{\tau,i},
\qquad
I_{N/n}\otimes V_{\tau,i}.
\]

矩阵只有 \(n-1\) 条非零 diagonals。论文采用 BSGS 后估计旋转复杂度约为

\[
O(2\sqrt{2n}).
\]

---

## 4. Refresh 与 mode conversion

### 4.1 A2A-\(I\)

**论文事实。** Section 5.1（p. 20）：

\[
\text{Z-To-R}
\rightarrow
\text{RLWE.Truncate}
\rightarrow
\text{RLWE.ModRaise}
\rightarrow
\text{R-To-Z}.
\]

该流程重置 arithmetic overflow \(I\)，并恢复 ciphertext modulus；它不以清理 bottom noise \(e\) 为目的。

### 4.2 A2A-\(e\)

**论文事实。** Section 5.1（pp. 20–21）：

1. fused-\(t\) Z-To-R；
2. RLWE.Truncate 和 ModRaise；
3. R-To-C；
4. CKKS.Sine；
5. fused-\(t^{-1}\) C-To-Z；
6. 从原 ciphertext 中减去被 bootstrap 的噪声。

先乘 \(t\) 后，triangle message \(\Delta[t^{-1}m]_t\) 进入 high overflow，可以被 Truncate 去掉，从而 bootstrap 的主要对象是 \(te\)。

Full A2A 必须先 A2A-\(I\)，再 A2A-\(e\)。论文明确不建议反序，因为大的 \(I\) 会放大线性变换噪声，降低 A2A-\(e\) 的清噪效果。

### 4.3 普通 A2B

**论文事实。** Section 5.2（pp. 21–22）和 Algorithm 1（p. 47）：

1. 对 arithmetic ciphertext 执行 special-\(b_0\) Z-To-C；
2. 令
   \[
   p=2^w,\qquad d=n/w;
   \]
3. 第 iter 轮用 plaintext mask 选取
   \[
   [iter\cdot w,(iter+1)\cdot w)
   \]
   的 bits；
4. 一次 multi-value D-CKKS LUT 同时得到 \(\mathrm{LUT}_{ID}\) 和 \(\mathrm{LUT}_{MSB}\)；
5. 将 MSB 输出累计到相应 Boolean half；
6. 对所有仍受当前低 chunk 影响的后续 chunk，令
   \[
   \rho=(nextIter-iter)w,
   \]
   把 ID 输出乘 \(2^{-\rho}\)、旋转 \(-\rho\)，再从 core 中减掉；
7. 若 \(-\rho\leq\mathrm{A2B\mbox{-}cutoff}\)，停止继续传播，把更低影响视为 D-CKKS 噪声；
8. 输出两个 Boolean ciphertext，即 breaking-into-halves。

对论文参数 \(n=64,w=4\)，普通 A2B 需要 \(d=16\) 轮 LUT bootstrap。

### 4.4 special-\(b_0\)

**论文事实。** p. 21 说明 triangle constant coefficient 中含 \(\Delta m/2^n\)，不能直接当作 bit fraction。special-\(b_0\) 把 Z-To-C inverse transform 的第 0 行改为第 1 行的两倍，从而把 constant coefficient 替换为 \(-\Delta.b_0\)，消掉全 word 的 \(m/2^n\) 项。

**代码事实。** 该矩阵在 [z-fhe-precompute.cpp](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe-precompute.cpp:184) 一带生成，实质是：

\[
V^{special}_{0}[0,:]=2V_0[1,:].
\]

### 4.5 Batched A2B

**论文事实。** Section 5.2（pp. 22–23）和 Algorithm 2（p. 48）一次接受

\[
d=n/w
\]

个 arithmetic ciphertext：

1. 每个 ciphertext 先做 special-\(b_0\) Z-To-C；
2. 第 \(j\) 个 core 预旋转 \(-jw\)；
3. 每轮 mask 后，将 \(d\) 个 core 的有效 chunk 合并成两个 ciphertext；
4. 用 real \(+\,i\cdot\)imag 把两个 ciphertext 合成一个 complex ciphertext；
5. 对合并结果做一次 multi-output LUT；
6. 拆分 ID/MSB 结果并更新各 core；
7. 最终对各输出做 \(+jw\) 后旋转。

该算法仍有 \(d\) 轮 bootstrap，但每轮同时服务 \(d\) 个输入 ciphertext，因此只有在 batch 填满时才是 amortized one bootstrap per input ciphertext。

**代码事实。** 上游实现对不足 batch 的输入会 padding，并打印尚未实现 partial batch 的提示，见 [z-fhe.cpp](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:1039) 附近。因此单 ciphertext latency 不能用 B-A2B 的 amortized headline。

### 4.6 B2B

**论文事实。** Section 5.3（p. 23）：

\[
\text{C-To-R}
\rightarrow
\text{Truncate/ModRaise}
\rightarrow
\text{R-To-C}
\rightarrow
\text{cosine D-CKKS bootstrap}.
\]

### 4.7 B2A

**论文事实。** Section 5.4（p. 23）：

\[
\text{C-To-Z}
\rightarrow
\operatorname{ZR.MultShort}.
\]

若后续只是 arithmetic Add，可以把 \(t^{-1}\) 融进 C-To-Z，省去独立 short multiplication。

**代码事实。** 上游 EvalBooleanToArith 只显式调用 special-\(t^{-1}\) C-To-Z，因为 MultShort 所需因子已经融入 special matrix。Lattigo 移植时不能再多乘一次 \(t^{-1}\)。

---

## 5. Boolean、shift、compare 与 select

### 5.1 Boolean operations

**论文事实。** Definition 29（p. 41）：

\[
\operatorname{AND}(b,b')
=
\frac{1}{\Delta}(\Delta b)(\Delta b'),
\]

\[
\operatorname{OR}(b,b')
=
\Delta b+\Delta b'
-
\frac{1}{\Delta}(\Delta b)(\Delta b'),
\]

\[
\operatorname{XOR}(b,b')
=
\Delta b+\Delta b'
-
\frac{2}{\Delta}(\Delta b)(\Delta b'),
\]

\[
\operatorname{NOT}(b)
=
\Delta\mathbf1-\Delta b.
\]

**代码事实。** 对应实现：

- AND：[z-leveledshe-bool.cpp:7](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:7)
- OR：[z-leveledshe-bool.cpp:22](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:22)
- XOR：[z-leveledshe-bool.cpp:39](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:39)
- NOT：[z-leveledshe-bool.cpp:57](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:57)

### 5.2 Shift、rotate 和 sign

**论文事实。** Definitions 30–31（p. 41）只规定 high-level construction：mask、CKKS.Rotate、recombination。Sign extraction 等于提取 \(b_{n-1}\)。

**代码事实。**

- right shift 的 full/sparse half-aware 实现始于 [z-leveledshe-bool.cpp:446](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:446)；
- rotate-left/right 包装在同文件 pp. 545–552 对应源码行；
- EvalSignExtract 直接调用 right shift \(n-1\)，见 [z-leveledshe-bool.cpp:555](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-leveledshe-bool.cpp:555)。

### 5.3 上游 compare 的溢出边界

**论文事实。** p. 41 只说 comparison 可以通过 arithmetic subtraction 和 Boolean sign extraction 实现，没有给出 modular overflow correction theorem。

**代码事实。** EvalLessThan 的全部核心逻辑是：

\[
d=x-y,\qquad d_B=A2B(d),\qquad result=\operatorname{MSB}(d_B).
\]

源码见 [z-user-advanced.cpp:142](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-user-advanced.cpp:142)。

这只在应用保证 signed subtraction 不溢出时正确。它不是任意 \(\mathbb Z_{2^n}\) 的通用 signed comparator，也不是 unsigned comparator。

反例：8-bit signed

\[
x=127,\qquad y=-1.
\]

则

\[
x-y=128\equiv-128\pmod{256},
\]

sign bit 为 1，代码会错误返回 \(127<-1\)。

**工程推断。** 决策树必须采用下列至少一种语义，并把逻辑 width 与实际 physical width/packing 分开计费：

1. unsigned feature 和 threshold 零扩展后再 subtraction/sign；由于已固定 root families 不含任意 `n+1`，本地候选映射为 logical `8->16`, `16->32`, `32->64`，logical 64 需要 exploratory physical 128；
2. 使用 same-width Boolean borrow comparator；
3. signed feature 做一位 sign extension；
4. 实现 overflow-corrected signed comparator：
   \[
   less=
   (s_x\oplus s_y)
   ?s_x
   :s_{x-y};
   \]
5. 使用显式 input-range contract 选择足够大的 word width，证明所有 feature-threshold differences 不溢出。

这些不是一个可互换的 `RangeSafe` wrapper。Unsigned-borrow、unsigned-widened、signed-no-overflow 和 signed-corrected 必须成为不同 benchmark variants；任何 widening 都按 physical width 重算 `N/n` word capacity、`n/w` A2B rounds、ciphertext 数和通信。

### 5.4 Select/MUX

**论文事实。** 论文和开源代码都没有定义 select/MUX。

**工程推断。** arithmetic leaf/value 的最小 select 为

\[
\operatorname{Select}(b,L,R)
=
L+b(R-L).
\]

其中 Boolean branch bit \(b\) 先 B2A，再使用一次 MultShort。若两侧均为 Boolean value，也可用

\[
(b\land R)\lor(\neg b\land L).
\]

---

## 6. 正确性、噪声和安全条件

### 6.1 A2A correctness

**论文事实。** Theorem 3（p. 24）：

\[
C_1
\left(
\frac{\|tv\|}{\Delta}
\right)^3
<
\frac{\|e_A\|}{\Delta}.
\]

\(e_A\) 是继续 A2A 也不能降低的 arithmetic bottom noise。

### 6.2 Arithmetic multiplication noise

**论文事实。** Theorem 4（p. 25），对

\[
f=\Delta I+\frac{\Delta}{t}[m]_t+v,
\qquad
f'=\Delta I'+\frac{\Delta}{t}[m']_t+v'
\]

执行 full multiplication 后：

\[
\|v''\|
\leq
3n\left[
(4\|I\|+1)\|v'\|
+
(4\|I'\|+1)\|v\|
+
\frac{4\|v\|\|v'\|}{\Delta}
\right],
\]

\[
\|I''\|
\leq
3n
\left(
4\|I\|\|I'\|+\|I\|+\|I'\|+1
\right)+1.
\]

对

\[
g=\Delta[m_g]_t+v_g
\]

执行 MultShort：

\[
\|v'''\|
\leq
3n\left[
(\|I\|+1)\|v_g\|
+
\|v\|
+
\frac{\|v\|\|v_g\|}{\Delta}
\right],
\]

\[
\|I'''\|
\leq
3n(\|I\|+1)+1.
\]

这一定理表明 overflow \(I\) 是 arithmetic multiplication 噪声增长的主因，A2A-\(I\) 不是只恢复 level 的性能选项，而是多次乘法的噪声控制手段。

### 6.3 B2B 与 A2B

**论文事实。** Theorem 5（p. 25）：

\[
C_2
\left(
\frac{\|v\|}{\Delta}
\right)^2
<
\frac{\|e_B\|}{\Delta}.
\]

Theorem 6（p. 25）：

\[
C_3
\left(
\frac{\|v\|p}{\Delta}
\right)^{\kappa+1}
<
\frac{\|e_B\|p}{\Delta}.
\]

### 6.4 Table 3 empirical noise

**论文事实。** Table 3（p. 24）：

| \(n\) | Full Mult max/avg, bits | MultShort max/avg, bits |
|---:|---:|---:|
| 8 | 4.3 / 3.9 | 2.6 / 1.5 |
| 16 | 5.0 / 4.3 | 2.4 / 1.7 |
| 32 | 4.9 / 4.6 | 2.9 / 2.3 |
| 64 | 5.6 / 5.0 | 3.3 / 2.6 |
| 128 | 5.8 / 5.4 | 3.6 / 2.9 |
| 256 | 6.3 / 5.9 | 4.0 / 3.4 |

Bottom noise：

\[
\log_2(\|e_A\|/\Delta)=-24.4,
\]

\[
\log_2(\|e_B\|/\Delta)=-20.4.
\]

A2A-\(I\) 后典型 overflow：

\[
\log_2\|I_A\|=2.8.
\]

论文明确标注 Table 3 仅供 illustration，不应直接作为实现指南。

### 6.5 Exact correctness 与 application-aware security

**论文事实。** pp. 23–24 采用 application-aware IND-CPAD：

- 软件或编译器必须追踪输入范围、noise、overflow 和 bootstrap failure probability；
- 若 correctness failure 不可忽略，安全性也会受损；
- sparse encapsulated secret \( \widetilde h=32 \) 用于 ModRaise，使刷新后 \(\|I\|<16\) 的失败概率可忽略；
- 附录的 evaluation keys 依赖 circular-security assumption。

因此该方案不是“对任意程序自动 exact”的无条件 CKKS integer layer。pure-Go API 需要保存并检查 word width、signedness、range、mode、scale、level 和可验证 noise/overflow metadata。

---

## 7. Level 预算与参数

### 7.1 Table 4

**论文事实。** Table 4（p. 26）：

| 操作 | 分解 | 总消耗 | 结束后可用 |
|---|---|---:|---:|
| A2A-\(I\) | R2C 3 + C2Z 1 + Z2C 1 + C2R 2 | 7 | \(L-7\) arithmetic |
| A2A-\(e\) | R2C 3 + Sine 9 + C2Z(\(t^{-1}\)) 1 + Z2C(\(t\)) 1 + C2R 2 | 16 | \(L-16\) arithmetic |
| A2B | special mask + R2C/LUT/C2R/combination | 18 | \(L-18\) Boolean |
| B-A2B | 同上，额外 combination level | 19 | \(L-19\) Boolean |
| B2B | R2C 3 + Cosine 8 + C2R 2 | 13 | \(L-13\) Boolean |

具体 polynomial 参数：

- CKKS.Sine degree 32，\(6+3=9\) levels，3 来自三次 double-angle；
- D-CKKS：\(w=4,p=16,\kappa=1\)；
- exponential degree 46，含两次 double-angle；
- LUT degree \(p-1=15\)；
- LUT 总消耗 \(6+2+5=13\) levels；
- cosine degree 50，\(6+2=8\) levels，一次 double-angle 和一次 squaring 得到 \(\cos^2(\pi x)\)。

### 7.2 Table 5

**论文事实。** Table 5（p. 27）：

\[
N=2^{16},
\qquad
\log_2\Delta=43,
\qquad
L=20,
\]

\[
\log_2(QP)=1254,
\qquad
h=192,
\qquad
\widetilde h=32,
\qquad
\sigma=3.2.
\]

其他设置：

- 7 个 50-bit \(P\)-primes；
- hybrid key switching dnum \(=3\)；
- A2B-cutoff \(=-16\)；
- 按 BTH22 声称 128-bit security；
- 使用 level-specific \(\Delta_\ell\)；
- Truncate 把 scale 重置为 \(q_0\)，所以起始 scale 与 \(q_0\) 对齐。

论文指出也可以使用 uniform ternary main secret，但会带来更高 noise，或 non-negligible bootstrap failure / 最多约 25% 性能损失。

---

## 8. Benchmark

### 8.1 实验环境

**论文事实。** p. 27：

- OpenFHE v1.4.2 + HEXL；
- single-thread；
- AMD Ryzen AI MAX+ 395；
- 128 GB RAM；
- Debian 13；
- clang 19；
- 1 次 warmup，5 次 measured average。

### 8.2 Table 6

**论文事实。** Table 6（p. 28），每格为 total time / amortized time per logical ciphertext slot：

| \(n\) / #slots | A2A-\(I\) | A2A | A2B | B-A2B | B2B | B2A |
|---|---:|---:|---:|---:|---:|---:|
| 8 / 8192 | 4.3s / 0.5ms | 10.1s / 1.2ms | 10.1s / 1.2ms | 13.0s / 0.8ms | 6.0s / 0.7ms | 0.7s / 0.1ms |
| 16 / 4096 | 4.7s / 1.1ms | 10.9s / 2.7ms | 20.5s / 5.0ms | 27.0s / 1.7ms | 5.9s / 1.4ms | 1.1s / 0.3ms |
| 32 / 2048 | 5.3s / 2.6ms | 11.8s / 5.8ms | 40.8s / 20ms | 57.7s / 3.5ms | 5.9s / 2.9ms | 1.7s / 0.8ms |
| 64 / 1024 | 6.4s / 6.3ms | 13.5s / 13.2ms | 80.5s / 79ms | 128s / 7.8ms | 5.9s / 5.8ms | 2.8s / 2.7ms |
| 128 / 512 | 7.7s / 15ms | 15.3s / 29.9ms | 164s / 320ms | 309s / 18.9ms | 5.8s / 11ms | 4.1s / 8.0ms |
| 256 / 256 | 10.2s / 40ms | 19.5s / 76.1ms | 327s / 1.3s | 823s / 50ms | 5.9s / 23ms | 6.4s / 25ms |

B-A2B 的 amortized denominator 还包括 \(n/4\) 个 batched input ciphertext。例如 \(n=64\)：

\[
\frac{128s}{16\cdot1024}
\approx 7.8ms.
\]

论文 headline：

- 相对 CPL，multiplication throughput 1.7–2 倍；
- 相对 CPL，batched A2B 4.4–5.2 倍；
- 相对 Kim25b，batched A2B 1.6 倍；
- 相对 REFHE 的估算为 multiplication 15 倍、bitwise 491 倍；
- 相对 TFHE-rs 的比较混合了 latency 与 throughput，且若干数据是 estimate，不能作为逐项复现实验的严格 oracle。

---

## 9. OpenFHE 源码核验

### 9.1 版本差异

**代码事实。**

- 论文 p. 27 声称 OpenFHE v1.4.2；
- 上游仓库 [CMakeLists.txt:28](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\CMakeLists.txt:28) 至 [CMakeLists.txt:31](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\CMakeLists.txt:31) 明确设置版本 1.4.0。

该差异必须写入复现 provenance，不应把代码仓库直接称为论文 Table 6 的完全相同 build。

### 9.2 主要入口

| 功能 | 源码 |
|---|---|
| Z-To-R / R-To-Z | [z-fhe.cpp:275](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:275) |
| A2A-\(I\) | [z-fhe.cpp:299](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:299) |
| A2A-\(e\) | [z-fhe.cpp:330](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:330) |
| Full A2A | [z-fhe.cpp:384](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:384) |
| A2B full | [z-fhe.cpp:485](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:485) |
| B-A2B | [z-fhe.cpp:583](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:583) |
| B2B full | [z-fhe.cpp:991](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:991) |
| B2A | [z-fhe.cpp:1028](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:1028) |
| Transform / LUT precompute | [z-fhe-precompute.cpp:24](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe-precompute.cpp:24) |
| Less-than | [z-user-advanced.cpp:142](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-user-advanced.cpp:142) |

### 9.3 Roots 和 inverse transform

**代码事实。**

- [z-constants.h:1](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\core\include\math\z-constants.h:1) 保存 \(n=8,16,32,64,128,256\) 的 128-bit fixed-point roots；
- \(n=256\) roots 始于 [z-constants.h:266](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\core\include\math\z-constants.h:266)；
- root map 位于 [z-constants.h:525](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\core\include\math\z-constants.h:525)；
- Vandermonde 和 inverse 构造位于 [z-constants.cpp:7](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\core\lib\math\z-constants.cpp:7)。

对根 \(\xi_j\)，上游没有做一般数值矩阵求逆，而是令

\[
d_j=n\xi_j^{n-1}-1.
\]

inverse column 的第 0 项为

\[
\frac{\xi_j^{n-1}-1}{d_j},
\]

第 \(i>0\) 项为

\[
\frac{\xi_j^{n-1-i}}{d_j}.
\]

恢复 real polynomial coefficients 时，对共轭根配对结果取两倍实部。

### 9.4 A2B LUT 的符号约定

**代码事实。** [z-fhe-precompute.cpp:246](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe-precompute.cpp:246) 一带生成 LUT：

- LUT_MSB 使用负 fractional representative；当 \(x\neq0\) 且 \(x\leq p/2\) 时返回 1；
- LUT_ID 在 \(x=0\) 时返回 0，其余 residue 返回 \(x-p\)，然后按 \(p\) 缩放；
- Hermite interpolation order 为 1。

因此 pure-Go port 不能直接把它改成普通无符号 \(x\) 与 \(x>>(w-1)\)。那会破坏 ID residual subtraction，虽然单独观察某些 MSB 输出可能仍像是 bit extraction。

### 9.5 Exponential/cosine polynomial

**代码事实。**

- exp 系数表为 [z-fhe-constants.h:12](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\include\scheme\ckksrns\z-fhe-constants.h:12) 的 coeff_exp_16_big_complex_46；
- A2B exp evaluation 在 [z-fhe.cpp:881](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:881) 一带；
- B2B cosine path 在 [z-fhe.cpp:958](D:\WorkSpace\LCPDTE\research\upstream\fhe-simd-alu\src\pke\lib\scheme\ckksrns\z-fhe.cpp:958) 一带。

---

## 10. Private decision tree 所需最小算子集合

### 10.1 必需

**工程推断。**

1. Arithmetic triangle Encode/Decode；
2. Arithmetic Add/Sub；
3. threshold Compare，优先做 specialized A2Sign；
4. Boolean sign extraction；
5. Boolean NOT；
6. 若使用 path product 或 one-hot path，增加 Boolean AND；
7. plaintext masks；
8. CKKS rotations 和 Z-slot rotations；
9. B2A；
10. MultShort，用于
    \[
    L+b(R-L).
    \]

### 10.2 条件需要

- B2B：Boolean multiplicative depth 接近 bottom-noise bound 时；
- A2A-\(I\)：大量 arithmetic multiplication 或 overflow \(I\) 增大时；
- A2A-\(e\)：arithmetic noise 接近 Theorem 3 阈值时；
- full arithmetic multiplication：普通 plaintext-threshold decision tree 通常不需要，只有 encrypted-encrypted arithmetic path、复杂 leaf polynomial 或 encrypted index arithmetic 才需要。

### 10.3 第一阶段不必实现

- 所有通用 ALU bitwise variants；
- 通用 equality；
- \(n=128,256\) 参数；
- sparse Boolean packing；
- 连续 full multiplication 的所有 fusion variants。

最小 end-to-end milestone 应是：

\[
\text{Encode}
\rightarrow
\text{Compare}
\rightarrow
\text{Select}
\rightarrow
\text{binary tree inference}
\rightarrow
\text{Decode}.
\]

---

## 11. 决策树专项优化与创新边界

### 11.1 Sign-only A2B

**工程推断。** 完整 A2B 输出 \(n\) 个 bits，但决策树 comparison 只需要 sign bit。

可设计 A2Sign：

- 仍逐 chunk 运行 LUT_ID，因为高 chunk 的 fractional tail 依赖移除低 chunk；
- 不保存低 chunk 的 LUT_MSB；
- 不构造完整两个 Boolean word ciphertext；
- 只在 sign chunk 到达时输出 sign；
- 可省 output masks、MSB accumulation、部分 rotations 和 memory。

在没有实测前，不能声称 bootstrap 数从 \(n/w\) 降成 \(O(1)\)。最保守的可验证主张是减少 combination、rotation 和 ciphertext materialization。

### 11.2 跨节点和跨 query 的 B-A2B scheduling

**工程推断。** B-A2B 的 batch unit 是 \(d=n/w\) 个 arithmetic ciphertext，而不是“一棵树的一次 query”。可以沿以下轴填充：

- 同层多个 nodes；
- 多棵树；
- 多个 queries；
- node \(\times\) query 的二维 batch。

benchmark 必须同时报告：

- batch utilization；
- total latency；
- amortized per comparison；
- rotations；
- bootstraps；
- peak memory。

### 11.3 多叉整数决策树

**工程推断。** 把 binary tree 换成 radix-\(r\) tree 不自动减少 comparison 数。

一个 \(r\)-way threshold node 通常需要 \(r-1\) 个 comparisons，balanced tree 的 depth 为 \(\log_rL\)，总 comparisons 约：

\[
(r-1)\log_rL.
\]

它通常不优于 binary 的 \(\log_2L\)。可能出现收益的前提是：

- \(r-1\) 个 thresholds 能同时 SIMD；
- comparisons 可以恰好填满 B-A2B；
- child digit 的求和/编码成本低于 binary path combination；
- 更浅 depth 显著减少 B2B 或 path-product；
- feature domain 足够小，可以一次 D-CKKS LUT 直接做 interval classification。

encrypted index 的递推

\[
idx'=r\cdot idx+digit
\]

本身便宜，但 encrypted index 不能直接驱动 CKKS data-dependent rotate 或随机访问。leaf retrieval 仍需要 one-hot、MUX network、polynomial 或 LUT selection。

因此更准确的研究名称是 radix-aware encrypted decision tree，并以 bootstraps、rotations、packing utilization 和 level/noise 联合建模，而不是仅以 tree depth 声称复杂度下降。

---

## 12. Pure-Go Lattigo port map

### 12.1 Package 边界

**工程推断。** 不修改 vendor，建议新增项目级 package：

- integer/z2n
  - params.go
  - value.go
  - encode.go
  - arithmetic.go
  - boolean.go
  - compare.go
- integer/homchain
  - roots.go
  - vandermonde.go
  - diagonals.go
  - transforms.go
- integer/bootstrap
  - truncate.go
  - dckks_lut.go
  - a2a.go
  - a2b.go
  - ba2b.go
  - b2b.go
- tree/integer
  - compare.go
  - select.go
  - evaluator.go
  - planner.go

### 12.2 Typed ciphertext metadata

**工程推断。** Value 至少需要保存：

- Cts：一个 arithmetic ciphertext 或两个 Boolean half ciphertext；
- Mode：Arithmetic、BooleanFull、DCKKS；
- WordBits；
- ChunkBits；
- Slots；
- Level；
- Scale；
- Signedness；
- input range；
- overflow/noise bounds。

当前 [he/value.go:5](D:\WorkSpace\LCPDTE\he\value.go:5) 的 CT 只保存 ciphertext/Scalar，不能可靠承载 mode、word width、Boolean pair packing、signedness 和 correctness contract。应新建 typed integer layer，而不是依赖调用者记住隐式约定。

### 12.3 Roots 与 linear transforms

**工程推断。**

1. 把 OpenFHE 128-bit roots 按整数 magnitude、sign、scale=128 移植；
2. 在 Go 中使用 big.Float / Lattigo bignum.Complex；
3. 使用 closed-form inverse，而不是 float64 数值求根或一般 matrix inversion；
4. 生成 normal、special-\(b_0\)、fused-\(t\)、fused-\(t^{-1}\) transforms；
5. 生成 \(I_{N/n}\otimes M\) 的 diagonal representation。

Lattigo 对应 API：

- [lintrans.Diagonals](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:12)
- [lintrans.Parameters](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:67)
- [lintrans.NewTransformation](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:79)
- [lintrans.Encode](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:84)
- [lintrans.GaloisElements](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:94)
- [EvaluateManyNew](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\lintrans\lintrans.go:124)

EvaluateManyNew 应用于同一输入的两个 half transforms，可共享 hoisted automorphisms。

### 12.4 Encoder

**工程推断。** Arithmetic encode：

1. 对每个 word 计算所有低位 prefix \([m]_{0\le i\le k}\)；
2. 生成 triangle polynomial coefficients；
3. 用 \(\tau\) 对 \(n/2\) 个选定 roots 求值；
4. 将 \(N/n\) 组 root values 拼成 CKKS slots；
5. 用标准 CKKS Encoder 做 slot encoding 和 encryption。

Decode：

1. CKKS slots decode；
2. 每组 \(n/2\) slots 做 \(\tau^{-1}\)，恢复 \(n\) 个 real coefficients；
3. 逐 coefficient 计算并 rounding \((t/\Delta)f\)；
4. rounding 后才代入 \(X=2\)；
5. mod \(2^n\)。

### 12.5 Bootstrapping API 映射

本地 Lattigo 可复用：

- [ScaleDown](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:593)
- [ModUp](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:643)
- [CoeffsToSlots](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:794)
- [EvalSinAndScale](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:819)
- [EvalCosAndScale](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:828)
- [SlotsToCoeffs](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\evaluator.go:837)
- [CKKS EvaluateMultiPoly](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\polynomial\polynomial_evaluator.go:83)

命名对应关系：

- paper R-To-C = Lattigo CoeffsToSlots；
- paper C-To-R = Lattigo SlotsToCoeffs。

本地 [DiBootstrapMany](D:\WorkSpace\LCPDTE\he\bts.go:191) 已具有：

\[
\text{SlotsToCoeffs}
\rightarrow
\text{ScaleDown}
\rightarrow
\text{ModUp}
\rightarrow
\text{CoeffsToSlots}
\rightarrow
\text{sin/cos}
\rightarrow
\text{shared-power Hermite multi-LUT}.
\]

应把它抽成可复用 D-CKKS primitive，参数化：

- LUT polynomials；
- input/output modulus \(p\)；
- Hermite order；
- target scale；
- complex packing；
- output mode。

不能未经验证就把 Lattigo ScaleDown 等同于论文 RLWE.Truncate。必须用 plaintext oracle 检查：

- 输出 scale 是否重置为 \(q_0\)；
- high overflow 和 message 是否按论文假设分离；
- ModUp 后 message invariant 是否保持；
- noise 是否满足 Theorems 3、5、6 所需的归一化。

### 12.6 Galois keys

**工程推断。** custom \(\tau\) transforms 和 chunk rotations 需要额外 Galois keys：

1. 调用 bootstrapping Parameters.GenEvaluationKeys，取得 bootstrap-ring secret skN2；
2. 收集 bootstrap 自带 Galois elements；
3. 加入所有 \(\tau\) transforms 的 GaloisElements；
4. 加入 Z-slot rotations \(kn/2\)；
5. 加入 A2B chunk/pre/post rotations；
6. 使用 rlwe.NewKeyGenerator(paramsN2).GenGaloisKeysNew(customGalEls, skN2)；
7. 合并进 rlwe.MemEvaluationKeySet，再建立 evaluator。

对应源码：

- [bootstrapping EvaluationKeys](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\keys.go:15)
- [GenEvaluationKeys](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\circuits\ckks\bootstrapping\keys.go:69)
- [GenGaloisKeysNew](D:\WorkSpace\LCPDTE\vendor\github.com\tuneinsight\lattigo\v6\core\rlwe\keygenerator.go:197)

### 12.7 参数差异

**代码事实。** 当前本地 [he/base.go:52](D:\WorkSpace\LCPDTE\he\base.go:52) 默认使用 Parameter19_H32768h32_LT33_B4H1：

- main \(H=32768\)，不是论文的 \(h=192\)；
- sparse encapsulated \(h=32\)；
- default scale 45，不是 43；
- modulus/level distribution 与 Table 5 不同。

[he/ckks_param.go:31](D:\WorkSpace\LCPDTE\he\ckks_param.go:31) 的 DefaultParam 虽有 \(H=192,h=32\)，却设置 Logbase \(=-1\)，明确不支持 integer/batch LUT bootstrapping。

因此本地没有与 Table 5 等价的现成参数。应新增 Gao-compatible parameter literal，而不是修改当前默认参数；并基于 Lattigo 实际 \(Q/P\) chain 重新跑 security estimator，不能仅按字段匹配声称 128-bit security。

---

## 13. 实现与验证顺序

### Phase A：plaintext algebra oracle

1. 实现 \(Z_t\)、\(Z_R\)、\([m]_t\)；
2. exhaustive 验证 Eq. (1)；
3. 实现 triangle encode/decode；
4. 对 \(n=8\) 全部 256 个值验证 Theorem 1 的无噪声版本；
5. exhaustive 验证全部 \(256^2\) 对的 Add 和 Mult。

### Phase B：roots 和 SIMD transforms

1. 导入 128-bit roots；
2. 验证
   \[
   |\xi^n-\xi+2|;
   \]
3. 验证
   \[
   \tau^{-1}\tau=I;
   \]
4. normal Z-To-C/C-To-Z roundtrip；
5. special-\(b_0\)、fused-\(t\)、fused-\(t^{-1}\) plaintext matrix test；
6. 多 Z-slot group isolation；
7. Z-slot rotations。

### Phase C：encrypted arithmetic

1. arithmetic Encrypt/Decrypt；
2. Add/Sub；
3. MultShort；
4. Full Mult；
5. level/scale invariant；
6. A2A-\(I\)；
7. A2A-\(e\)；
8. Full A2A。

### Phase D：D-CKKS 和 Boolean

1. 对 \(p=16\) 全 residue 验证 LUT_ID；
2. 对 \(p=16\) 全 residue 验证 LUT_MSB；
3. multi-LUT shared-power output；
4. Boolean encode/decode；
5. AND/OR/XOR/NOT；
6. shifts/rotates/sign；
7. B2B。

### Phase E：conversions

1. A2B Algorithm 1；
2. B-A2B Algorithm 2；
3. B2A；
4. 每轮记录 level、scale、noise、rotation count；
5. 在 Theorems 5–6 的阈值两侧测试成功/失败边界。

### Phase F：decision tree

1. signed no-overflow compare；
2. signed corrected compare；
3. unsigned widened compare with frozen logical-to-physical mapping；
4. same-width unsigned borrow compare；
5. B2A + Select；
6. single-node tree；
7. binary tree；
8. batched node/query scheduling；
9. A2Sign；
10. radix-\(r\) tree。

### Differential tests

- \(n=8\)：全空间 encode/decode、Add、Mult、Compare；
- \(n=16,32,64\)：随机和边界向量；
- zero、all-ones、signed min/max、threshold equality；
- signed overflow 和 unsigned wraparound；
- Boolean pair half crossing；
- A2B cutoff 附近；
- OpenFHE 导出的 intermediate vectors 与 pure-Go 每阶段逐项比较；
- end-to-end tree output 与 plaintext tree bit-for-bit 一致。

---

## 14. 结论

Gao–Zheng 的核心贡献不是简单地在 CKKS slots 中放整数，而是三部分的组合：

1. 用 triangle encoding 在 \(Z_R\) 内恢复 \(\mathbb Z_{2^n}\) arithmetic；
2. 用 \(\sigma^{-1}\tau\) 同态链把 \(N/n\) 个非 cyclotomic machine-word rings 嵌入 CKKS RLWE ring；
3. 用 D-CKKS LUT 在 Arithmetic/Boolean 间转换，并把 \(O(n)\) 的 chunk bootstraps 横向摊销到 \(O(n)\) 个 ciphertext。

对 private decision tree，最直接且可验证的结合点是：

- triangle arithmetic 表示 feature-threshold differences；
- range-safe comparison；
- sign-only A2B；
- 跨节点/跨 query 的 B-A2B scheduling；
- B2A + MultShort leaf select；
- 以 bootstrap、rotation、packing utilization、level/noise 联合评价 radix tree，而不是只比较 tree depth。

其中最需要先修正的 correctness 缺口是上游 EvalLessThan 的 modular overflow；最有潜力形成新算子贡献的是 A2Sign；最有潜力形成系统贡献的是 decision-tree-aware batch planner。
