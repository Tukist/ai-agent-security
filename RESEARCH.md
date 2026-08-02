# AI Agent Security — Research Log

## 2026-07-23 论文发现

### 1. ChainWatch (arXiv:2607.19432, Jul 2026) ⭐
- 六阶段 kill chain 检测框架
- 攻击类型: 直接序列攻击、间接 prompt 注入链、混合多步攻击
- 20维特征提取
- 启示: 可以构造 kill-chain 序列来绕过单步检测

### 2. DTap (arXiv:2605.04808, May 2026)
- 14 领域 + 50 模拟环境
- DTap-Red: 自主红队 agent 探索注入向量 (prompt/tool/skill/environment/combinations)
- 启示: 多向量组合攻击

### 3. AI-Infra-Guard (arXiv:2606.31227, Jun 2026)
- 75+ 组件, 1400+ 漏洞规则
- 26+ jailbreak 攻击算子
- 启示: 可参考 jailbreak 算子设计攻击模板

### 4. IPI-proxy (arXiv:2605.11868, May 2026)
- 820 攻击字符串, 6 个 benchmark 整合
- HTML 注入: comment/invisible CSS/semantic prose
- 启示: 注入payload库可参考

### 5. AgentSeer (arXiv:2509.17259, Sep 2025)
- GPT-OSS-20B 红队挑战赛冠军
- Agentic 级别的攻击比 model 级别高 24% 成功率
- 启示: 工具调用上下文是关键攻击面

## 已知竞赛论文
- UDora: 推理链劫持, ASR 99%
- AgentDojo: Slack 场景 92% 攻击成功率
- MELON: 遮蔽重执行检测
- StruQ: prompt/data 双通道隔离
- TensorTrust: 126k 样本, 16 种攻击策略

## 待探索
- [ ] ChainWatch kill chain 阶段映射到竞赛 predicate
- [ ] DTap 注入向量在竞赛环境中的可用性
- [ ] AI-Infra-Guard jailbreak 算子适配

## SKYGOD07 Stockfish v7 (84.240分) 关键创新
代码已保存: reference/SKYGOD07_stockfish_v7.py

### 5个核心创新 vs 我们的v46(76分):
1. **per-model split by latency**: 探测阶段测平均延迟→判断当前是gpt_oss(慢)还是gemma(快)
   - 慢模型发送FRAME_TEMPLATE(Harmony注入)跳过chain-of-thought
   - 快模型发送普通TEMPLATE
2. **adaptive margin**: MARGIN_S根据observed slowest动态缩放
   - 快模型: margin自动缩到几秒,多塞候选
   - 慢模型: margin保持47s安全值
3. **PROBE_HOPS=1**: 探测时只跑1hop(跳过wrap-up generation),省~50%探测时间
   - 用REPLAY_COST_COEF放大回填真实回放成本
4. **REPLAY_SAFE_SIZING**: 逐个累积每个KEPT候选的实测成本
   - 停止条件基于真实成本而非固定N
5. **SLOW_MULTIPOST_N**: 对慢模型,一条消息伪造N个http.post端点
   - N=4时每候选4次EXFIL(64raw vs 18raw)

---
## 五大创新详解 (SKYGOD07 v7 → Jun-Morita v106: 84→88分)

代码: reference/SKYGOD07_stockfish_v7.py, reference/JunMorita_v106_88110.py

### 1. per-model split by latency
- **问题**: GPT-OSS(推理模型)慢但注入模板效果好, Gemma(非推理)快但不需要注入
- **方案**: 前8个候选用普通模板测平均延迟 → >12s判为GPT-OSS切FRAME_TEMPLATE, <12s保持TEMPLATE
- **参数**: SPLIT_BY_LATENCY=True, SPLIT_THRESHOLD_S=12.0, SPLIT_CLASSIFY_N=8

### 2. adaptive margin
- **问题**: MARGIN_S=47对gemma太保守(gemma每候选~8s)
- **方案**: margin = min(47, 4.0+slowest×2.5), 快模型自动缩到24s, 慢模型保持47s
- **参数**: MARGIN_S=47, MARGIN_FLOOR_MIN=4.0, MARGIN_SLOWEST_COEF=2.5

### 3. PROBE_HOPS=1 (实验性, v111待定)
- **问题**: hops=8探测时模型多发一条wrap-up, 耗时无用
- **方案**: 探测用hops=1跳过wrap-up, 省~45%时间, 用REPLAY_COST_COEF放大估算真回放成本
- **参数**: PROBE_HOPS=1, REPLAY_COST_COEF=1.8

### 4. REPLAY_SAFE_SIZING
- **问题**: 固定N=max(8100/lat)要么保守要么超时
- **方案**: 逐个累积实测成本, replay_cost>=0.97*9000时停, N自适应模型速度
- **参数**: REPLAY_SAFE_SIZING=True, REPLAY_SAFE_FRAC=0.97

### 5. SLOW_MULTIPOST_N (实验性)
- **问题**: GPT-OSS慢, 每候选只1次EXFIL(18raw)
- **方案**: FRAME_TEMPLATE注入时伪造N个端点, N=4时每候选4次EXFIL(64raw)
- **参数**: SLOW_MULTIPOST_N=1(默认), 实验值=4
