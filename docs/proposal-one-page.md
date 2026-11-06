# Moon Shamir 项目申报参考书

## 门限秘密分享：可验证的密钥分片备份内核

GitHub 仓库账号：yyqdbngt；注册表账号：123123213weqw；日期：2026 年 11 月 4 日；主要语言：MoonBit；许可：Apache-2.0。  
GitHub：https://github.com/123123213weqw/moon-shamir  
公共模块：123123213weqw/moon_shamir@0.2.0（模块发布于 123123213weqw 名下）

本文供个人参考，按实际实现编写。公开提交与验证记录另附核对表，不以材料修订代替主办方复核。

## 一、项目目标与生态空白

把一把密钥变成 n 份份额、任意 k 份即可恢复的秘密分享原语：私钥、恢复码、种子短语的分片备份。选此方向依据可复现查证：2026-11-04 克隆 mooncakes.io 注册表索引（3557 个模块），检索 shamir / secret sharing / threshold scheme / key shard / split key / slip39 / bip39，**无一实现**——在压缩、SAT/SMT 求解器、TLS、WebAuthn 皆有人占位的生态里，密钥分片备份是仍为空位的基础设施。它解决的是真实痛点：单点存放的密钥一次事故即永久丢失，一次泄露即彻底失守；Shamir 门限方案给出信息论保证——任意 k 份恰好确定秘密、任意 k−1 份对一切可能秘密不可区分（不是计算困难，是数学上不可能）。

## 二、已完成交付能力

| 能力 | 实际机制 | 输出及边界 |
|---|---|---|
| split | 每字节一条 GF(2⁸)（AES 多项式 0x11B）随机 k−1 次多项式，份额 i 为各多项式在 x=i 处的取值 | hex 秘密 ≤16 KiB；2≤k≤n≤255；份额一行可打印（index:threshold:digest:data） |
| combine | 拉格朗日插值常数项；确定性取最小 x 坐标的前 k 份 | 不足 k 份**直接拒绝**——不存在"恢复出错值"的输出可误用 |
| diagnose | 穷举全部 k-子集（≤12 份、k≤6，至多 C(12,6)=924 次插值），凡与法定人数一致者收录 | **点名**与每个法定人数都不一致的嫌疑份额——损坏份额是被定位的，不只是被怀疑 |
| verify | 执行 combine 同款插值但不返回秘密；可选 secret_hex 追加逐字节相等断言（格式非法即拒绝） | 持有方可证明份额集属于某个已知秘密而响应不携带任何新信息 |
| 完整性标签 | 每份额携带秘密的 CRC-32 | 抗意外损坏（坏/混入份额 → verified:false）；明确声明**不是 MAC** |
| 使用入口 | MoonBit 库 execute/run 与 JSON CLI + scripts/shamir.mjs 命令行（split/combine/diagnose/verify） | 单 JSON 应答，错误信封与退出码 0/1/2 |

## 三、核心工程机制

熵与时间一样是注入的：系数流由调用方传入种子的 SplitMix64 生成，库从不读取环境随机源——同一 (secret, seed) 在 js/wasm/wasm-gc/native 四后端逐位复现同一份额，这正是独立 oracle 能逐份额对拍的前提。GF(2⁸) 中减法即 XOR，拉格朗日权重随之退化为 x_j 与 (x_i XOR x_j)⁻¹ 之积——不变式写在插值函数处。代数定律作为一等公民验证：**任意 C(n,k) 个 k-子集恢复同一秘密**，白盒测试对 3-of-5 的全部 10 个子集穷举断言，oracle 对随机 split 的每个 k-子集恢复比对。diagnose 的法定人数搜索同样可穷举验证：向随机 split 注入一个翻转位份额，引擎与 oracle 必须点名同一嫌疑人、同一好份额集、同一恢复秘密。

## 四、可复现案例

examples/split.json 与 combine.json：16 字节秘密 3-of-5 分片，取第 1/3/5 份恢复，输出逐字段锚定。examples/diagnose.json：五份中一份首字节被翻转，diagnose 输出 suspects [5]、good [1,2,3,4] 并仍恢复原秘密。命令行一键复现：`node scripts/shamir.mjs split <hex> 3 5 2026` 打印份额，任意三行交回 combine 即还原。三个示例均由 CLI 实际执行并与钉死的期望输出比对。

## 五、验证与实际规模

12 项 MoonBit 测试声明（四后端全绿、--deny-warn 零告警）、6 个 CLI 夹具（含逐字钉死的拒绝消息）、3 个锚定示例；独立 Python oracle 复算 62 项检查：40 组随机分片**逐份额十六进制比对**（GF(2⁸) 由生成元 3 的指数/对数表独立构造，与实现的移位归约乘法器路径不同；SplitMix64 亦为 Python 独立重写）、每组全部 k-子集恢复、15 组注入坏份额的 diagnose 对拍、种子确定性与敏感性、拒绝路径；30 条畸形输入全部单错误对象退出 1；CLI 工具闭环纳入验证梯。生产代码 854 行（有效 688 行），由 scripts/stats.py 机检并写入 PROJECT_STATS.md。一键 sh scripts/verify.sh 复现全部证据。

## 六、使用与验收

库调用 execute(Json)/run(Value)；CLI `node _build/js/debug/build/cmd/main/main.js examples/split.json`；工具化 `node scripts/shamir.mjs split cafebabe 2 3 7`。复核命令即 verify.sh 的展开清单，不另行维护第二套说辞。

## 七、当前边界与来源

纯内存决策库：不落盘、不网络传输、不做分布式份额管理；份额 x 坐标 1..255 故 n≤255；秘密 ≤16 KiB；种子以 JSON 数值传输故 ≤2^53−1。CRC-32 与 SplitMix64 均非密码学原语：前者防意外不防恶意，后者的可复现性以种子为代价——生产必须注入高熵种子，文档如实声明。方案本身非首创（Shamir 1979、Blakley 1979），贡献在于 MoonBit 生态空位的可验证实现与证据链。比赛准入与最终审核由主办方决定，公开发布不构成受理证明。
