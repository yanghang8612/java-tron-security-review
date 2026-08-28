# 逐条候选复核与补跑

从 0.4.3 开始，每日复核队列合并初筛的 `findings.json` 和 `coverage.json.deferred`。
后者必须含标题和实质问题描述/证据；纯覆盖备注、扫描中断、限流记录和安全拒绝不作为漏洞送审。
按候选稳定标识去重，保留反证、原始暂缓原因及代码位置。每条单独运行，按配置最多 8 条。

初筛保持 Sol / xhigh / 200；复核保持 Sol / high，每条估算成本 30、60 分钟。
从 0.4.4 开始，单条复核同时限制首次有效进展等待 5 分钟、连续无进展 10 分钟。
启动、预检 0/N、重连和重复心跳不计为进展；增长的 token/成本/文件计数和新的分析阶段才计入。
这检测的是 CLI 可观测进展，不等同于网络连接建立或模型首 token 到达。
对这两种停滞或明确网络故障，原模型最多重试一次，退避 5 秒。
重试扣除前次已记录的估算成本与耗时，共享每条 30 / 60 分钟额度；
用量或耗时未知、剩余额度不足时跳过原模型重试，不能把缺失用量当作零。
限流、明确模型不可用，或上述可恢复故障仍未恢复时，每条最多一次降级到 5.5 / high；
每轮最多 3 次降级，每次最多 30 分钟，也适用首响应和无进展检测。
5.5 没有 CLI 成本计价支持，所以降级受次数和超时限制，不宣称有美元硬上限。
本地成本上限、总时限、安全拒绝、认证/授权失败和其他未知错误不触发恢复。
完整结束但覆盖 partial 或结论“证据不足”的任务不重试；已恢复的历史连接错误也不触发重试。
所有尝试独立保留，只有最终尝试参与退出判定；失败尝试的估算用量仍计入报告。

扫描使用 CLI 的 `--verbose` 脱敏生命周期诊断；每次还保存
`invocation.stdout.execution.json`，记录终止原因、计数与耗时，不记录凭据或提示词。
中断后留下的结论文件不是完整复核，不会自动被提升为“复核支持/排除”。
原始执行日志仍不对网页下载或 ZIP 开放。

## 结果含义

- 未复核、等待复核、正在复核：尚无完整独立判断。
- 复核支持：独立模型给出代码与生产可达性证据；仍需人工确认，不是安全证明。
- 复核排除：独立模型提供反证或阻断路径；不能仅凭空发现列表判定排除。
- 已复核 / 证据不足：缺少必要证据，或复核没有返回有效的明确结论。
- 复核失败、安全限制、超出本轮上限：单独保留原因，不覆盖其他候选结果。

每条进度原子写入 `verification-manifest.json`。复核使用原有单候选扫描和成本限制，
不是追加一次无边界的大扫描。补充结论写在 `results/artifacts/jtsr-verdict.json`
或 CLI `turn.finalResponse` 的 `jtsr-verdict` 代码块里；控制面验证标识、结论与证据字段。
格式缺失、冲突、未完成的模型调用不会被解释为已排除。SDK 原始报告不被控制面改写。

## 仅补跑已有候选

支持单个 daily-tvm / weekly 切面，必须使用原始扫描的同一完整 commit 和干净 checkout。
源扫描须已结束、非演练；不会接受其他补跑作为源，不会从报告执行任意命令、模型或提示词。
配置中的切面路径变化时拒绝自动补跑，要求先检查范围变化。

```bash
jtsr doctor --target /path/to/clean-java-tron
jtsr plan --mode daily-tvm --scope tvm-activation-replay --target /path/to/clean-java-tron
jtsr verify --source-run /private/scans/RUN_ID --target /path/to/clean-java-tron --plan-only
jtsr verify --source-run /private/scans/RUN_ID --target /path/to/clean-java-tron \
  --output-root /private/scans --run-id NEW_RUN_ID --auth chatgpt
```

`--plan-only` 不调用模型；`--dry-run` 只创建带候选队列的演练记录。新运行编号不能覆盖已有运行。
源报告不修改，补跑记录携带 `source_run_id` 和 `target_revision`；原报告页面提供补跑入口。
补跑结论不把原始 partial 覆盖改成 complete。

只重试某次补充复核中的失败项：

```bash
jtsr verify --source-run /private/scans/DISCOVERY_RUN \
  --retry-failed-from /private/scans/PREVIOUS_VERIFY_RUN \
  --target /path/to/clean-java-tron --plan-only
jtsr verify --source-run /private/scans/DISCOVERY_RUN \
  --retry-failed-from /private/scans/PREVIOUS_VERIFY_RUN \
  --target /path/to/clean-java-tron --output-root /private/scans --auth chatgpt
```

按稳定候选标识选择 `failed`，不会重跑已完成/证据不足项，也不会重跑安全拒绝项。
前次复核必须已结束、非演练，且来自同一初筛和完整 commit；缺失/不安全日志拒绝自动选择。
新报告记录 `retry_of_run_id`，两份原始报告保持不变。无符合条件的失败项时拒绝调用模型。

## 手动部署服务器

升级镜像和 runner 后，安装仓库里的 `java-tron-security-review-verify@.service` 并 daemon-reload。
在跳板机 shell 使用原始运行编号启动一次性任务：

```bash
sudo systemctl start --no-block java-tron-security-review-verify@RUN_ID.service
sudo journalctl -u java-tron-security-review-verify@RUN_ID.service -n 60 --no-pager
```

runner 自动取源报告中的 commit，使用隔离临时 checkout。原始报告只读挂载，只有新运行可写；
复用每日锁、资源限制、认证和沙箱，不修改 timer、Nginx 或每日 latest/last-run 指针。
执行前运行 doctor 和候选计划检查；人工预检查可用相同环境加
`JTSR_VERIFY_SOURCE_RUN=RUN_ID JTSR_VERIFY_PLAN_ONLY=1` 运行 runner，不触发模型。
选择失败项时另设 `JTSR_VERIFY_RETRY_FROM=PREVIOUS_VERIFY_RUN`；前次复核额外只读挂载到
`/scan/previous`。这些是单次 runner 环境变量，不必修改每日服务或 timer。
补跑结果写到 `latest-verification` / `last-verification.json`，不适用每日扫描的自动保留清理规则。
完整报告 ZIP 包含逐条结论和复核清单，仍不包括认证、上下文和原始执行日志。
