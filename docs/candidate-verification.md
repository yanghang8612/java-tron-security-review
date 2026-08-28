# 逐条候选复核与补跑

从 0.4.3 开始，每日复核队列合并初筛的 `findings.json` 和 `coverage.json.deferred`。
后者必须含标题和实质问题描述/证据；纯覆盖备注、扫描中断、限流记录和安全拒绝不作为漏洞送审。
按候选稳定标识去重，保留反证、原始暂缓原因及代码位置。每条单独运行，按配置最多 8 条。

初筛保持 Sol / xhigh / 200；复核保持 Sol / high，每条估算成本 30、60 分钟。
限流或明确模型不可用时最多 3 次降级到 5.5 / high，每次最多 30 分钟。
5.5 没有 CLI 成本计价支持，所以降级受次数和超时限制，不宣称有美元硬上限。
本地成本/超时、安全拒绝、未知错误不会触发换模型重试。

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
补跑结果写到 `latest-verification` / `last-verification.json`，不适用每日扫描的自动保留清理规则。
完整报告 ZIP 包含逐条结论和复核清单，仍不包括认证、上下文和原始执行日志。
