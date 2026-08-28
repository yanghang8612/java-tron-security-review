# 私有 HTTP 报告门户

报告服务为现有扫描系统增加网页，不触发扫描、不修改目标源码或每日 timer。
历史报告自动可见，新报告生成后点击刷新即可；页面时间按浏览器时区显示。

## 安装到现有服务器

前提：已部署扫描器，已有 `java-tron-security-review:local` 镜像、UID/GID 10001、
私有 `/var/lib/java-tron-security-review/scans` 目录，以及包含唯一 `listen 6060;`
指令的 Nginx 网关。先检查 `ss -lntup`，确认 8765 没有被其他服务占用。

```bash
cd /path/to/java-tron-security-review
git pull --ff-only
sudo bash deploy/server/install-report-web.sh \
  --nginx-config /etc/nginx/conf.d/tron-gateway.conf
```

该安装器只更新独立的 web 镜像/服务，不覆盖扫描器镜像，不重启扫描、不修改 timer。
复用服务器已有运行时，不需要在老系统上另装 Python 或 Node。
Nginx 原配置先备份，插入一条 include，然后执行 `nginx -t`，成功才 reload；
验证失败恢复原配置。`/gm/`、`/jm/` 等已有代理路由保持原样。
不传 `--nginx-config` 可仅启动回环地址上的报告服务，手动接入其他网关。

访问 `http://<gateway>:6060/security/`。后端只发布在 `127.0.0.1:8765`，不要在
安全组或防火墙中开放 8765。HTTP 不加密账号、会话和报告，必须在受控网络或可信代理中使用；
登录校验不能替代网络隔离。账号用于这个门户，不是 ChatGPT 账号。

默认账号 `reviewer`；随机密码仅存服务器 root 私有文件，在跳板机手动查看：

```bash
sudo cat /etc/java-tron-security-review/report-web-login.txt
```

不要把该文件、报告或浏览器下载目录上传 GitHub。网页使用 8 小时会话，退出立即失效；
服务重启使所有会话失效。每 5 分钟全局最多 15 次登录尝试，过限等待 5 分钟。
密码散列使用 PBKDF2-SHA256；本地初始密码文件便于运维交付，权限 0600。

## 阅读和导出

登录后点击运行记录，查看审查切面、版本、模型、估算用量、正式发现、待验证线索和覆盖记录。
估算用量包含失败/降级尝试，不等同于 ChatGPT 订阅账单。

发现与待验证线索以中文分区卡片展示：标题、严重性来源、问题概述、代码位置，
待验证原因优先显示；展开“分析与证据”查看影响、根因、支持证据、反证、生产可达性和修复建议。
同一发现的不同审查记录分别保留，不把多模型佐证显示为已确认结论。
搜索框可按标题、代码路径、证据和编号筛选；清空搜索恢复全部条目。

“原始 JSON”默认折叠，保留完整原文；报告文件的“阅读”也会显示结构化内容。
未知字段仍按名称和值展示，不丢弃新模型字段。历史报告无需重新扫描即可使用新界面。
门户只从白名单报告文件匹配发现详情，不读取汇总中携带的任意绝对路径；
无法唯一匹配时保留摘要并显示提示，不猜测关联记录。

- `report.md`：在线阅读或者下载 Markdown。
- `findings.json` / `coverage.json`：发现详情、覆盖缺口和待验证项。
- `results.sarif`：用于支持 SARIF 的本地审查工具。
- “下载完整报告 ZIP”：仅打包白名单报告和运行元数据，不包含扫描日志、上下文、状态数据库、密钥。

报告中的模型内容只作为文本显示，不执行 HTML、脚本、图片或外链。
单文件上限 8 MiB，ZIP 原始内容合计上限 64 MiB；超限需运维在服务器安全导出。
扫描结果保留期仍由原扫描器管理（默认 90 天），门户不会创建第二份长期副本。
报告正在写入或被清理时，刷新后重试。

“扫描完成”需要成功的执行结果和有效完整覆盖记录；“覆盖不完整”“执行失败”
及“未结束 / 中断”分别展示，未知/损坏记录不显示为成功。
无正式发现不代表安全；待验证项不是已确认漏洞；多模型一致也不等同于证明。

## 检查、升级与回退

```bash
sudo systemctl status java-tron-security-review-web --no-pager
curl --fail http://127.0.0.1:8765/security/api/health
curl -i http://127.0.0.1:6060/security/api/runs  # 未登录应返回 401
sudo systemctl is-active java-tron-security-review.timer
```

完整验证使用独立的临时运维容器，仅在此次验证中读取门户登录文件，不输出密码或 Cookie：

```bash
sudo docker run --rm --network host --read-only \
  --mount type=bind,src=/etc/java-tron-security-review/report-web-login.txt,dst=/login.txt,readonly \
  --mount "type=bind,src=$PWD/scripts/check_report_web.py,dst=/check.py,readonly" \
  --user 0:0 java-tron-security-review-web:local \
  python3 /check.py --url http://127.0.0.1:6060/security/ --login-file /login.txt
```

后续 `git pull --ff-only` 后重复安装命令即可，已有账号不会被覆盖。
配置位于 `/etc/java-tron-security-review/report-web.env`，修改后重启 web 服务。
不要将扫描器的 `jtsr.env` 或 auth 目录挂载给门户。

回退：停止并禁用 `java-tron-security-review-web`，从 Nginx 原 server 内删除
`include /etc/nginx/snippets/jtsr-report-web.conf;`，`nginx -t` 通过后 reload。
若用备份恢复整份 Nginx 配置，先确认备份之后没有其他路由变更。报告和扫描 timer 不受影响。

需要轮换密码时，先停止 web 服务，把两个 `report-web-auth.json` / `report-web-login.txt`
移动到 root 私有备份目录，再运行安装器生成新账号密码；不要在 shell 历史中输入明文密码。
单独删除密码散列或登录文件会使安装器拒绝继续，以免误覆盖认证信息。
