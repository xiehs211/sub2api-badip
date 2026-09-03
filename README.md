# sub2api-badip

面向公网部署的 Sub2API 登录爆破 IP 社区投票名单。站长先从自己的 Web/反向代理后台日志人工确认 IP，再提交一行脱敏投票；仓库不保存原始日志、账号、密码、请求正文或完整 UA。

## 目录

- `votes/YYYY-MM.csv`：append-only 原始投票，每个 GitHub 用户对同一 IP 最多一行。
- `blocklist/ips.txt`：纯 IP，一行一个，可给 ipset、WAF、fail2ban 等使用。
- `blocklist/ips.json`：带净票数、reporter、次数、时间和 UA 家族的结果。
- `blocklist/nginx-deny.conf`：可被 Nginx `include` 的生成文件。
- `whitelist.txt`：私有/特殊地址、Cloudflare 节点和公共 DNS 等硬拒绝地址。
- `scripts/submit.py`：手动生成并追加一行投票。
- `scripts/build.py`：校验投票并生成 `blocklist/`，由 GitHub Actions 调用。

## 手动提交

### 1. 准备分支

Fork 本仓库后执行：

```bash
git clone https://github.com/YOUR_GITHUB_LOGIN/sub2api-badip.git
cd sub2api-badip
git switch -c report/manual-ip
```

### 2. 人工确认日志

从 Sub2API、Nginx、Caddy 或 Cloudflare 后台日志中确认：

- 请求确实是登录失败或爆破行为；
- IP 是真实客户端 IP，不是 Cloudflare/Nginx 节点；
- `count` 是该 IP 的实际观察次数；
- `ua` 只填写短 UA 家族，例如 `Go-http-client/2.0`，不要填写完整 UA。

`--ip-source` 表示你确认 IP 的来源：`direct` 是 Sub2API 直连，`nginx` 是可信 Nginx 代理链，`cloudflare` 是 Cloudflare `CF-Connecting-IP`。必须同时带 `--confirm-real-ip`，否则命令拒绝执行。

### 3. 生成投票行

下面命令会把一行写入当前月份的 `votes/YYYY-MM.csv`：

```bash
python scripts/submit.py \
  --ip YOUR_PUBLIC_IP \
  --reporter YOUR_GITHUB_LOGIN \
  --vote yes \
  --count 198 \
  --first-seen 2026-09-02T01:12:00Z \
  --last-seen 2026-09-02T09:40:00Z \
  --category auth_login \
  --ua Go-http-client/2.0 \
  --ip-source nginx \
  --confirm-real-ip \
  --evidence-summary "198 failed login responses; real client IP confirmed"
```

`--vote yes` 写入 `+1`，`--vote no` 写入 `-1`。`--first-seen` 默认等于 `--last-seen`，`--last-seen` 默认当前 UTC 时间。`--evidence-summary` 只参与本地哈希计算，不会写入仓库；不要在其中放账号、密码或原始日志。

先预览而不写文件：

```bash
python scripts/submit.py --dry-run \
  --ip YOUR_PUBLIC_IP --reporter YOUR_GITHUB_LOGIN --vote yes --count 198 \
  --ip-source nginx --confirm-real-ip
```

### 4. 检查并提交 PR

```bash
git diff -- votes/2026-09.csv
python scripts/build.py
python -m unittest discover -s tests -v
git add votes/2026-09.csv
git commit -m "report: add manually verified brute-force IP"
git push --set-upstream origin report/manual-ip
```

然后在 GitHub 页面创建 Pull Request。也可以使用已登录的 GitHub CLI：

```bash
gh pr create \
  --title "report: add manually verified brute-force IP" \
  --body "IP manually verified from local web logs; no raw logs uploaded."
```

PR 必须通过 Actions：作者必须与 CSV 中的 `reporter` 一致，历史行不能编辑或删除，IP 必须通过公网地址和白名单校验。

## 判定规则

- 正向 reporter 数量至少 2，或净票数至少 3，才进入黑名单。
- `+1` 是确认爆破，`-1` 是反驳；每个 reporter 对同一 IP 只能投一票。
- 最近 90 天没有观察到的记录过期；`scan`/`scan_*` 类别 30 天过期。
- `whitelist.txt` 命中的地址永不进入名单；所有非全球可路由地址也会被拒绝。
- `count` 是人工从本地日志确认的失败次数，不是投票权重；每行仍只贡献一票。

## 从名单消费

```nginx
include /path/to/sub2api-badip/blocklist/nginx-deny.conf;
```

也可以读取 `blocklist/ips.txt` 后灌入 ipset、Cloudflare WAF 自定义规则或其他本地封禁系统。名单是辅助信号，部署方仍应保留自己的限流、可信代理配置和管理员保护措施。

## 开发检查

```bash
python -m unittest discover -s tests -v
python scripts/build.py
```
