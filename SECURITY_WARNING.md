# ⚠️ SECURITY WARNING / 安全警告

本仓库为公开仓库（GitHub）。在 `/mnt/windows/g/deepseekworklpalce/SCIN/` 目录内进行任何**调试、测试、示例、冒烟测试**时，**严禁**将以下内容提交或写入本仓库：

## 禁止提交 / 写入的内容

1. **个人身份凭据**
   - Gmail App Password、SMTP 密码、邮箱账号
   - API Key（无论哪家厂商）
   - 私钥 / 公钥对（尤其是部署服务器上实际在用的）
   - 各类 Token（GitHub、OpenAI、其他 AI、OAuth）

2. **基础设施细节**
   - VPS 公网 IP、SSH 密钥路径、Nginx 反代配置
   - 域名（生产域名的具体值）
   - 服务器账户名、密码

3. **临时 / 测试文件**（每次测试后必须删除，**不要** `git add` / `git commit`）
   - `*.tgz`、`*.tar.gz`、`*.zip` 部署包
   - `*_deploy*`、`_sn_*` 部署脚本 / 产物
   - `test_bug_*.py`、`final_fix_*.py`、`debug_*.py` 等临时脚本
   - `schema.sql`、`init_*.sql` 等数据库初始化脚本（**如果**涉及生产结构）
   - 任何 `*.env` 变体（`.env`、`.env.local`、`env_debug`、`tmp.env`、`test.env`）
   - 任何 `*.log`（通常是带有生产上下文的调试日志）
   - `scratch/`、`tmp/`、`tmp_test/` 等临时目录

## 已被 `.gitignore` 覆盖的（防止误提交）

```
.env
.env.local
*.env
*.tar.gz
*.tgz
*.db
*.db.bak*
*.log
_local_*.json
*.secret
_test_*.py
scratch/
tmp/
tmp_test/
_deploy* / _sn_*
.pytest_cache / __pycache__
```

> 在添加临时文件前，**先**用 `git check-ignore -v <你的文件>` 确认它确实被忽略；忽略规则写错了会直接进仓库。

## 如何操作临时测试脚本（正确的姿势）

```bash
# 1. 在 / 或 /tmp 下调试，**不要** 在仓库目录内
cp your_temp_script.py /tmp/

# 2. /tmp 下操作
cd /tmp && python3 your_temp_script.py

# 3. 测试完毕后清理
rm -f /tmp/your_temp_script.py

# 4. 确认真的需要保留为正式资产才进仓库
git status   # 应该是干净的
```

## 历史重写提醒

本仓库在 `2026-08-25` 做过一次敏感信息重写（移除 `translations/` 目录 + `HANDOFF.md` + 全历史 IP/域名/Gmail 脱敏），GitHub 服务端旧对象保留约 16 天后消失。
此后**任何**一次 `git push --force` 或新涉及敏感内容的提交，必须在这两天内赶在 GH 清理窗口前再重写一次。**不要**再把敏感信息反复写进去。

## 如果有人不小心把敏感信息推上去了

```bash
# 别慌，立刻：
1. 用 git filter-repo 重写历史（参考上面的 2026-08-25 流程）
2. 强推 origin：git push origin main --force
3. 在 GitHub Settings → 立即改 GitHub 仓库为 Private 或 Delete（如果是凭据级泄露）
4. 更换所有已泄露的密码 / Key / 凭据（GitHub、SMTP、VPS 账号）
5. 在 GitHub → Settings → Security → Secret Scanning 检查是否还有其他泄露
```

> **规则：敏感信息（任何真实的）只存在本地 / 部署服务器上，永远不进本仓库。本仓库只放代码 / 示例 / 文档。**
