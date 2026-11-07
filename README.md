# Nexa (Rust)

透明代理管理面板的 Rust 重写版本，功能与 Go 版 `nexa-go/` 对齐（同一套 Web 面板、同一套 API 契约）。

独立守护进程，`./nexa` 即可运行，默认监听 `:9990`。  
提供 HTTP API + 内嵌 Web 面板，不依赖 luci / rpcd / ubus / UCI。

## 特性

- **完整 Web 面板**：`assets/` 内嵌 Go 版 `web/dist` 全部资源（HTML/CSS/JS + CodeMirror + 图标），
  六个页面：启动配置 / 配置文件 / 代理配置（5 个 tab）/ 编辑器 / 日志 / 设置
- JWT 认证 + bcrypt 密码（默认 `admin` / `admin`），支持「无验证访问」总开关
- 配置持久化（JSON）+ profiles 上传/下载/编辑/重命名/删除
- 代理核心进程管理：respawn 守护、pidfile、HUP 重载、profile 复制到运行目录、
  GID 绕过（`nexa` 系统组）、cgroup v1/v2 放置、崩溃后自动清理网络规则
- **完整 nftables 规则生成**（`nfttemplate.rs`）：DNS 劫持、redirect/tproxy/tun 三种模式、
  本机/局域网访问控制（user/group/cgroup/IP/MAC）、保留地址、fake-ip、DSCP/fwmark/mark/cgroup/gid 绕过、
  中国大陆 IP 绕过（内嵌 geoip 集合文件）
- **iptables 回退后端**（`netmanager/iptables.rs`）：无 fw4 时自动用 iptables/ip6tables + ipset 下发等价规则，
  含能力探测（xt_MARK / xt_TPROXY / REDIRECT --to-ports）
- `nexa on` / `nexa off` 子命令：只下发/清理防火墙与策略路由，不启停核心
- **定时调度**：定时重启核心、按大小限制定时清日志（内置 5 字段 cron）
- 局域网主机发现（DHCP 租约 + ARP/邻居表）与系统标识符（users/groups/cgroups/os_type）
- 日志查看/清理 + SSE 实时推送（`/api/logs/stream`）、调试报告（`/api/debug`）

## 快速开始

```bash
cargo build --release

# 运行
./target/release/nexa -p 9990

# 指定数据目录
./target/release/nexa -d /etc/nexa -p 9990

# 仅应用 / 清理网络规则（不涉及核心进程）
./target/release/nexa on
./target/release/nexa off
```

浏览器访问：`http://<host>:9990`

## 项目结构

```
src/
  main.rs              # 入口、CLI（-d/-p/--addr、on/off）、路由、Boot 与优雅退出
  web.rs               # include! 组合 web_api.inc.rs + web_ui.inc.rs
  web_api.inc.rs       # 全部 HTTP API 处理器
  web_ui.inc.rs        # 内嵌静态资源（include_str!/include_bytes!）
  config.rs            # 配置模型 + 默认值（对齐原 UCI，含 cgroup/OpenWrt 探测）
  auth.rs              # JWT + bcrypt + 无验证开关
  store.rs             # 配置 / profiles 持久化（原子写）
  core.rs              # 代理核心进程管理（respawn / cgroup / GID / 日志）
  netmanager.rs        # 网络规则：bridge-nf、TUN 等待、ip rule/route、nft 应用、Cleanup
  netmanager/
    iptables.rs        # iptables/ip6tables 回退后端（含 ipset 与能力探测）
  nfttemplate.rs       # nftables 劫持表生成（Build + Render，含单元测试）
  scheduler.rs         # 定时重启 / 定时清日志（内置 cron）
  cgroupsupport.rs     # cgroup v1/v2 支持度检测
  identifiers.rs       # 系统 users/groups/cgroups/os_type
  hosts.rs             # 局域网主机发现
  logger.rs            # app/core 日志 + 订阅广播
  paths.rs             # 路径管理（数据目录 / 运行目录 / 日志 / pidfile）
assets/                # 内嵌前端资源（与 nexa-go/web/dist 一致）
assets/geoip/          # 内嵌 geoip 集合文件，首次运行释放到 <数据目录>/firewall/
```

## API 概览

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/auth/login | 登录 |
| GET | /api/auth/me | 当前用户名 |
| PUT | /api/auth/password | 修改用户名 + 密码 |
| GET/PUT | /api/auth/no-auth | 无验证访问开关 |
| GET | /api/paths | 数据/运行/日志路径 |
| GET | /api/version | 二进制版本 + 应用版本 |
| GET | /api/identifiers | 系统 users/groups/cgroups |
| GET | /api/hosts | 局域网主机 |
| POST | /api/debug | 生成 debug 报告 |
| GET/PUT | /api/config | 读写配置 |
| POST | /api/config/apply | 保存并应用（重启核心 + 网络） |
| GET | /api/status | 核心运行状态与 PID |
| POST | /api/start \| stop \| restart \| restart-core \| reload | 启停/重启/重载 |
| POST | /api/net/on \| off | 单独应用/清理网络规则 |
| GET/POST | /api/profiles | 列表 / 上传（`?name=` + 原始文件） |
| GET/PUT/DELETE | /api/profiles/:name | 下载 / 写入 / 删除 |
| POST | /api/profiles/:name/rename | 重命名（重名 409） |
| GET | /api/logs/app \| core | 日志内容 |
| POST | /api/logs/app/clear \| core/clear | 清空日志 |
| GET | /api/logs/stream | core 日志 SSE 实时推送 |

## 验证

```bash
cargo test                                  # nft 规则渲染单元测试
cargo check                                 # 类型检查
```

## License

MIT
