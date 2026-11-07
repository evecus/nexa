//! 代理核心进程生命周期管理，对齐 Go 版 internal/core（原 proxy.init 的 procd 逻辑）：
//! spawn/respawn/pidfile/HUP/profile 复制/launcher。不假设核心类型。

use crate::config::Config;
use crate::logger::Logger;
use crate::paths;
use crate::store::Store;
use parking_lot::Mutex;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// 核心在 5 秒内退出视为异常崩溃（对齐 Go 版 watch）。
const CRASH_WINDOW: Duration = Duration::from_secs(5);
const MAX_CRASHES: i32 = 1;

struct CoreState {
    child: Option<Child>,
    pid: u32,
    running: bool,
    stop_flag: bool,
    crashes: i32,
}

pub struct CoreManager {
    #[allow(dead_code)]
    store: Arc<Store>,
    log: Arc<Logger>,
    state: Mutex<CoreState>,
    on_give_up: Mutex<Option<Box<dyn Fn() + Send + Sync + 'static>>>,
    /// 上一次 start 使用的配置，watch 线程重启时复用。
    last_cfg: Mutex<Option<Config>>,
    shutting_down: AtomicBool,
}

impl CoreManager {
    pub fn new(store: Arc<Store>, log: Arc<Logger>) -> Self {
        Self {
            store,
            log,
            state: Mutex::new(CoreState {
                child: None,
                pid: 0,
                running: false,
                stop_flag: false,
                crashes: 0,
            }),
            on_give_up: Mutex::new(None),
            last_cfg: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// 注册核心放弃重启时的回调（用于清理网络规则等）。
    pub fn set_on_give_up<F>(&self, f: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        *self.on_give_up.lock() = Some(Box::new(f));
    }

    /// 通知 watch 线程：进程正在退出，不要再 respawn。
    pub fn request_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// 是否运行中。
    pub fn is_running(&self) -> bool {
        self.state.lock().running
    }

    /// 当前核心 pid。
    pub fn pid(&self) -> u32 {
        self.state.lock().pid
    }

    /// 启动核心（对齐 proxy.init start_service 第 83-130 行）。
    pub fn start(self: &Arc<Self>, cfg: &Config) -> anyhow::Result<()> {
        {
            let st = self.state.lock();
            if st.running {
                anyhow::bail!("core already running");
            }
        }

        // 清理残留的核心进程（nexa 非正常退出时 pidfile 可能残留）
        self.kill_stale_core();

        let c = &cfg.config;

        // 校验可执行文件
        if c.run_binary.is_empty() {
            self.log.app("App", "未配置可执行文件路径，退出。");
            anyhow::bail!("run_binary empty");
        }
        if !which_exists(&c.run_binary) {
            self.log.app(
                "App",
                &format!("可执行文件不存在或无执行权限：{}，退出。", c.run_binary),
            );
            anyhow::bail!("run_binary not found: {}", c.run_binary);
        }

        // 校验 profile
        if c.profile.is_empty() {
            self.log.app("配置文件", "未选择配置文件，退出。");
            anyhow::bail!("profile empty");
        }
        let profile_src = paths::profiles_dir().join(&c.profile);
        if !profile_src.exists() {
            self.log
                .app("配置文件", &format!("文件不存在：{}，退出。", c.profile));
            anyhow::bail!("profile not found: {}", c.profile);
        }

        // 复制 profile → run/config.<ext>（对齐 proxy.init:103-111）
        let ext = match c.profile.rfind('.') {
            Some(i) => &c.profile[i + 1..],
            None => "",
        };
        let run_profile: PathBuf = if ext.is_empty() {
            paths::run_dir().join("config")
        } else {
            paths::run_dir().join(format!("config.{}", ext))
        };
        std::fs::create_dir_all(paths::run_dir())?;
        // 切换配置文件后后缀可能不同（如 config.json → config.yaml），
        // 先清理 run 目录里旧的 config / config.* 残留，只保留本次要写入的文件。
        self.clean_run_profiles(&run_profile);
        std::fs::copy(&profile_src, &run_profile)?;
        self.log.app(
            "配置文件",
            &format!("已复制：{} → {}", c.profile, run_profile.display()),
        );

        // 启动参数（对齐 proxy.init:116-119 的 launcher，但直接 exec 避免引号问题）
        let args = split_args(&c.run_args);
        let mut cmd = Command::new(&c.run_binary);
        cmd.args(&args)
            .current_dir(paths::run_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // GID 绕过：核心以 root 运行，主 GID 设为固定数字 config.CORE_BYPASS_GID，
        // nft/iptables 用 skgid/--gid-owner 匹配绕过（对齐 Go 版，无需创建系统组）。
        // meta skgid 匹配的是主 GID，不是附加组，所以必须把 CORE_BYPASS_GID 设为主 GID，
        // 同时把 root 组（GID 0）加到附加组里，保持 root 权限正常。
        //
        // 系统不支持 cgroup 防回环时，GID 绕过是唯一可靠、程序完全可控的手段，
        // 因此这里无条件评估「有效」GID 绕过开关：只要用户开启了，或者系统不支持 cgroup，就启用。
        // 这样即使用户之前保存的配置是在支持 cgroup 的系统上生成的（bypass_gid=false），
        // 迁移到不支持 cgroup 的系统后依然能自动兜底，不会两种防回环手段都没有。
        let cgroup_supported = crate::cgroupsupport::supported();
        let effective_bypass_gid = cfg.proxy.bypass_gid || !cgroup_supported;
        if !cgroup_supported && cfg.proxy.bypass_cgroup {
            self.log
                .app("核心", "当前系统不支持 cgroup 防回环，已自动改用 GID 绕过。");
        }
        let core_gid: Option<u32> = if effective_bypass_gid {
            self.log.app(
                "核心",
                &format!(
                    "已将核心进程主 GID 设为 {}（防回环，无需系统组）。",
                    crate::config::CORE_BYPASS_GID
                ),
            );
            Some(crate::config::CORE_BYPASS_GID)
        } else {
            None
        };
        // 非 unix 平台上 core_gid 不会被读取（无 pre_exec 可用），显式消费避免告警
        #[cfg(not(unix))]
        let _ = core_gid;

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(move || {
                    // nexa 被 kill -9 时内核自动杀掉核心子进程
                    #[cfg(target_os = "linux")]
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
                    libc::setpgid(0, 0);
                    if let Some(gid) = core_gid {
                        // 附加组保留 root 组，主 GID 设为 nexa 组
                        let root_gid: libc::gid_t = 0;
                        libc::setgroups(1, &root_gid as *const libc::gid_t);
                        libc::setgid(gid as libc::gid_t);
                    }
                    Ok(())
                });
            }
        }

        self.log.app("核心", "启动中。");
        let mut child = cmd.spawn()?;
        let pid = child.id();

        // 行缓冲读取 stdout/stderr → core 日志（对齐 Go 的 lineWriter）
        if let Some(out) = child.stdout.take() {
            let log = self.log.clone();
            thread::spawn(move || pump_lines(out, log));
        }
        if let Some(err) = child.stderr.take() {
            let log = self.log.clone();
            thread::spawn(move || pump_lines(err, log));
        }

        {
            let mut st = self.state.lock();
            st.child = Some(child);
            st.pid = pid;
            st.running = true;
            st.stop_flag = false;
            st.crashes = 0;
        }
        *self.last_cfg.lock() = Some(cfg.clone());

        // 写 pidfile
        let _ = std::fs::write(paths::pid_file_path(), pid.to_string());

        // 关键：把核心进程放入指定 cgroup，否则 nft 规则里的
        // `socket cgroupv2 level 2 "services/<name>" counter return`（cgroup v2）
        // 或 `meta cgroup <id> counter return`（cgroup v1）匹配不到，
        // 会导致核心自身出站流量被自身规则再次劫持，连接数指数级增长，内存暴涨。
        // 系统不支持 cgroup 时直接跳过（已经用 GID 绕过兜底，见上文）。
        if cgroup_supported {
            match self.place_into_cgroup(cfg, pid) {
                Ok(()) => self.log.app("核心", &format!("已将 PID {} 加入 cgroup。", pid)),
                Err(e) => self.log.app(
                    "核心",
                    &format!(
                        "警告：cgroup 设置失败：{}，防回环可能失效（已同时启用 GID 绕过作为兜底）。",
                        e
                    ),
                ),
            }
        }

        // respawn 守护
        let this = Arc::clone(self);
        thread::spawn(move || {
            this.watch();
        });
        Ok(())
    }

    /// 停止核心：SIGTERM，3 秒后强杀（含进程组，避免残留子进程）。
    pub fn stop(&self) -> anyhow::Result<()> {
        let child = {
            let mut st = self.state.lock();
            if !st.running && st.child.is_none() {
                return Ok(());
            }
            st.stop_flag = true;
            st.running = false;
            st.pid = 0;
            st.child.take()
        };
        let _ = std::fs::remove_file(paths::pid_file_path());
        if let Some(mut child) = child {
            let pid = child.id();
            send_terminate(pid);
            thread::spawn(move || {
                // 先给 3 秒优雅退出的时间，再强杀整个进程组（核心自己拉起的子进程一并清理）
                thread::sleep(Duration::from_secs(3));
                let _ = child.kill();
                let _ = child.wait();
                kill_process_group(pid);
            });
        }
        Ok(())
    }

    /// HUP 信号快速重载（对齐 procd_set_param reload_signal HUP）。
    pub fn reload(&self) -> anyhow::Result<()> {
        let st = self.state.lock();
        if !st.running || st.pid == 0 {
            anyhow::bail!("core not running");
        }
        send_hup(st.pid)
    }

    /// 重启 = Stop + Start（等 Stop 完成，最多 10 秒）。
    pub async fn restart(self: &Arc<Self>, cfg: &Config) -> anyhow::Result<()> {
        self.stop()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && self.is_running() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.start(cfg)
    }

    pub fn status_json(&self) -> serde_json::Value {
        let st = self.state.lock();
        serde_json::json!({
            "running": st.running,
            "pid": st.pid,
        })
    }

    /// respawn 守护：进程退出后若非主动停止则重启。
    /// 若核心快速退出（5 秒内），视为启动失败，不再重试并触发 onGiveUp 清理网络规则。
    fn watch(self: &Arc<Self>) {
        loop {
            let start_time = Instant::now();
            // 等待本次子进程退出
            loop {
                let mut exited = false;
                {
                    let mut st = self.state.lock();
                    match st.child.as_mut() {
                        None => return, // 已被 stop() 取走
                        Some(c) => match c.try_wait() {
                            Ok(Some(_)) => exited = true,
                            Ok(None) => {}
                            Err(_) => exited = true,
                        },
                    }
                }
                if exited {
                    break;
                }
                if self.shutting_down.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(200));
            }
            let elapsed = start_time.elapsed();

            {
                let mut st = self.state.lock();
                st.running = false;
                st.pid = 0;
                st.child = None;
                let _ = std::fs::remove_file(paths::pid_file_path());
                if st.stop_flag {
                    st.crashes = 0;
                    st.stop_flag = false;
                    return;
                }
                // 核心在 5 秒内退出视为异常崩溃
                if elapsed < CRASH_WINDOW {
                    st.crashes += 1;
                } else {
                    st.crashes = 0;
                }
                if st.crashes >= MAX_CRASHES {
                    self.log.app(
                        "核心",
                        &format!(
                            "连续 {} 次启动后快速退出，停止重试。请检查配置或权限。",
                            MAX_CRASHES
                        ),
                    );
                    let cb = self.on_give_up.lock().take();
                    drop(st);
                    if let Some(cb) = cb {
                        cb();
                    }
                    return;
                }
            }

            if self.shutting_down.load(Ordering::SeqCst) {
                return;
            }
            self.log.app("核心", "进程退出，1 秒后重启。");
            thread::sleep(Duration::from_secs(1));
            let cfg = self.last_cfg.lock().clone();
            match cfg {
                Some(cfg) => {
                    if let Err(e) = self.start(&cfg) {
                        self.log.app("核心", &format!("重启失败：{}", e));
                        return;
                    }
                }
                None => return,
            }
        }
    }

    /// 把核心进程放入配置的 cgroup，对齐原 proxy.init 的 launcher 行为。
    /// cgroup v2：/sys/fs/cgroup/services/<name>/cgroup.procs
    /// cgroup v1：/sys/fs/cgroup/net_cls/<name>/cgroup.procs（同时写 net_cls.classid）
    fn place_into_cgroup(&self, cfg: &Config, pid: u32) -> anyhow::Result<()> {
        let name = cfg.routing.cgroup_name.as_str();
        if name.is_empty() {
            return Ok(());
        }
        let pid_s = pid.to_string();
        match crate::cgroupsupport::detect() {
            crate::cgroupsupport::Version::V2 => {
                let cg_path = format!("/sys/fs/cgroup/services/{}", name);
                if std::fs::create_dir_all(&cg_path).is_err() {
                    // 目录可能已存在或已被其他子进程占用，尝试直接写父级
                    return write_cgroup_procs("/sys/fs/cgroup/services", &pid_s);
                }
                write_cgroup_procs(&cg_path, &pid_s)
            }
            crate::cgroupsupport::Version::V1 => {
                let cg_path = format!("/sys/fs/cgroup/net_cls/{}", name);
                std::fs::create_dir_all(&cg_path)?;
                if !cfg.routing.cgroup_id.is_empty() {
                    let _ = std::fs::write(
                        Path::new(&cg_path).join("net_cls.classid"),
                        &cfg.routing.cgroup_id,
                    );
                }
                write_cgroup_procs(&cg_path, &pid_s)
            }
            crate::cgroupsupport::Version::None => Ok(()),
        }
    }

    /// 读取 pidfile，若其中有 pid 且对应进程仍在运行则杀掉。
    /// 处理 nexa 被 kill -9 后核心进程残留的情况。
    fn kill_stale_core(&self) {
        let data = match std::fs::read_to_string(paths::pid_file_path()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let pid: i32 = match data.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => return,
        };
        if !process_alive(pid) {
            let _ = std::fs::remove_file(paths::pid_file_path());
            return;
        }
        self.log
            .app("核心", &format!("检测到残留核心进程 PID {}，正在终止。", pid));
        send_terminate(pid as u32);
        thread::sleep(Duration::from_millis(500));
        if process_alive(pid) {
            thread::sleep(Duration::from_millis(1500));
            send_kill(pid as u32);
        }
        let _ = std::fs::remove_file(paths::pid_file_path());
        self.log.app("核心", "已清理残留核心进程。");
    }

    /// 启动核心前调用：删除 run 目录下除 keep 以外的 config / config.*，
    /// 保证目录里只有本次要用的这一个配置文件；不动核心自己生成的其它文件。
    fn clean_run_profiles(&self, keep: &Path) {
        let entries = match std::fs::read_dir(paths::run_dir()) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if name != "config" && !name.starts_with("config.") {
                continue;
            }
            if path == keep {
                continue;
            }
            if std::fs::remove_file(&path).is_ok() {
                self.log.app(
                    "配置文件",
                    &format!("已清理 run 目录残留文件：{}", path.display()),
                );
            }
        }
    }
}

/// 逐行读取核心输出写入 core 日志。
fn pump_lines<R: std::io::Read>(r: R, log: Arc<Logger>) {
    let reader = BufReader::new(r);
    for line in reader.lines().map_while(Result::ok) {
        log.core(&format!("{}\n", line));
    }
}

fn write_cgroup_procs(path: &str, pid: &str) -> anyhow::Result<()> {
    Ok(std::fs::write(Path::new(path).join("cgroup.procs"), pid)?)
}

fn split_args(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

fn which_exists(name: &str) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    std::env::split_paths(&std::env::var("PATH").unwrap_or_default()).any(|d| d.join(name).exists())
}

// ── 信号封装（unix / 非 unix） ─────────────────────────

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn send_terminate(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn send_kill(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn kill_process_group(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            // 核心以独立进程组运行（pre_exec 里 setpgid），负 pid 表示整个进程组
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

#[cfg(unix)]
fn send_hup(pid: u32) -> anyhow::Result<()> {
    let ret = unsafe { libc::kill(pid as i32, libc::SIGHUP) };
    if ret != 0 {
        anyhow::bail!("发送 SIGHUP 到 PID {} 失败", pid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_hup(_pid: u32) -> anyhow::Result<()> {
    anyhow::bail!("当前平台不支持 SIGHUP 重载")
}
