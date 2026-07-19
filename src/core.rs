//! 管理外部代理核心的生命周期，对齐 proxy.init 的 procd 逻辑：
//! spawn/respawn/pidfile/HUP/profile 复制/launcher。不假设核心类型。

use anyhow::{anyhow, Result};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::logger::Logger;
use crate::paths;

struct ManagerState {
    /// 核心子进程。watch 协程持有其所有权，仅在 wait 返回后置 None。
    /// 外部代码不应 take() 它，避免 watch 协程拿不到 child。
    child: Option<Child>,
    /// 独立的 pid 字段：对齐 Go 版 m.pid，watch 阻塞期间仍可查询。
    pid: u32,
    running: bool,
    stop_flag: bool,
    crashes: i32,
}

pub struct Manager {
    log: Arc<Logger>,
    state: Mutex<ManagerState>,
    on_give_up: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Manager {
    pub fn new(log: Arc<Logger>) -> Arc<Self> {
        Arc::new(Manager {
            log,
            state: Mutex::new(ManagerState {
                child: None,
                pid: 0,
                running: false,
                stop_flag: false,
                crashes: 0,
            }),
            on_give_up: Mutex::new(None),
        })
    }

    /// OnGiveUp 注册核心放弃重启时的回调。
    pub fn on_give_up<F>(self: &Arc<Self>, fn_: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        *self.on_give_up.lock().unwrap() = Some(Arc::new(fn_));
    }

    /// Running 是否运行中。
    pub fn running(&self) -> bool {
        self.state.lock().unwrap().running
    }

    /// PID 当前核心 pid（无则 0）。
    /// 使用独立 pid 字段而非 child.id()，因为 watch 协程在 wait() 期间
    /// 仍持有 child，外部 child.id() 不可靠（且会与 watch 抢锁）。
    pub fn pid(&self) -> u32 {
        self.state.lock().unwrap().pid
    }

    /// Start 启动核心。对齐 proxy.init start_service。
    pub fn start(self: &Arc<Self>, cfg: &Config) -> Result<()> {
        {
            let st = self.state.lock().unwrap();
            if st.running {
                return Err(anyhow!("core already running"));
            }
        }

        // 清理残留的核心进程
        self.kill_stale_core();

        let c = &cfg.config;

        // 校验可执行文件
        if c.run_binary.is_empty() {
            self.log.app("App", "未配置可执行文件路径，退出。");
            return Err(anyhow!("run_binary empty"));
        }
        if which(&c.run_binary).is_none() {
            self.log.app(
                "App",
                &format!("可执行文件不存在或无执行权限：{}，退出。", c.run_binary),
            );
            return Err(anyhow!("run_binary not found: {}", c.run_binary));
        }

        // 校验 profile
        if c.profile.is_empty() {
            self.log.app("配置文件", "未选择配置文件，退出。");
            return Err(anyhow!("profile empty"));
        }
        let profile_src = format!("{}/{}", paths::PROFILES_DIR, c.profile);
        if !Path::new(&profile_src).exists() {
            self.log.app(
                "配置文件",
                &format!("文件不存在：{}，退出。", c.profile),
            );
            return Err(anyhow!("profile not exist: {}", c.profile));
        }

        // 复制 profile → run/config.<ext>
        let ext = c
            .profile
            .rfind('.')
            .map(|i| &c.profile[i + 1..])
            .unwrap_or("");
        let run_profile = if !ext.is_empty() {
            format!("{}/config.{}", paths::RUN_DIR, ext)
        } else {
            format!("{}/config", paths::RUN_DIR)
        };
        fs::create_dir_all(paths::RUN_DIR)?;
        copy_file(&profile_src, &run_profile)?;
        self.log
            .app("配置文件", &format!("已复制：{} → {}", c.profile, run_profile));

        // 启动参数
        let args = split_args(&c.run_args);
        let mut cmd = Command::new(&c.run_binary);
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // GID 绕过：先确定 supplementary groups（对齐 Go cmd.Groups([]uint32{0})）
        // 注意 std::os::unix::process::CommandExt::groups 在 stable 上是 unstable feature，
        // 故改用 pre_exec 中调用 libc::setgroups 实现。
        let supp_groups: Option<Vec<u32>> = if cfg.proxy.bypass_gid {
            match ensure_nexa_group() {
                Ok(gid) => {
                    cmd.uid(0);
                    cmd.gid(gid);
                    self.log.app(
                        "核心",
                        &format!("已将 nexa 组（GID {}）设为核心进程主 GID。", gid),
                    );
                    Some(vec![0])
                }
                Err(e) => {
                    self.log.app(
                        "核心",
                        &format!("警告：创建 nexa 组失败：{}，GID 绕过可能失效。", e),
                    );
                    None
                }
            }
        } else {
            None
        };

        // 设置进程组 + Pdeathsig（nexa 被 kill -9 时内核自动杀掉核心子进程）+ supplementary groups
        let pdeathsig_setup = move || {
            unsafe {
                libc::setpgid(0, 0);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            }
            if let Some(groups) = &supp_groups {
                let gids: Vec<libc::gid_t> =
                    groups.iter().map(|&g| g as libc::gid_t).collect();
                let rc = unsafe { libc::setgroups(gids.len(), gids.as_ptr()) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        };
        unsafe {
            cmd.pre_exec(pdeathsig_setup);
        }

        self.log.app("核心", "启动中。");
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(e.into());
            }
        };

        let pid = child.id();

        // 捕获 stdout/stderr，按行喂给 logger
        if let Some(stdout) = child.stdout.take() {
            let log = self.log.clone();
            thread::spawn(move || {
                stream_lines(stdout, log);
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let log = self.log.clone();
            thread::spawn(move || {
                stream_lines(stderr, log);
            });
        }

        {
            let mut st = self.state.lock().unwrap();
            st.child = Some(child);
            st.pid = pid;
            st.running = true;
            st.stop_flag = false;
        }

        // 写 pidfile
        let _ = fs::write(paths::PID_FILE_PATH, pid.to_string());

        // 放入 cgroup
        if let Err(e) = self.place_into_cgroup(cfg, pid) {
            self.log.app(
                "核心",
                &format!("警告：cgroup 设置失败：{}，防回环可能失效。", e),
            );
        } else {
            self.log
                .app("核心", &format!("已将 PID {} 加入 cgroup。", pid));
        }

        // respawn 守护
        {
            let mut st = self.state.lock().unwrap();
            st.crashes = 0;
        }
        let self_arc = self.clone();
        let cfg_clone = cfg.clone();
        thread::spawn(move || {
            self_arc.watch(cfg_clone);
        });
        Ok(())
    }

    /// placeIntoCgroup 把核心进程放入配置的 cgroup。
    fn place_into_cgroup(&self, cfg: &Config, pid: u32) -> Result<()> {
        let name = &cfg.routing.cgroup_name;
        if name.is_empty() {
            return Ok(());
        }
        let pid_str = pid.to_string();
        match cgroups_version() {
            2 => {
                let cg_path = format!("/sys/fs/cgroup/services/{}", name);
                if let Err(_) = fs::create_dir_all(&cg_path) {
                    // 目录可能已存在或已被其他子进程占用，尝试直接写父级
                    return write_cgroup_procs("/sys/fs/cgroup/services", &pid_str);
                }
                write_cgroup_procs(&cg_path, &pid_str)
            }
            1 => {
                let cg_path = format!("/sys/fs/cgroup/net_cls/{}", name);
                fs::create_dir_all(&cg_path)?;
                if !cfg.routing.cgroup_id.is_empty() {
                    let _ = fs::write(
                        format!("{}/net_cls.classid", cg_path),
                        &cfg.routing.cgroup_id,
                    );
                }
                write_cgroup_procs(&cg_path, &pid_str)
            }
            _ => Ok(()),
        }
    }

    /// watch 对齐 procd respawn：进程退出后若非主动停止则重启。
    /// 若核心快速退出（5 秒内），视为启动失败，不再重试并清理网络规则。
    fn watch(self: Arc<Self>, cfg: Config) {
        const MAX_CRASHES: i32 = 1;
        let crash_window = Duration::from_secs(5);
        loop {
            // watch 持有 child 的所有权，wait 期间不释放锁。
            // 期间外部 pid()/running() 仍能从独立字段读到正确值。
            let mut child = {
                let mut st = self.state.lock().unwrap();
                match st.child.take() {
                    Some(c) => c,
                    None => return,
                }
            };
            let start_time = Instant::now();
            let _ = child.wait();
            let elapsed = start_time.elapsed();
            // child 已退出，释放句柄
            drop(child);

            {
                let mut st = self.state.lock().unwrap();
                st.running = false;
                st.pid = 0;
                st.child = None;
                let _ = fs::remove_file(paths::PID_FILE_PATH);
                if st.stop_flag {
                    st.crashes = 0;
                    return;
                }
                if elapsed < crash_window {
                    st.crashes += 1;
                } else {
                    st.crashes = 0;
                }
                let crashes = st.crashes;
                drop(st);

                if crashes >= MAX_CRASHES {
                    self.log.app(
                        "核心",
                        &format!(
                            "连续 {} 次启动后快速退出，停止重试。请检查配置或权限。",
                            MAX_CRASHES
                        ),
                    );
                    if let Some(cb) = self.on_give_up.lock().unwrap().clone() {
                        cb();
                    }
                    return;
                }
            }
            self.log.app("核心", "进程退出，1 秒后重启。");
            thread::sleep(Duration::from_secs(1));
            // 重启
            if let Err(e) = self.start(&cfg) {
                self.log.app("核心", &format!("重启失败：{}", e));
                return;
            }
        }
    }

    /// Stop 停止核心。
    /// 注意：watch 协程在 wait() 期间持有 child 句柄，此处无法 take() 它。
    /// 改为通过独立 pid 字段直接发 SIGTERM（对齐 Go 版 cmd.Process.Signal）。
    /// watch 协程 wait() 返回后会检测 stop_flag 并退出，完成最终清理。
    pub fn stop(&self) -> Result<()> {
        let pid = {
            let mut st = self.state.lock().unwrap();
            if !st.running {
                return Ok(());
            }
            st.stop_flag = true;
            st.pid
        };
        if pid > 0 {
            let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
            let _ = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM);
            // 3 秒后若仍存活则强杀
            let pid_for_kill = pid;
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(3));
                let p = nix::unistd::Pid::from_raw(pid_for_kill as i32);
                // 先检测是否还活着
                if nix::sys::signal::kill(p, None).is_ok() {
                    let _ = nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGKILL);
                }
            });
        }
        Ok(())
    }

    /// Reload HUP 信号快速重载。
    #[allow(dead_code)]
    pub fn reload(&self) -> Result<()> {
        let st = self.state.lock().unwrap();
        if !st.running || st.pid == 0 {
            return Err(anyhow!("core not running"));
        }
        let pid = st.pid;
        drop(st);
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGHUP,
        )?;
        Ok(())
    }

    /// Restart = Stop + Start。
    pub fn restart(self: &Arc<Self>, cfg: &Config) -> Result<()> {
        self.stop()?;
        // 等待 stop 完成
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if !self.running() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.start(cfg)
    }

    /// killStaleCore 读取 pidfile，若其中有 pid 且对应进程仍在运行则杀掉。
    fn kill_stale_core(&self) {
        let data = match fs::read_to_string(paths::PID_FILE_PATH) {
            Ok(s) => s,
            Err(_) => return,
        };
        let pid: i32 = match data.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => return,
        };
        let nix_pid = nix::unistd::Pid::from_raw(pid);
        // 发送信号 0 检测进程是否存活
        match nix::sys::signal::kill(nix_pid, None) {
            Ok(_) => {}
            Err(_) => {
                // 进程不存在，仅清理 pidfile
                let _ = fs::remove_file(paths::PID_FILE_PATH);
                return;
            }
        }
        self.log.app(
            "核心",
            &format!("检测到残留核心进程 PID {}，正在终止。", pid),
        );
        // 先 SIGTERM，等 0.5 秒
        let _ = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM);
        thread::sleep(Duration::from_millis(500));
        // 检测是否已退出
        if nix::sys::signal::kill(nix_pid, None).is_ok() {
            thread::sleep(Duration::from_millis(1500));
            let _ = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL);
        }
        let _ = fs::remove_file(paths::PID_FILE_PATH);
        self.log.app("核心", "已清理残留核心进程。");
    }
}

fn stream_lines<R: Read + Send + 'static>(stream: R, log: Arc<Logger>) {
    let reader = BufReader::new(stream);
    for line in reader.lines().flatten() {
        log.core(&format!("{}\n", line));
    }
}

fn copy_file(src: &str, dst: &str) -> Result<()> {
    fs::copy(src, dst)?;
    Ok(())
}

/// splitArgs 简单按空格拆分启动参数。
fn split_args(s: &str) -> Vec<String> {
    let s = s.trim();
    if s.is_empty() {
        return vec![];
    }
    s.split_whitespace().map(|x| x.to_string()).collect()
}

/// which 在 PATH 中查找可执行文件，并校验可执行权限。
fn which(name: &str) -> Option<String> {
    // 如果含路径分隔符，直接检查
    if name.contains('/') {
        let p = Path::new(name);
        if p.exists() {
            if let Ok(meta) = fs::metadata(p) {
                if meta.permissions().mode() & 0o111 != 0 {
                    return Some(name.to_string());
                }
            }
        }
        return None;
    }
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.exists() {
            if let Ok(meta) = fs::metadata(&candidate) {
                if meta.permissions().mode() & 0o111 != 0 {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

/// cgroupsVersion 判断 cgroup 版本。
fn cgroups_version() -> i32 {
    let f = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return 2,
    };
    for line in f.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 {
            // cgroup v2：type 为 cgroup2
            if fields[2] == "cgroup2" {
                return 2;
            }
            // cgroup v1：type 为 cgroup（含 net_cls 控制器）
            if fields[2] == "cgroup" && fields.len() >= 4 && fields[3].contains("net_cls") {
                return 1;
            }
        }
    }
    // 默认按 v2 处理
    2
}

fn write_cgroup_procs(path: &str, pid: &str) -> Result<()> {
    fs::write(format!("{}/cgroup.procs", path), pid)?;
    Ok(())
}

/// EnsureNexaGroup 确保 nexa 系统组存在，返回其 GID。
pub fn ensure_nexa_group() -> Result<u32> {
    // 先查找是否已存在
    if let Some(gid) = crate::sysutil::lookup_group_gid("nexa") {
        return Ok(gid);
    }

    // 尝试 groupadd（标准 Linux）
    if which("groupadd").is_some() {
        let status = Command::new("groupadd").arg("-r").arg("nexa").status();
        if let Ok(s) = status {
            if s.success() {
                return lookup_nexa_gid();
            }
        }
    }
    // 尝试 addgroup（BusyBox/OpenWrt）
    if which("addgroup").is_some() {
        let status = Command::new("addgroup").arg("-S").arg("nexa").status();
        if let Ok(s) = status {
            if s.success() {
                return lookup_nexa_gid();
            }
        }
    }
    // 回退：直接写 /etc/group
    if let Ok(gid) = append_group_to_file("nexa") {
        return Ok(gid);
    }
    Err(anyhow!("无法创建 nexa 组（groupadd/addgroup/写文件均失败）"))
}

fn lookup_nexa_gid() -> Result<u32> {
    crate::sysutil::lookup_group_gid("nexa")
        .ok_or_else(|| anyhow!("创建 nexa 组后查找失败"))
}

/// appendGroupToFile 直接向 /etc/group 追加 nexa 组条目。
fn append_group_to_file(name: &str) -> Result<u32> {
    use std::io::Write;
    let data = fs::read_to_string("/etc/group")?;
    // 收集已占用的 GID
    let mut used = std::collections::HashSet::new();
    for line in data.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if let Ok(gid) = fields[2].parse::<i64>() {
                used.insert(gid);
            }
        }
    }
    // 从 65534 往下找一个空闲 GID
    let mut gid: i64 = 0;
    for i in (100..=65534).rev() {
        if !used.contains(&i) {
            gid = i;
            break;
        }
    }
    if gid == 0 {
        return Err(anyhow!("找不到可用的 GID"));
    }
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open("/etc/group")?;
    writeln!(f, "\n{}:x:{}:", name, gid)?;
    Ok(gid as u32)
}
