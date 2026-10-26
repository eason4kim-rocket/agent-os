//! 执行器（Executor trait）：daemon 收到 exec 请求后，把命令放进笼子里跑。
//!
//! - PlainExecutor：软件层策略预检 + 直接执行（macOS 开发兜底）
//! - LandlockExecutor（Linux）：经由 llrun（Rust 原生 Landlock）内核强制
//!
//! 账本如实记录实际使用的 enforcement 级别——与 README/注释三方一致是铁律。

use crate::policy::Policy;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub rc: i32,
    pub stdout: String,
    pub stderr: String,
    pub enforcement: String,
}

pub trait Executor: Send + Sync {
    fn name(&self) -> &'static str;
    fn enforcement(&self) -> &'static str;
    fn available(&self) -> bool {
        true
    }
    fn execute(&self, policy: &Policy, argv: &[String], stdin: Option<&str>) -> ExecResult;
}

/// 超时感知的进程执行（轮询 try_wait，超时 kill）。
fn run_with_timeout(cmd: &mut Command, stdin: Option<&str>, timeout: Duration) -> (i32, String, String) {
    use std::io::Write;
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (127, String::new(), format!("[harness] spawn 失败: {e}")),
    };
    if let Some(s) = stdin {
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(s.as_bytes());
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                let mut err = String::new();
                if let Some(mut o) = child.stdout.take() {
                    use std::io::Read;
                    let _ = o.read_to_string(&mut out);
                }
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_string(&mut err);
                }
                return (status.code().unwrap_or(-1), out, err);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (124, String::new(), "[harness] 执行超时被强制终止".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return (-1, String::new(), format!("[harness] wait 失败: {e}")),
        }
    }
}

pub struct PlainExecutor;

impl Executor for PlainExecutor {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn enforcement(&self) -> &'static str {
        "software"
    }
    fn execute(&self, policy: &Policy, argv: &[String], stdin: Option<&str>) -> ExecResult {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).current_dir(policy.workdir());
        let (rc, out, err) = run_with_timeout(&mut cmd, stdin, Duration::from_secs(60));
        ExecResult { rc, stdout: out, stderr: err, enforcement: self.enforcement().into() }
    }
}

pub struct LandlockExecutor {
    /// llrun 二进制路径（与 agentd 同目录或 PATH 中）
    pub llrun_path: PathBuf,
    /// 额外只读挂载的执行器目录（/bin 等，由调用方提供）
    pub rox_dirs: Vec<String>,
}

impl Executor for LandlockExecutor {
    fn name(&self) -> &'static str {
        "landlock"
    }
    fn enforcement(&self) -> &'static str {
        "kernel-native"
    }
    fn execute(&self, policy: &Policy, argv: &[String], stdin: Option<&str>) -> ExecResult {
        let mut cmd = Command::new(&self.llrun_path);
        cmd.arg("--rw").arg(policy.workdir());
        for d in &self.rox_dirs {
            cmd.arg("--rox").arg(d);
        }
        cmd.arg("--").args(argv).current_dir(policy.workdir());
        let (rc, out, err) = run_with_timeout(&mut cmd, stdin, Duration::from_secs(120));
        ExecResult { rc, stdout: out, stderr: err, enforcement: self.enforcement().into() }
    }
}

/// 选择执行器：Linux 且 llrun 存在 → 内核原生；否则软件层。
pub fn select(llrun_hint: Option<&PathBuf>) -> Box<dyn Executor> {
    #[cfg(target_os = "linux")]
    {
        let candidates: Vec<PathBuf> = match llrun_hint {
            Some(p) => vec![p.clone()],
            None => {
                let mut v = Vec::new();
                if let Ok(exe) = std::env::current_exe() {
                    if let Some(parent) = exe.parent() {
                        v.push(parent.join("llrun"));
                    }
                }
                v.push(PathBuf::from("llrun"));
                v
            }
        };
        for c in candidates {
            if c.exists() {
                return Box::new(LandlockExecutor {
                    llrun_path: c,
                    rox_dirs: vec![
                        "/bin".into(), "/usr/bin".into(), "/lib".into(),
                        "/usr/lib".into(), "/lib64".into(),
                    ],
                });
            }
        }
    }
    #[allow(unreachable_code)]
    Box::new(PlainExecutor)
}
