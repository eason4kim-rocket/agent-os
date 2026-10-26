//! agentd — AgentOS 常驻运行时入口。
//! 用法：agentd [--state-dir <DIR>] --socket <SOCK> [--llrun <PATH>]
//! 默认 state-dir：$HOME/.local/state/agentos（H3：不再使用 /tmp 可预测目录）。

use agentos_core::daemon::{serve, DaemonConfig};
use std::path::PathBuf;

fn default_state_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".local/state/agentos"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/agentos-state"))
}

fn main() {
    let mut state_dir = default_state_dir();
    let mut socket = PathBuf::from("/tmp/agentos.sock");
    let mut llrun: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--state-dir" => state_dir = args.next().map(PathBuf::from).unwrap_or(state_dir),
            "--socket" => socket = args.next().map(PathBuf::from).unwrap_or(socket),
            "--llrun" => llrun = args.next().map(PathBuf::from),
            other => {
                eprintln!("未知参数: {other}\n用法: agentd [--state-dir <DIR>] --socket <SOCK> [--llrun <PATH>]");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = serve(DaemonConfig { state_dir, socket, llrun }) {
        eprintln!("[agentd] 启动失败: {e}");
        std::process::exit(1);
    }
}
