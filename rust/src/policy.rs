//! Policy（agentos.policy.v0）：与 harness/policy.py 的 to_dict/validate 语义对齐。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "agentos.policy.v0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub schema: String,
    pub workdir: String,
    #[serde(default)]
    pub extra_read: Vec<String>,
    #[serde(default)]
    pub allow_commands: Vec<String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub backend: String,
    #[serde(default = "default_max_steps")]
    pub max_steps: u32,
}

fn default_max_steps() -> u32 {
    24
}

/// 与 harness/policy.py DEFAULT_ALLOW_COMMANDS 保持一致（find 因 -delete 移出）。
pub const DEFAULT_ALLOW_COMMANDS: &[&str] = &[
    "ls", "cat", "head", "tail", "grep", "wc", "mkdir", "mv", "cp", "echo",
];

/// 词法归一化：折叠 `.` 与 `..` 组件。不解析符号链接（内核层兜底）。
pub fn normalize_lexical(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                // 只在非根位置回退；越出根的 `..` 直接丢弃（对绝对路径即钉在根）
                if !out.pop() && !p.is_absolute() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// 目的地操作数会写入文件系统的命令（最后一个非选项参数）。
const WRITE_DEST_COMMANDS: &[&str] = &["mkdir", "mv", "cp", "tee"];

/// 任何参数中出现即拒绝的破坏性选项。
const DENIED_OPTION_FRAGMENTS: &[&str] = &["-delete", "-exec", "-fprintf", "-fls", "-ok"];

impl Policy {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let p: Policy = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if p.schema != SCHEMA {
            return Err(format!("schema 不匹配: {} (期望 {SCHEMA})", p.schema));
        }
        Ok(p)
    }

    pub fn workdir(&self) -> PathBuf {
        PathBuf::from(&self.workdir)
    }

    fn resolve_token(&self, raw: &str) -> PathBuf {
        let p = Path::new(raw);
        let joined = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.workdir().join(p)
        };
        // H2 修复：词法折叠 `.`/`..`。Rust 的 starts_with 按组件逐字比较、不折叠 ..，
        // 不折叠则 `work/../../etc` 会被误判为在 work 之下（红队 H2 已实证逃逸）。
        normalize_lexical(&joined)
    }

    /// 路径是否在 root 之下。符号链接的最终语义由内核层（Landlock）兜底；
    /// plain 后端的残余符号链接风险已在 README 诚实声明。
    fn inside(p: &Path, root: &Path) -> bool {
        p.starts_with(root)
    }

    pub fn path_allowed_read(&self, raw: &str) -> Result<(), String> {
        let p = self.resolve_token(raw);
        if Self::inside(&p, &self.workdir()) {
            return Ok(());
        }
        for r in &self.extra_read {
            if Self::inside(&p, &PathBuf::from(r)) {
                return Ok(());
            }
        }
        Err(format!("path outside allowed roots: {}", p.display()))
    }

    pub fn path_allowed_write(&self, raw: &str) -> Result<(), String> {
        let p = self.resolve_token(raw);
        if Self::inside(&p, &self.workdir()) {
            return Ok(());
        }
        Err(format!("write outside workdir: {}", p.display()))
    }

    pub fn command_allowed(&self, argv: &[String]) -> Result<(), String> {
        let Some(first) = argv.first() else {
            return Err("empty command".into());
        };
        let cmd = Path::new(first)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(first);
        if self.allow_commands.iter().any(|c| c == cmd) {
            Ok(())
        } else {
            Err(format!("command '{cmd}' not in allow_commands"))
        }
    }

    /// run_command 完整软件层校验（H1 修复的 Rust 版）：白名单 + 危险选项 + 操作数路径。
    pub fn validate_run_command(&self, argv: &[String]) -> Result<(), String> {
        self.command_allowed(argv)?;
        let cmd = Path::new(&argv[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&argv[0])
            .to_string();

        for tok in &argv[1..] {
            if tok.starts_with('-')
                && DENIED_OPTION_FRAGMENTS.iter().any(|f| tok.contains(f))
            {
                return Err(format!("forbidden option: {tok}"));
            }
        }

        let operands: Vec<&String> = argv[1..].iter().filter(|t| !t.starts_with('-')).collect();
        let n = operands.len();
        for (i, tok) in operands.iter().enumerate() {
            let is_write_dest = WRITE_DEST_COMMANDS.contains(&cmd.as_str()) && i + 1 == n;
            if is_write_dest {
                self.path_allowed_write(tok)
                    .map_err(|e| format!("{cmd}: {e}"))?;
            } else {
                let p = self.resolve_token(tok);
                let may_read = p.exists() || p.is_absolute();
                if may_read {
                    self.path_allowed_read(tok)
                        .map_err(|e| format!("{cmd}: {e}"))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(tmp: &Path) -> Policy {
        Policy {
            schema: SCHEMA.into(),
            workdir: tmp.join("work").to_string_lossy().into(),
            extra_read: vec![],
            allow_commands: DEFAULT_ALLOW_COMMANDS.iter().map(|s| s.to_string()).collect(),
            network: false,
            backend: "auto".into(),
            max_steps: 24,
        }
    }

    #[test]
    fn dotdot_escape_denied() {
        // H2 回归：`..` 词法折叠后越出 workdir 必须拒绝
        let tmp = tempfile();
        let mut p = policy(&tmp);
        p.workdir = tmp.join("work").to_string_lossy().into();
        std::fs::create_dir_all(p.workdir()).unwrap();
        assert!(p.path_allowed_read("../outside/secret").is_err());
        assert!(p.path_allowed_read("sub/../../outside/x").is_err());
        assert!(p.path_allowed_write("a/../../evil").is_err());
        // 笼内多级 .. 不越出则放行
        assert!(p.path_allowed_read("a/b/../../../work/a.txt").is_ok());
    }

    #[test]
    fn escape_denials_match_python() {
        let tmp = tempfile();
        let p = policy(&tmp);
        std::fs::create_dir_all(p.workdir()).unwrap();
        std::fs::write(p.workdir().join("a.txt"), "x").unwrap();

        let escapes: Vec<Vec<String>> = vec![
            ["cat", "/etc/passwd"].iter().map(|s| s.to_string()).collect(),
            ["cp", "/etc/passwd", "stolen.txt"].iter().map(|s| s.to_string()).collect(),
            ["cp", "a.txt", "/tmp/stolen"].iter().map(|s| s.to_string()).collect(),
            ["mv", "a.txt", "/etc/moved"].iter().map(|s| s.to_string()).collect(),
            ["mkdir", "/tmp/escape"].iter().map(|s| s.to_string()).collect(),
            ["sh", "-c", "id"].iter().map(|s| s.to_string()).collect(),
            ["find", ".", "-delete"].iter().map(|s| s.to_string()).collect(),
        ];
        for argv in escapes {
            assert!(p.validate_run_command(&argv).is_err(), "应拒绝: {argv:?}");
        }
        assert!(p.validate_run_command(&["ls".to_string()]).is_ok());
        assert!(p.validate_run_command(&["mkdir".to_string(), "-p".to_string(), "2026-01".to_string()]).is_ok());
    }

    fn tempfile() -> PathBuf {
        let d = std::env::temp_dir().join(format!("agentos-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
