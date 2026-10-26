//! Landlock 内核强制（llandlock.c 的 Rust 原生移植）。
//!
//! 仅 Linux。 handled 集合覆盖 ABI v3 全部 FS 权限（含 REFER/TRUNCATE/MAKE_SYM）；
//! 网络与 IOCTL_DEV 由调用方在容器层兜底（--network none）。

use std::os::unix::io::AsRawFd;

const SYS_LLANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LLANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LLANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const SYS_PRCTL: libc::c_long = libc::SYS_prctl;
const PR_SET_NO_NEW_PRIVS: libc::c_long = 38;
const LL_RULE_PATH_BENEATH: libc::c_long = 1;

// linux/landlock.h ABI v3 文件系统权限位
const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;

const HANDLED_ALL: u64 = (1 << 15) - 1; // bits 0..=14，与上列全集一致

const RW: u64 = HANDLED_ALL & !EXECUTE;
const ROX: u64 = EXECUTE | READ_FILE | READ_DIR;

#[repr(C)]
#[derive(Default)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn create_ruleset() -> Result<i32, String> {
    let attr = RulesetAttr { handled_access_fs: HANDLED_ALL };
    let fd = unsafe {
        libc::syscall(
            SYS_LLANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>() as libc::c_size_t,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(format!("kernel Landlock unavailable: {}", std::io::Error::last_os_error()));
    }
    Ok(fd as i32)
}

fn add_path(ruleset_fd: i32, path: &str, access: u64) -> Result<(), String> {
    let fd = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("[llandlock] warn: skip missing path {path}");
            return Ok(());
        }
        Err(e) => return Err(format!("open {path}: {e}")),
    };
    let rule = PathBeneathAttr { allowed_access: access, parent_fd: fd.as_raw_fd() };
    let r = unsafe {
        libc::syscall(
            SYS_LLANDLOCK_ADD_RULE,
            ruleset_fd as libc::c_int,
            LL_RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0 as libc::c_uint,
        )
    };
    drop(fd); // 显式在 restrict 前关闭（内核在 add_rule 时复制引用）
    if r < 0 {
        return Err(format!("add_rule {path}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// 应用策略并执行命令（execvp 语义：成功则不返回）。
pub fn run(rw: &[String], rox: &[String], argv: &[String]) -> Result<(), i32> {
    let ruleset_fd = match create_ruleset() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("[llrun] {e}");
            return Err(126);
        }
    };
    for p in rw {
        if let Err(e) = add_path(ruleset_fd, p, RW) {
            eprintln!("[llrun] {e}");
            unsafe { libc::close(ruleset_fd) };
            return Err(126);
        }
    }
    for p in rox {
        if let Err(e) = add_path(ruleset_fd, p, ROX) {
            eprintln!("[llrun] {e}");
            unsafe { libc::close(ruleset_fd) };
            return Err(126);
        }
    }
    unsafe {
        if libc::syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            perror("prctl");
            libc::close(ruleset_fd);
            return Err(126);
        }
        if libc::syscall(SYS_LLANDLOCK_RESTRICT_SELF, ruleset_fd as libc::c_int, 0 as libc::c_uint) < 0 {
            eprintln!("[llrun] restrict_self: {}", std::io::Error::last_os_error());
            libc::close(ruleset_fd);
            return Err(126);
        }
        libc::close(ruleset_fd);
    }
    let c_argv: Vec<std::ffi::CString> = argv
        .iter()
        .map(|s| std::ffi::CString::new(s.as_str()).unwrap_or_default())
        .collect();
    let mut c_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    c_ptrs.push(std::ptr::null());
    unsafe {
        libc::execvp(c_ptrs[0], c_ptrs.as_mut_ptr());
    }
    eprintln!("[llrun] exec {}: {}", argv[0], std::io::Error::last_os_error());
    Err(127)
}

fn perror(what: &str) {
    eprintln!("[llrun] {what}: {}", std::io::Error::last_os_error());
}
