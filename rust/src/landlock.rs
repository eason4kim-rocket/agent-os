//! Landlock 内核强制（llandlock.c 的 Rust 原生移植）。
//!
//! 仅 Linux。 handled 集合覆盖 ABI v3 全部 FS 权限（含 REFER/TRUNCATE/MAKE_SYM）；
//! ABI >= 4 时同时强制 TCP bind/connect deny-all（UDP/unix 不在此层，见 README 边界）；
//! IOCTL_DEV（ABI v5）仍为已知缺口。

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

// ABI v4（内核 6.7+）网络位：deny-all 语义 = handled 置位且不加任何 net 规则
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;
const NET_ALL: u64 = NET_BIND_TCP | NET_CONNECT_TCP;
const LL_CREATE_RULESET_VERSION: u64 = 1;

const RW: u64 = HANDLED_ALL & !EXECUTE;
const ROX: u64 = EXECUTE | READ_FILE | READ_DIR;

#[repr(C)]
#[derive(Default)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64, // ABI v4
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// 内核是否支持 Landlock ABI v4+（网络强制前提）。供 executor 如实判定。
pub fn network_supported() -> bool {
    probe_abi() >= 4
}

fn probe_abi() -> i64 {
    unsafe { libc::syscall(SYS_LLANDLOCK_CREATE_RULESET, std::ptr::null::<libc::c_void>(), 0 as libc::size_t, LL_CREATE_RULESET_VERSION as libc::c_uint) as i64 }
}

fn create_ruleset(deny_net: bool) -> Result<i32, String> {
    let abi = probe_abi();
    let net_enforced = deny_net && abi >= 4;
    if deny_net && abi >= 0 && abi < 4 {
        eprintln!("[llrun] warn: kernel Landlock ABI {abi} < 4，网络不受内核强制");
    }
    if deny_net && abi < 0 {
        eprintln!("[llrun] warn: 内核不支持 Landlock，网络不受内核强制");
    }
    let attr = RulesetAttr {
        handled_access_fs: HANDLED_ALL,
        handled_access_net: if net_enforced { NET_ALL } else { 0 },
    };
    let size = if net_enforced {
        std::mem::size_of::<RulesetAttr>()
    } else {
        std::mem::size_of::<u64>()
    };
    let fd = unsafe {
        libc::syscall(
            SYS_LLANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            size as libc::size_t,
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
    let ruleset_fd = match create_ruleset(/* deny_net: v0 策略一律禁网 */ true) {
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
