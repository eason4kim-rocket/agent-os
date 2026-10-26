//! llrun — Landlock 策略编译目标（llandlock.c 的 Rust 版，仅 Linux）。
//! 用法：llrun [--rw PATH]... [--rox PATH]... -- CMD [ARGS]...

fn main() {
    #[cfg(target_os = "linux")]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut rw: Vec<String> = Vec::new();
        let mut rox: Vec<String> = Vec::new();
        let mut cmd_index: Option<usize> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--rw" if i + 1 < args.len() => {
                    rw.push(args[i + 1].clone());
                    i += 2;
                }
                "--rox" if i + 1 < args.len() => {
                    rox.push(args[i + 1].clone());
                    i += 2;
                }
                "--" => {
                    cmd_index = Some(i + 1);
                    break;
                }
                _ => {
                    eprintln!("usage: llrun [--rw P]... [--rox P]... -- CMD...");
                    std::process::exit(2);
                }
            }
        }
        match cmd_index {
            Some(ci) if ci < args.len() => {
                if let Err(code) = agentos_core::landlock::run(&rw, &rox, &args[ci..]) {
                    std::process::exit(code);
                }
            }
            _ => {
                eprintln!("usage: llrun [--rw P]... [--rox P]... -- CMD...");
                std::process::exit(2);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("llrun 仅支持 Linux（Landlock 是 Linux 内核特性）。macOS 请使用 harness 的 landlock/docker 后端。");
        std::process::exit(1);
    }
}
