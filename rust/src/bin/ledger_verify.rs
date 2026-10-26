//! ledger-verify — 独立核验 agentos.ledger.v0 账本。
//! 用法：ledger-verify <ledger.jsonl> [ledger.anchor]

use agentos_core::ledger::Ledger;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ledger-verify <ledger.jsonl> [ledger.anchor]");
        std::process::exit(2);
    }
    let ledger = Ledger::load(&PathBuf::from(&args[1]));
    let anchor = args.get(2).map(PathBuf::from);
    match ledger.verify(anchor.as_deref()) {
        Ok(total) => println!("[账本] ✔ 完整：{total} 条事件，哈希链无断裂，锚点核对一致"),
        Err(e) => {
            eprintln!("[账本] ✘ 存疑：首个问题 → {}", e.reason);
            std::process::exit(1);
        }
    }
}
