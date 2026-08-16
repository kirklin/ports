//! ports —— 查看本地端口占用情况的工具。
//!
//! 能够快速展示端口对应的进程 ID、进程名、所属用户、运行时间以及完整的命令行信息。

mod fmt;
mod model;
mod render;
mod sys;

use std::io::{self, Read, Write};
use std::process::ExitCode;

use fmt::Style;
use model::Entry;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
ports

用法:
    ports [选项] [端口...]

端口:
    3000            单个端口
    3000 8080       多个端口
    3000-3010       端口区间
    (省略)          列出所有监听中的端口

选项:
    -a, --all       包含所有连接状态（默认仅显示 LISTEN 状态）
    -k, --kill      终止占用端口的进程（默认发送 SIGTERM，会请求确认）
    -9              与 -k 配合使用，直接发送 SIGKILL 信号
    -f, --force     使用 -k 时强制终止，不再请求确认
    -j, --json      输出 JSON
        --no-color  不上色
    -h, --help      帮助
    -V, --version   版本

退出码:
    0  成功找到匹配的进程
    1  未找到匹配的进程（可用于条件判断，如 `ports 3000 || echo \"端口未被占用\"`）
    2  命令行参数错误或系统调用失败

示例:
    ports                 # 列出所有监听中的端口
    ports 3000            # 查询占用 3000 端口的进程
    ports 3000 -k         # 终止占用 3000 端口的进程
    ports -a --json       # 输出所有连接状态的 JSON 格式数据
";

struct Args {
    ports: Vec<u16>,
    all: bool,
    kill: bool,
    sigkill: bool,
    force: bool,
    json: bool,
    no_color: bool,
}

fn main() -> ExitCode {
    // 忽略 SIGPIPE 信号，防止因向已关闭的管道写入数据导致程序崩溃（例如：`ports -a --json | head`）。
    // 默认情况下，Rust 会在写入错误时触发 panic，进而导致进程异常退出。
    //
    // SAFETY: 进程刚启动，还没有别的线程；signal 是异步信号安全的。
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(a)) => a,
        Ok(None) => return ExitCode::SUCCESS, // --help / --version 已经打印
        Err(e) => {
            eprintln!("ports: {e}");
            eprintln!("试试 `ports --help`");
            return ExitCode::from(2);
        }
    };

    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ports: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> io::Result<ExitCode> {
    let st = if args.no_color || args.json { Style::plain() } else { Style::detect() };

    let scan = sys::scan()?;
    let skipped = scan.skipped;

    let mut entries: Vec<Entry> = scan
        .entries
        .into_iter()
        .filter(|e| args.all || e.is_listening())
        .filter(|e| args.ports.is_empty() || args.ports.binary_search(&e.local_port).is_ok())
        .collect();
    entries = render::collapse(std::mem::take(&mut entries));

    if entries.is_empty() {
        if args.json {
            println!("[]");
        } else if let [p] = args.ports.as_slice() {
            println!("{}", st.dim(&format!("端口 {p} 没有进程占用")));
        } else if !args.ports.is_empty() {
            println!("{}", st.dim("指定的端口都没有进程占用"));
        } else {
            println!("{}", st.dim("没有监听中的端口"));
        }
        warn_if_partial(skipped, st);
        return Ok(ExitCode::from(1));
    }

    if args.kill {
        return do_kill(&entries, args, st);
    }

    if args.json {
        print!("{}", render::json(&entries));
    } else if args.ports.len() == 1 && entries.len() <= 4 {
        // 当仅查询单个端口时，显示详细的进程视图。
        print!("{}", render::detail(args.ports[0], &entries, st));
    } else {
        print!("{}", render::table(&entries, args.all, st));
    }

    // 如果指定了端口且找到了匹配项，则不再提示权限不足的警告，
    // 因为对于特定的地址和端口组合，通常只会有一个监听者。
    if args.ports.is_empty() {
        warn_if_partial(skipped, st);
    }
    Ok(ExitCode::SUCCESS)
}

/// 若因为非 root 权限导致部分进程信息不可见，输出相应的警告提示。
fn warn_if_partial(skipped: usize, st: Style) {
    if skipped == 0 || unsafe { libc::geteuid() } == 0 {
        return;
    }
    eprintln!(
        "{}",
        st.dim(&format!(
            "note: {skipped} 个进程无权查看（多为其他用户/系统进程），需要完整结果请用 sudo ports"
        ))
    );
}

fn do_kill(entries: &[Entry], args: &Args, st: Style) -> io::Result<ExitCode> {
    // 同一个进程可能占用多个端口，因此需要按 PID 去重以避免重复发送信号。
    let mut targets: Vec<&Entry> = Vec::new();
    for e in entries {
        if !targets.iter().any(|t| t.pid == e.pid) {
            targets.push(e);
        }
    }

    let sig = if args.sigkill { libc::SIGKILL } else { libc::SIGTERM };
    let signame = if args.sigkill { "SIGKILL" } else { "SIGTERM" };

    eprintln!("{}", st.bold("即将终止:"));
    for t in &targets {
        eprintln!(
            "  {} {}  {}  {}",
            st.yellow(&t.pid.to_string()),
            fmt::sanitize(&t.proc_name),
            st.dim(&format!(":{}", t.local_port)),
            st.dim(&fmt::truncate(&fmt::sanitize(t.display_command()), 60))
        );
    }

    if !args.force && !confirm(&format!("发送 {signame}?"))? {
        eprintln!("{}", st.dim("已取消"));
        return Ok(ExitCode::SUCCESS);
    }

    let mut failed = 0;
    for t in &targets {
        // SAFETY: 就是发信号，pid 来自本次扫描。
        if unsafe { libc::kill(t.pid, sig) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!(
                "{} {} ({}): {err}",
                st.red("失败"),
                t.pid,
                fmt::sanitize(&t.proc_name)
            );
            failed += 1;
        }
    }
    if failed == targets.len() {
        return Ok(ExitCode::from(2));
    }

    // 发送 SIGTERM 后，进程可能需要一定时间才能完全退出。
    // 等待一段时间后再报告最终结果，避免用户立即重新运行工具时发现端口仍显示被占用。
    let alive = wait_gone(&targets, 2000);
    // 进程未完全退出并不意味着端口仍然被占用（例如僵尸进程）。
    // 这里以重新扫描的结果作为端口是否已被释放的标准。
    let alive = if alive.is_empty() { alive } else { still_holding(&alive, &targets) };

    for t in &targets {
        // 进程名（以及命令行参数）来自外部输入，在 Linux 上可以通过 prctl 任意修改，
        // 在打印前必须进行清理，以避免潜在的终端控制符注入。
        let name = fmt::sanitize(&t.proc_name);
        if alive.contains(&t.pid) {
            eprintln!(
                "{} {} ({name}) 收到 {signame} 后仍在运行{}",
                st.yellow("!"),
                t.pid,
                if args.sigkill { "" } else { "，可以试试 -9" }
            );
        } else {
            eprintln!("{} {} ({name})", st.green("已终止"), t.pid);
        }
    }
    Ok(if alive.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// 轮询等待指定进程退出，并在超时后返回仍然存活的进程 PID 列表。
fn wait_gone(targets: &[&Entry], timeout_ms: u64) -> Vec<i32> {
    let step_ms = 50;
    let mut waited = 0;
    loop {
        let alive: Vec<i32> = targets
            .iter()
            .filter(|t| unsafe { libc::kill(t.pid, 0) } == 0)
            .map(|t| t.pid)
            .collect();
        if alive.is_empty() || waited >= timeout_ms {
            return alive;
        }
        std::thread::sleep(std::time::Duration::from_millis(step_ms));
        waited += step_ms;
    }
}

/// 重新扫描系统，返回仍然持有指定端口的进程 PID 列表。
/// 为了安全起见，如果扫描失败，将直接返回传入的所有 PID。
fn still_holding(pids: &[i32], targets: &[&Entry]) -> Vec<i32> {
    let Ok(scan) = sys::scan() else {
        return pids.to_vec();
    };
    pids.iter()
        .copied()
        .filter(|pid| {
            let ports: Vec<u16> = targets
                .iter()
                .filter(|t| t.pid == *pid)
                .map(|t| t.local_port)
                .collect();
            scan.entries
                .iter()
                .any(|e| e.pid == *pid && ports.contains(&e.local_port))
        })
        .collect()
}

fn confirm(prompt: &str) -> io::Result<bool> {
    if !fmt::is_tty(libc::STDIN_FILENO) {
        // 在非交互式环境中，默认拒绝执行危险操作，防止在脚本中意外关闭服务。
        eprintln!("{prompt} 非交互环境，需要 -f 才会执行");
        return Ok(false);
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut buf = [0u8; 1];
    let n = io::stdin().read(&mut buf)?;
    eprintln!();
    Ok(n == 1 && (buf[0] == b'y' || buf[0] == b'Y'))
}

fn parse_args(it: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut a = Args {
        ports: Vec::new(),
        all: false,
        kill: false,
        sigkill: false,
        force: false,
        json: false,
        no_color: false,
    };

    for arg in it {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("ports {VERSION}");
                return Ok(None);
            }
            "-a" | "--all" => a.all = true,
            "-k" | "--kill" => a.kill = true,
            "-9" => {
                a.sigkill = true;
                a.kill = true;
            }
            "-f" | "--force" => a.force = true,
            "-j" | "--json" => a.json = true,
            "--no-color" => a.no_color = true,
            s if s.starts_with('-') && s.len() > 1 && !s[1..].starts_with(|c: char| c.is_ascii_digit()) => {
                return Err(format!("未知选项 {s}"));
            }
            s => parse_port_spec(s, &mut a.ports)?,
        }
    }

    if a.kill && a.ports.is_empty() {
        return Err("使用 -k 选项时必须指定目标端口，以防意外终止所有监听进程".into());
    }
    // 对端口列表进行排序和去重，以便后续使用二分查找提高匹配效率。
    a.ports.sort_unstable();
    a.ports.dedup();
    Ok(Some(a))
}

/// 解析端口参数字符串，支持单个端口、逗号分隔列表以及连字符表示的范围。
fn parse_port_spec(s: &str, out: &mut Vec<u16>) -> Result<(), String> {
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u16 = lo.trim().parse().map_err(|_| bad(part))?;
                let hi: u16 = hi.trim().parse().map_err(|_| bad(part))?;
                if lo > hi {
                    return Err(format!("端口区间 {part} 的起点比终点大"));
                }
                out.extend(lo..=hi);
            }
            None => out.push(part.parse().map_err(|_| bad(part))?),
        }
    }
    Ok(())
}

fn bad(s: &str) -> String {
    format!("无法解析的端口格式 `{s}`（有效示例：1-65535，或 3000-3010）")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Option<Args>, String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_single_and_multiple_ports() {
        let a = args(&["3000"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![3000]);
        let a = args(&["3000", "8080"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![3000, 8080]);
    }

    #[test]
    fn parses_range_and_comma_list() {
        let a = args(&["3000-3003"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![3000, 3001, 3002, 3003]);
        let a = args(&["80,443"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![80, 443]);
    }

    #[test]
    fn dash_nine_implies_kill() {
        let a = args(&["3000", "-9"]).unwrap().unwrap();
        assert!(a.kill && a.sigkill);
    }

    #[test]
    fn kill_without_port_is_rejected() {
        // 必须显式指定目标端口，禁止无参数使用 -k，以免意外终止所有监听端口的进程。
        assert!(args(&["-k"]).is_err());
    }

    #[test]
    fn rejects_unknown_flags_and_bad_ports() {
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["http"]).is_err());
        assert!(args(&["99999"]).is_err());
        assert!(args(&["3010-3000"]).is_err());
    }

    #[test]
    fn ports_are_sorted_and_deduped_for_binary_search() {
        let a = args(&["8080", "80", "8080", "443"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![80, 443, 8080]);
        // 确保重叠的端口范围不会产生重复项。
        let a = args(&["3000-3002", "3001-3003"]).unwrap().unwrap();
        assert_eq!(a.ports, vec![3000, 3001, 3002, 3003]);
    }

    #[test]
    fn full_range_is_accepted() {
        let a = args(&["1-65535"]).unwrap().unwrap();
        assert_eq!(a.ports.len(), 65535);
    }

    #[test]
    fn flags_and_ports_can_interleave() {
        let a = args(&["-a", "3000", "--json", "8080"]).unwrap().unwrap();
        assert!(a.all && a.json);
        assert_eq!(a.ports, vec![3000, 8080]);
    }
}
