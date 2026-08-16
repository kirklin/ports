//! 端到端测试：在测试进程中启动一个监听 socket，以已知的端口和 PID 作为预期基准，
//! 校验完整的工作链路（内核枚举 → 结构体解析 → 进程关联 → 最终输出）。

use std::net::TcpListener;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ports")
}

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("运行 ports 失败");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn finds_a_socket_we_opened_ourselves() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let me = std::process::id();

    let (stdout, _, code) = run(&[&port.to_string(), "--json"]);
    assert_eq!(code, 0, "应该找到端口 {port}，输出：{stdout}");
    assert!(stdout.contains(&format!(r#""port":{port},"#)), "{stdout}");
    assert!(stdout.contains(&format!(r#""pid":{me},"#)), "{stdout}");
    assert!(stdout.contains(r#""state":"LISTEN""#), "{stdout}");
    assert!(stdout.contains(r#""address":"127.0.0.1""#), "{stdout}");
}

/// IPv6 使用了不同的地址解码路径（macOS 使用 16 字节 union，Linux 使用
/// 32 位字的十六进制表示），因此需要使用真实的内核数据进行独立验证。
#[test]
fn finds_an_ipv6_listener() {
    let Ok(l) = TcpListener::bind("[::1]:0") else {
        eprintln!("跳过：本机未配置 IPv6 回环地址");
        return;
    };
    let port = l.local_addr().unwrap().port();
    let me = std::process::id();

    let (stdout, _, code) = run(&[&port.to_string(), "--json"]);
    assert_eq!(code, 0, "应该找到 IPv6 端口 {port}：{stdout}");
    assert!(stdout.contains(&format!(r#""pid":{me},"#)), "{stdout}");
    // 确保地址正确解析为 ::1，若字节序解析错误，将导致类似于 1:0:0:0:0:0:0:0 的错误结果。
    assert!(
        stdout.contains(r#""address":"::1""#),
        "IPv6 地址解码错了：{stdout}"
    );
}

#[test]
fn json_output_is_parseable_and_complete() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();

    let (stdout, _, _) = run(&[&port.to_string(), "--json"]);
    // 未引入 serde 依赖，此处调用 Python 脚本作为独立的 JSON 格式校验工具。
    let ok = Command::new("python3")
        .arg("-c")
        // 注意：为避免 Rust 的 `\` 续行符消除 Python 脚本中必须的缩进空格，
        // 此处的 Python 脚本全部编写为单行语句格式。
        .arg(concat!(
            "import json,sys\n",
            "d=json.load(sys.stdin)\n",
            "assert len(d)==1, d\n",
            "e=d[0]\n",
            "keys=('port','proto','state','address','peer','peer_port','pid','process',",
            "'user','uid','ppid','started','uptime_secs','exe','command')\n",
            "missing=[k for k in keys if k not in e]\n",
            "assert not missing, missing\n",
            "assert isinstance(e['port'],int) and isinstance(e['pid'],int)\n",
            "assert e['state']=='LISTEN', e\n",
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.as_mut().unwrap().write_all(stdout.as_bytes())?;
            c.wait_with_output()
        });
    match ok {
        Ok(o) => assert!(
            o.status.success(),
            "JSON 校验失败：{}\n原文：{stdout}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(_) => eprintln!("跳过：未找到 python3 环境"),
    }
}

#[test]
fn free_port_exits_one_so_shell_can_branch_on_it() {
    // 绑定后立即释放，以获取一个基本可以确认处于空闲状态的端口号。
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (_, _, code) = run(&[&port.to_string()]);
    assert_eq!(code, 1, "查询空闲端口的进程应当返回退出码 1，以支持条件命令逻辑 `ports N || ...`");
}

#[test]
fn detail_view_shows_the_essentials() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();

    let (stdout, _, _) = run(&[&port.to_string(), "--no-color"]);
    for want in ["PID", "Process", "User", "Started", "Address", "Command"] {
        assert!(stdout.contains(want), "详情里缺 {want}：{stdout}");
    }
    assert!(stdout.contains("LISTEN"), "{stdout}");
}

#[test]
fn kill_refuses_without_force_when_not_a_tty() {
    // 在非交互环境中默认拒绝执行终止进程的操作，防止在自动化脚本中意外中断关键服务。
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();

    let (_, stderr, code) = run(&[&port.to_string(), "-k"]);
    assert_eq!(code, 0, "取消不算失败");
    assert!(stderr.contains("-f"), "应提示需要 -f：{stderr}");
    // 验证目标进程（即本测试进程）依然处于运行状态。
    assert!(TcpListener::bind("127.0.0.1:0").is_ok());
}

#[test]
fn kill_terminates_a_real_child_process() {
    let Ok(mut child) = Command::new("python3")
        .args([
            "-c",
            "import socket,time\n\
             s=socket.socket()\n\
             s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
             s.bind(('127.0.0.1',0))\n\
             s.listen(1)\n\
             print(s.getsockname()[1],flush=True)\n\
             time.sleep(120)\n",
        ])
        .stdout(Stdio::piped())
        .spawn()
    else {
        eprintln!("跳过：未找到 python3 环境");
        return;
    };

    // 读取子进程输出的绑定端口号。
    let port = {
        use std::io::{BufRead, BufReader};
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        line.trim().parse::<u16>().expect("未能从子进程获取有效的端口号")
    };

    let (_, _, code) = run(&[&port.to_string(), "-k", "-f"]);
    assert_eq!(code, 0, "SIGTERM 应当成功");

    let status = child.wait().expect("等待子进程失败");
    assert!(!status.success(), "子进程应当是被信号终止的");

    // 端口已经放开了。
    let (_, _, code) = run(&[&port.to_string()]);
    assert_eq!(code, 1, "目标进程被终止后，对应端口应当被释放");
}

/// 回归测试：验证命令行参数中包含换行符（如 `python -c` 传入的多行脚本）时，不会破坏表格渲染布局。
/// 同时验证恶意输入的 ANSI 转义序列被正确处理，不会直接输出到终端。
#[test]
fn table_stays_one_line_per_entry_even_with_nasty_argv() {
    let script = "import socket,time,sys\n\
                  socks=[]\n\
                  for _ in range(2):\n\
                  \x20   s=socket.socket()\n\
                  \x20   s.bind(('127.0.0.1',0)); s.listen(1); socks.append(s)\n\
                  print(' '.join(str(x.getsockname()[1]) for x in socks),flush=True)\n\
                  time.sleep(60)\n";
    let Ok(mut child) = Command::new("python3")
        .args(["-c", script, "\x1b[31mEVIL\x1b[0m\nsecond line"])
        .stdout(Stdio::piped())
        .spawn()
    else {
        eprintln!("跳过：未找到 python3 环境");
        return;
    };

    let ports: Vec<u16> = {
        use std::io::{BufRead, BufReader};
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        line.trim()
            .split(' ')
            .map(|p| p.parse().expect("端口号"))
            .collect()
    };
    assert_eq!(ports.len(), 2);

    let (stdout, _, _) = run(&[
        &ports[0].to_string(),
        &ports[1].to_string(),
        "--no-color",
    ]);
    let _ = child.kill();
    let _ = child.wait();

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "表头 + 2 行，实际 {} 行：\n{stdout}",
        lines.len()
    );
    assert!(!stdout.contains('\x1b'), "发现未被清理的转义序列：{stdout:?}");
    for row in &lines[1..] {
        assert!(
            row.starts_with(char::is_numeric),
            "行首应当是端口号：{row:?}"
        );
    }
}

/// 回归测试：在应用 fork 模型（如 nginx / gunicorn / php-fpm 等采用 master-worker 架构）时，
/// 父子进程会共享同一个监听 socket。如果内部仅保留一对一的 inode 映射，会导致同一端口
/// 随机报告其中某一个进程 PID。本测试用于验证在 Linux 和 macOS 上均能正确报告所有共享该端口的进程。
#[test]
fn reports_every_process_sharing_a_listening_socket() {
    let Ok(mut child) = Command::new("python3")
        .args([
            "-c",
            "import socket,os,time\n\
             s=socket.socket()\n\
             s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
             s.bind(('127.0.0.1',0))\n\
             s.listen(5)\n\
             kids=[]\n\
             for _ in range(3):\n\
             \x20   pid=os.fork()\n\
             \x20   if pid==0:\n\
             \x20       time.sleep(60); os._exit(0)\n\
             \x20   kids.append(pid)\n\
             print(s.getsockname()[1],os.getpid(),*kids,flush=True)\n\
             time.sleep(60)\n",
        ])
        .stdout(Stdio::piped())
        .spawn()
    else {
        eprintln!("跳过：未找到 python3 环境");
        return;
    };

    let nums: Vec<i64> = {
        use std::io::{BufRead, BufReader};
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        line.trim()
            .split(' ')
            .map(|n| n.parse().expect("端口和 pid"))
            .collect()
    };
    let (port, want_pids) = (nums[0], &nums[1..]);
    assert_eq!(want_pids.len(), 4, "1 个父进程 + 3 个子进程");

    let (stdout, _, code) = run(&[&port.to_string(), "--json"]);

    // 断言前先清理相关测试进程，避免在测试失败时遗留孤儿进程。
    let _ = child.kill();
    let _ = child.wait();
    for pid in want_pids {
        unsafe { libc_kill(*pid as i32) };
    }

    assert_eq!(code, 0, "{stdout}");
    for pid in want_pids {
        assert!(
            stdout.contains(&format!(r#""pid":{pid},"#)),
            "未能正确报告共享该 socket 的目标进程 {pid}：{stdout}"
        );
    }
}

/// 调用 libc::kill 终止进程，以避免为测试引入不必要的依赖。
unsafe fn libc_kill(pid: i32) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, 9) };
}

/// 回归测试：默认情况下 Rust 会将 SIGPIPE 设为 SIG_IGN，这导致向已关闭的管道写入时会引发 panic，
/// 在 `panic="abort"` 策略下会导致进程以 SIGABRT（退出码 134）终止。
/// 对于如 `ports -a --json | head` 此类通过管道截断大量输出的典型用法，该测试验证管道关闭被安全处理。
#[test]
fn early_closed_pipe_does_not_abort() {
    use std::io::Read;

    let mut child = Command::new(bin())
        .args(["-a", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // 仅读取单个字节后立即关闭标准输出管道，触发 SIGPIPE 环境。
    let mut one = [0u8; 1];
    let _ = child.stdout.as_mut().unwrap().read(&mut one);
    drop(child.stdout.take());

    let status = child.wait().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_ne!(
            status.signal(),
            Some(6),
            "管道关闭引发了 SIGABRT，表明未能正确捕获并处理写管道时的 panic"
        );
        // Unix 命令行工具在遭遇 SIGPIPE 时退出属于正常行为，返回成功或对应错误码均可接受，但不应 abort。
        assert!(
            status.success() || status.signal() == Some(13) || status.code() == Some(0),
            "断管后的退出状态不对: {status:?}"
        );
    }
}

#[test]
fn port_range_and_comma_list_both_match() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();

    // 临时端口可能正好是 65534/65535，port+2 会溢出。
    let hi = port.saturating_add(2);
    let (a, _, _) = run(&[&format!("{port}-{hi}"), "--json"]);
    assert!(a.contains(&format!(r#""port":{port},"#)), "区间没匹配上：{a}");

    let (b, _, _) = run(&[&format!("1,{port}"), "--json"]);
    assert!(b.contains(&format!(r#""port":{port},"#)), "逗号列表没匹配上：{b}");
}
