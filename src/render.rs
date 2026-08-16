//! 渲染层：处理表格输出、单端口详细信息以及 JSON 格式化输出。

use crate::fmt::{self, Style};
use crate::model::{Entry, Proto};

/// 生成表格形式的输出。最后一列将占满终端的剩余宽度，超出部分将被截断以避免破坏排版。
pub fn table(entries: &[Entry], show_state: bool, st: Style) -> String {
    let now = fmt::now();

    let mut headers: Vec<&str> = vec!["PORT", "PROTO"];
    if show_state {
        headers.push("STATE");
    }
    headers.extend_from_slice(&["PID", "PROCESS", "USER", "UPTIME", "ADDRESS", "COMMAND"]);

    // 设置单列的最大宽度。如果不加限制，某些过长的进程名（如 "Microsoft Edge Helper"）
    // 可能会挤占命令行（COMMAND）列的显示空间。
    const MAX_PROCESS: usize = 22;
    const MAX_ADDRESS: usize = 21;

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let mut r = vec![e.local_port.to_string(), e.proto.to_string()];
            if show_state {
                r.push(e.state.map(|s| s.as_str()).unwrap_or("-").to_string());
            }
            // 进程名和命令行参数可能包含不可见字符，在输出到表格前需进行清理。
            r.extend([
                e.pid.to_string(),
                fmt::truncate(&fmt::sanitize(&e.proc_name), MAX_PROCESS),
                fmt::sanitize(&e.user),
                fmt::duration(now.saturating_sub(e.start_time)),
                fmt::truncate(&e.local_addr, MAX_ADDRESS),
                fmt::sanitize(e.display_command()),
            ]);
            r
        })
        .collect();

    // 除最后一列外，计算各列内容的实际最大宽度（与表头宽度对比取最大值）。
    let ncol = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| fmt::width(h)).collect();
    for r in &rows {
        for i in 0..ncol - 1 {
            widths[i] = widths[i].max(fmt::width(&r[i]));
        }
    }

    let gap = 2;
    let fixed: usize = widths[..ncol - 1].iter().sum::<usize>() + gap * (ncol - 1);
    // 最后一列至少保留 12 列的空间，避免在终端过窄时命令被过度截断为一个省略号。
    let last = fmt::term_width().saturating_sub(fixed).max(12);

    let mut out = String::new();
    let head: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            if i == ncol - 1 {
                h.to_string()
            } else {
                fmt::pad(h, widths[i] + gap)
            }
        })
        .collect();
    out.push_str(&st.dim(&head));
    out.push('\n');

    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            if i == ncol - 1 {
                out.push_str(&st.dim(&fmt::truncate(cell, last)));
            } else {
                let painted = match headers[i] {
                    "PORT" => st.bold(&st.cyan(cell)),
                    "PID" => st.yellow(cell),
                    "STATE" => {
                        if cell == "LISTEN" {
                            st.green(cell)
                        } else {
                            st.dim(cell)
                        }
                    }
                    _ => cell.clone(),
                };
                // 终端颜色转义序列不计入视觉宽度，因此补充空格时需按照原始文本宽度计算。
                out.push_str(&painted);
                out.push_str(&" ".repeat(widths[i] + gap - fmt::width(cell)));
            }
        }
        out.push('\n');
    }
    out
}

/// 显示单个端口的详细信息。侧重于展示“进程身份”及其相关上下文，而非仅仅罗列文件描述符。
pub fn detail(port: u16, entries: &[Entry], st: Style) -> String {
    let now = fmt::now();
    let mut out = String::new();

    // 键名固定宽度为 9，加上前后各 2 个空格的缩进，换行内容需与值列对齐。
    const KEY: usize = 9;
    const INDENT: usize = 2 + KEY + 2;
    let avail = fmt::term_width().saturating_sub(INDENT).max(24);

    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str(&st.dim("  ───\n\n"));
        }
        // UDP 协议没有状态，不显示任何占位符。
        let state = e.state.map(|s| s.as_str());
        out.push_str(&format!(
            "{} {}{}\n\n",
            st.bold(&st.cyan(&format!("{port}"))),
            st.dim(&e.proto.to_string()),
            match state {
                Some("LISTEN") => format!(" {}", st.green("LISTEN")),
                Some(s) => format!(" {}", st.dim(s)),
                None => String::new(),
            }
        ));

        let started = e.start_time;
        let mut row = |k: &str, v: &str| {
            out.push_str(&format!("  {}  {}\n", st.dim(&fmt::pad(k, KEY)), v));
        };
        row("PID", &st.yellow(&e.pid.to_string()));
        row("Process", &fmt::sanitize(&e.proc_name));
        row("User", &format!("{} ({})", fmt::sanitize(&e.user), e.uid));
        row(
            "Started",
            &format!(
                "{}  {}",
                fmt::local_time(started),
                st.dim(&format!("({} ago)", fmt::duration(now.saturating_sub(started))))
            ),
        );
        row("Address", &addr_port(&e.local_addr, e.local_port));
        if let Some(peer) = &e.remote_addr {
            row("Peer", &addr_port(peer, e.remote_port));
        }
        // 可执行文件路径或命令行参数可能非常长（特别是在 Chromium 系列浏览器中），采用折行显示而非截断。
        if let Some(exe) = &e.exe {
            wrapped(&mut out, "Binary", &fmt::sanitize(exe), KEY, INDENT, avail, 3, st);
        }
        if let Some(cmd) = &e.cmdline {
            wrapped(&mut out, "Command", &fmt::sanitize(cmd), KEY, INDENT, avail, 6, st);
        }
        let mut row = |k: &str, v: &str| {
            out.push_str(&format!("  {}  {}\n", st.dim(&fmt::pad(k, KEY)), v));
        };
        row("Parent", &e.ppid.to_string());
    }

    if entries.len() == 1 {
        out.push_str(&format!(
            "\n  {}  {}\n",
            st.dim("kill it:"),
            st.dim(&format!("ports {port} -k"))
        ));
    }
    out
}

/// 详细信息中的多行字段渲染逻辑：首行显示键名，后续行通过缩进与首行的值对齐。
#[allow(clippy::too_many_arguments)]
fn wrapped(
    out: &mut String,
    key: &str,
    val: &str,
    keyw: usize,
    indent: usize,
    avail: usize,
    max_lines: usize,
    st: Style,
) {
    for (i, line) in fmt::wrap(val, avail, max_lines).iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("  {}  {}\n", st.dim(&fmt::pad(key, keyw)), line));
        } else {
            out.push_str(&format!("{}{}\n", " ".repeat(indent), st.dim(line)));
        }
    }
}

pub fn json(entries: &[Entry]) -> String {
    let now = fmt::now();
    let mut out = String::from("[\n");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str("  {");
        out.push_str(&format!(r#""port":{},"#, e.local_port));
        out.push_str(&format!(r#""proto":"{}","#, e.proto));
        match e.state {
            Some(s) => out.push_str(&format!(r#""state":"{}","#, s.as_str())),
            None => out.push_str(r#""state":null,"#),
        }
        out.push_str(&format!(r#""address":{},"#, jstr(&e.local_addr)));
        match &e.remote_addr {
            Some(p) => out.push_str(&format!(
                r#""peer":{},"peer_port":{},"#,
                jstr(p),
                e.remote_port
            )),
            None => out.push_str(r#""peer":null,"peer_port":null,"#),
        }
        out.push_str(&format!(r#""pid":{},"#, e.pid));
        out.push_str(&format!(r#""process":{},"#, jstr(&e.proc_name)));
        out.push_str(&format!(r#""user":{},"#, jstr(&e.user)));
        out.push_str(&format!(r#""uid":{},"#, e.uid));
        out.push_str(&format!(r#""ppid":{},"#, e.ppid));
        out.push_str(&format!(r#""started":{},"#, e.start_time));
        out.push_str(&format!(
            r#""uptime_secs":{},"#,
            now.saturating_sub(e.start_time)
        ));
        match &e.exe {
            Some(p) => out.push_str(&format!(r#""exe":{},"#, jstr(p))),
            None => out.push_str(r#""exe":null,"#),
        }
        match &e.cmdline {
            Some(c) => out.push_str(&format!(r#""command":{}"#, jstr(c))),
            None => out.push_str(r#""command":null"#),
        }
        out.push('}');
    }
    out.push_str("\n]\n");
    out
}

/// 最小化 JSON 字符串转义。控制字符必须转换为 \u 格式，以确保输出为合法的 JSON 格式。
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// 合并属于同一进程且端口相同的 IPv4 和 IPv6 监听记录。
/// 很多服务会同时绑定两种协议，导致工具输出两行相同的信息。此处将其合并以提升可读性。
pub fn collapse(mut entries: Vec<Entry>) -> Vec<Entry> {
    // 排序的键值必须包含用于判断是否可以合并的所有字段。
    // 否则，两条原本可以合并的记录中间可能会插入一条不可合并的记录（例如同一端口的 ESTABLISHED 状态），
    // 从而导致合并逻辑失效。
    entries.sort_by(|a, b| {
        a.local_port
            .cmp(&b.local_port)
            .then(a.proto_rank().cmp(&b.proto_rank()))
            .then(a.pid.cmp(&b.pid))
            .then(a.state_key().cmp(b.state_key()))
            .then(a.remote_addr.is_some().cmp(&b.remote_addr.is_some()))
            .then(a.local_addr.cmp(&b.local_addr))
    });

    let mut out: Vec<Entry> = Vec::with_capacity(entries.len());
    for e in entries {
        match out.last_mut() {
            Some(prev)
                if prev.pid == e.pid
                    && prev.proto == e.proto
                    && prev.local_port == e.local_port
                    && prev.state == e.state
                    && prev.remote_addr.is_none()
                    && e.remote_addr.is_none() =>
            {
                if prev.local_addr != e.local_addr {
                    // 如果已经绑定了 0.0.0.0 (表示监听所有地址)，则无需再追加其他具体地址。
                    if prev.local_addr == "*" || e.local_addr == "*" {
                        prev.local_addr = "*".to_string();
                    } else {
                        prev.local_addr = format!("{},{}", prev.local_addr, e.local_addr);
                    }
                }
            }
            _ => out.push(e),
        }
    }
    out
}

impl Entry {
    fn proto_rank(&self) -> u8 {
        match self.proto {
            Proto::Tcp => 0,
            Proto::Udp => 1,
        }
    }

    /// 用于排序的状态标识。只需保证相同的状态排列在一起即可。
    fn state_key(&self) -> &'static str {
        self.state.map(|s| s.as_str()).unwrap_or("")
    }
}

/// 对包含端口号的 IPv6 地址进行格式化时，必须加上方括号（例如 `[::1]:8080`），
/// 否则该地址自身可能被误认为是一个不带端口的合法 IPv6 地址。
fn addr_port(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TcpState;

    fn entry(pid: i32, port: u16, addr: &str) -> Entry {
        Entry {
            proto: Proto::Tcp,
            state: Some(TcpState::Listen),
            local_addr: addr.to_string(),
            local_port: port,
            remote_addr: None,
            remote_port: 0,
            pid,
            proc_name: "node".into(),
            exe: Some("/usr/bin/node".into()),
            cmdline: Some("node server.js".into()),
            user: "kirk".into(),
            uid: 501,
            ppid: 1,
            start_time: 1_700_000_000,
        }
    }

    #[test]
    fn collapse_merges_v4_and_v6_rows_of_same_process() {
        let v = collapse(vec![entry(10, 3000, "127.0.0.1"), entry(10, 3000, "::1")]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].local_addr, "127.0.0.1,::1");
    }

    #[test]
    fn collapse_prefers_wildcard_over_listing_addresses() {
        let v = collapse(vec![entry(10, 3000, "*"), entry(10, 3000, "127.0.0.1")]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].local_addr, "*");
    }

    /// 回归测试：合并操作仅比较相邻行。因此排序规则必须保证可以合并的行相互紧挨。
    /// 在同一进程、同一端口上，ESTABLISHED 状态的记录不应插入到 IPv4/IPv6 LISTEN 记录之间，
    /// 否则会导致原本应该合并的两条记录被拆分。
    #[test]
    fn collapse_merges_across_an_interleaving_established_row() {
        let mut est = entry(10, 3000, "127.0.0.1");
        est.state = Some(TcpState::Established);
        est.remote_addr = Some("127.0.0.1".into());
        est.remote_port = 55000;

        let v = collapse(vec![
            entry(10, 3000, "127.0.0.1"),
            est,
            entry(10, 3000, "::1"),
        ]);
        assert_eq!(v.len(), 2, "两条 LISTEN 应合并为一条，另加那条 ESTABLISHED: {v:?}");
        let listen = v.iter().find(|e| e.state == Some(TcpState::Listen)).unwrap();
        assert_eq!(listen.local_addr, "127.0.0.1,::1");
    }

    #[test]
    fn collapse_dedups_identical_rows_separated_by_another() {
        let mut est = entry(10, 3000, "127.0.0.1");
        est.state = Some(TcpState::Established);
        est.remote_addr = Some("10.0.0.1".into());

        let v = collapse(vec![
            entry(10, 3000, "*"),
            est,
            entry(10, 3000, "*"),
        ]);
        assert_eq!(v.len(), 2, "两条完全相同的 LISTEN 应去重: {v:?}");
    }

    #[test]
    fn ipv6_gets_brackets_before_the_port() {
        // `::1:8080` 自身是一个合法的 IPv6 地址字面量，不加方括号会导致端口信息混淆。
        assert_eq!(addr_port("::1", 8080), "[::1]:8080");
        assert_eq!(addr_port("127.0.0.1", 8080), "127.0.0.1:8080");
        assert_eq!(addr_port("*", 80), "*:80");
        // 包含多个地址的组合字符串也需要用方括号包裹。
        assert_eq!(addr_port("127.0.0.1,::1", 80), "[127.0.0.1,::1]:80");
    }

    #[test]
    fn detail_brackets_ipv6_address() {
        let mut e = entry(1, 8080, "::1");
        e.remote_addr = Some("::2".into());
        e.remote_port = 999;
        let out = detail(8080, &[e], Style::plain());
        assert!(out.contains("[::1]:8080"), "{out}");
        assert!(out.contains("[::2]:999"), "{out}");
    }

    #[test]
    fn collapse_keeps_distinct_processes_apart() {
        let v = collapse(vec![entry(10, 3000, "*"), entry(11, 3000, "*")]);
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn collapse_sorts_by_port() {
        let v = collapse(vec![entry(1, 8080, "*"), entry(2, 80, "*")]);
        assert_eq!(v[0].local_port, 80);
        assert_eq!(v[1].local_port, 8080);
    }

    #[test]
    fn json_escapes_quotes_and_control_chars() {
        let mut e = entry(1, 80, "*");
        e.cmdline = Some("say \"hi\"\n\tbye".into());
        let j = json(&[e]);
        assert!(j.contains(r#""command":"say \"hi\"\n\tbye""#), "{j}");
    }

    #[test]
    fn json_emits_null_not_empty_string_for_missing_fields() {
        let mut e = entry(1, 80, "*");
        e.exe = None;
        e.cmdline = None;
        let j = json(&[e]);
        assert!(j.contains(r#""exe":null"#));
        assert!(j.contains(r#""command":null"#));
    }
}
