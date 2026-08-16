//! 终端显示格式化工具集合：处理时间、字符串截断、宽度计算及 ANSI 颜色控制。

use std::os::raw::c_int;

/// 将秒数转换为易读的时间格式（最大保留两个单位，例如 `3d 5h`）。
pub fn duration(secs: u64) -> String {
    const M: u64 = 60;
    const H: u64 = 60 * M;
    const D: u64 = 24 * H;
    match secs {
        s if s < M => format!("{s}s"),
        s if s < H => {
            let (m, r) = (s / M, s % M);
            if r == 0 { format!("{m}m") } else { format!("{m}m {r}s") }
        }
        s if s < D => {
            let (h, r) = (s / H, (s % H) / M);
            if r == 0 { format!("{h}h") } else { format!("{h}h {r}m") }
        }
        s => {
            let (d, r) = (s / D, (s % D) / H);
            if r == 0 { format!("{d}d") } else { format!("{d}d {r}h") }
        }
    }
}

/// 将 Unix 时间戳转换为本地时间的 `YYYY-MM-DD HH:MM:SS` 格式。
/// 调用 libc 的 localtime_r 实现，避免引入第三方时间库。
pub fn local_time(unix: u64) -> String {
    let t = unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // 安全性：localtime_r 将结果写入调用者提供的 tm 结构，避免了使用静态缓冲区的并发问题。
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return unix.to_string();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 计算字符串在终端中的显示宽度。将 CJK 全角字符计为两列，以保证表格对齐。
pub fn width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    let c = c as u32;
    // 判断字符是否属于东亚宽字符（East Asian Wide / Fullwidth）的主要区间。
    let wide = (0x1100..=0x115F).contains(&c)
        || (0x2E80..=0x303E).contains(&c)
        || (0x3041..=0x33FF).contains(&c)
        || (0x3400..=0x4DBF).contains(&c)
        || (0x4E00..=0x9FFF).contains(&c)
        || (0xA000..=0xA4CF).contains(&c)
        || (0xAC00..=0xD7A3).contains(&c)
        || (0xF900..=0xFAFF).contains(&c)
        || (0xFE30..=0xFE6F).contains(&c)
        || (0xFF00..=0xFF60).contains(&c)
        || (0xFFE0..=0xFFE6).contains(&c)
        || (0x1F300..=0x1F9FF).contains(&c)
        || (0x20000..=0x3FFFD).contains(&c);
    if wide { 2 } else { 1 }
}

/// 对字符串进行清理，将控制字符替换为空格并合并连续的空白字符。
///
/// 这样做的目的：
/// 1. 过滤命令行参数中可能存在的换行符，防止表格排版被破坏。
/// 2. 移除潜在的 ANSI 转义序列，防止被监控进程通过构造特殊的命令行参数控制终端显示。
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        let ctrl = (c as u32) < 0x20 || c == '\x7f' || matches!(c as u32, 0x80..=0x9f);
        let c = if ctrl || c == ' ' { ' ' } else { c };
        if c == ' ' {
            if !prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// 将字符串截断至指定显示宽度，超出部分以 `…` 结尾。
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > max - 1 {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// 将长字符串按指定的显示宽度换行，优先在空格处断开；若单个连续字符串超长则强制截断。
/// 为了防止恶意超长参数刷屏，超过 `max_lines` 指定的行数后将截断。
pub fn wrap(s: &str, max_width: usize, max_lines: usize) -> Vec<String> {
    let max_width = max_width.max(8);
    let mut lines = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0;

    for token in s.split(' ').filter(|t| !t.is_empty()) {
        let tw = width(token);
        if cur_w > 0 && cur_w + 1 + tw > max_width {
            lines.push(std::mem::take(&mut cur));
            cur_w = 0;
            if lines.len() == max_lines {
                lines.push("…".to_string());
                return lines;
            }
        }
        if tw > max_width {
            // 强制切断超长的连续字符串（如没有空格的长路径）。
            for c in token.chars() {
                let cw = char_width(c);
                if cur_w + cw > max_width {
                    lines.push(std::mem::take(&mut cur));
                    cur_w = 0;
                    if lines.len() == max_lines {
                        lines.push("…".to_string());
                        return lines;
                    }
                }
                cur.push(c);
                cur_w += cw;
            }
        } else {
            if cur_w > 0 {
                cur.push(' ');
                cur_w += 1;
            }
            cur.push_str(token);
            cur_w += tw;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

pub fn pad(s: &str, to: usize) -> String {
    let w = width(s);
    if w >= to {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(to - w))
    }
}

/// 获取终端列数。当输出被重定向或无法获取时，默认返回 120 列。
pub fn term_width() -> usize {
    #[repr(C)]
    struct WinSize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    let mut ws = WinSize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // 安全性：TIOCGWINSZ 将终端大小写入调用者提供的 WinSize 结构。
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &raw mut ws) };
    if rc == 0 && ws.ws_col > 0 { ws.ws_col as usize } else { 120 }
}

pub fn is_tty(fd: c_int) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

// ---- 颜色控制 ----

#[derive(Clone, Copy)]
pub struct Style {
    on: bool,
}

impl Style {
    /// 检测是否应该启用彩色输出。遵循 NO_COLOR 约定，非 TTY 环境默认关闭。
    pub fn detect() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Style { on: !no_color && is_tty(libc::STDOUT_FILENO) }
    }

    pub fn plain() -> Self {
        Style { on: false }
    }

    fn wrap(self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }

    pub fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn cyan(self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn green(self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn red(self, s: &str) -> String {
        self.wrap("31", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_uses_at_most_two_units() {
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(60), "1m");
        assert_eq!(duration(75), "1m 15s");
        assert_eq!(duration(3600), "1h");
        assert_eq!(duration(3600 + 14 * 60), "1h 14m");
        assert_eq!(duration(86400), "1d");
        assert_eq!(duration(3 * 86400 + 5 * 3600), "3d 5h");
    }

    #[test]
    fn cjk_counts_as_two_columns() {
        assert_eq!(width("abc"), 3);
        assert_eq!(width("中文"), 4);
        assert_eq!(width("a中"), 3);
    }

    #[test]
    fn truncate_respects_display_width() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("abcdef", 4), "abc…");
        // 确保不会将全角字符截断在一半。
        assert_eq!(truncate("中文字", 4), "中…");
    }

    #[test]
    fn pad_aligns_by_display_width() {
        assert_eq!(pad("ab", 4), "ab  ");
        assert_eq!(pad("中", 4), "中  ");
        assert_eq!(pad("toolong", 3), "toolong");
    }

    #[test]
    fn wrap_breaks_at_spaces() {
        assert_eq!(wrap("short", 20, 5), vec!["short"]);
        assert_eq!(
            wrap("aaa bbb ccc ddd", 7, 5),
            vec!["aaa bbb", "ccc ddd"]
        );
        // 确保每一行的宽度都不会超过限制。
        for line in wrap("one two three four five six", 10, 9) {
            assert!(width(&line) <= 10, "超宽: {line:?}");
        }
    }

    #[test]
    fn wrap_hard_splits_tokens_longer_than_the_line() {
        // 长字符串（如无空格的路径）必须被强制截断，以防破坏布局。
        let long = "a".repeat(25);
        let lines = wrap(&long, 10, 9);
        assert!(lines.len() >= 3, "{lines:?}");
        for l in &lines {
            assert!(width(l) <= 10, "{l:?}");
        }
        assert_eq!(lines.concat(), long, "强制截断不应丢失字符");
    }

    #[test]
    fn wrap_stops_at_max_lines() {
        let lines = wrap("aa bb cc dd ee ff gg hh", 5, 2);
        assert_eq!(lines.len(), 3, "输出应包含两行正文及最后一行省略号: {lines:?}");
        assert_eq!(lines.last().unwrap(), "…");
    }

    #[test]
    fn wrap_handles_empty_input() {
        assert_eq!(wrap("", 10, 3), vec![""]);
    }

    #[test]
    fn sanitize_folds_newlines_and_collapses_runs() {
        assert_eq!(sanitize("python3 -c\nimport os\nx=1"), "python3 -c import os x=1");
        assert_eq!(sanitize("a\t\tb"), "a b");
        assert_eq!(sanitize("  lead and trail  "), "lead and trail");
        assert_eq!(sanitize("plain"), "plain");
    }

    #[test]
    fn sanitize_strips_terminal_escape_sequences() {
        // 监控工具必须清理转义序列，防止被监控进程注入恶意控制符。
        let evil = "node \x1b[2J\x1b[1;31mFAKE\x1b[0m server.js";
        let out = sanitize(evil);
        assert!(!out.contains('\x1b'), "未能清除转义字符: {out:?}");
        assert_eq!(out, "node [2J [1;31mFAKE [0m server.js");
        // 同时需要清理 C1 控制字符。
        assert!(!sanitize("a\u{9b}b").contains('\u{9b}'));
    }

    #[test]
    fn sanitize_keeps_cjk_intact() {
        assert_eq!(sanitize("123云盘 Helper"), "123云盘 Helper");
    }

    #[test]
    fn style_off_emits_no_escapes() {
        let s = Style::plain();
        assert_eq!(s.bold("x"), "x");
        assert_eq!(s.red("x"), "x");
    }
}
