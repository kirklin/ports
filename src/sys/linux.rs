//! Linux 平台实现：解析 `/proc/net/{tcp,tcp6,udp,udp6}` 获取 socket inode，
//! 然后遍历 `/proc/<pid>/fd` 下的符号链接（例如 `socket:[12345]`），将 inode 映射回对应的进程。
//!
//! 该实现逻辑类似于 ss 或 netstat 工具。
//! 需要注意，`/proc/net/*` 中的 IP 地址按 32 位字的主机字节序以十六进制表示，并非直观的 IP 字符串，
//! 解析时必须特别处理，否则可能会将 127.0.0.1 错误解析为 1.0.0.127。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::model::{Entry, Proto, Scan, TcpState};

/// `/proc/net/*` 文件中的单行记录。
struct RawSock {
    proto: Proto,
    local_addr: String,
    local_port: u16,
    remote_addr: Option<String>,
    remote_port: u16,
    state: Option<TcpState>,
    inode: u64,
}

struct ProcMeta {
    name: String,
    exe: Option<String>,
    cmdline: Option<String>,
    uid: u32,
    ppid: i32,
    start_time: u64,
}

pub fn scan() -> io::Result<Scan> {
    let mut socks = Vec::new();
    for (path, proto, v6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
    ] {
        // 如果内核未编译特定协议模块导致文件不存在，则直接跳过，不抛出异常。
        if let Ok(text) = fs::read_to_string(path) {
            parse_net(&text, proto, v6, &mut socks);
        }
    }
    if socks.is_empty() && !Path::new("/proc/net/tcp").exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "/proc/net/tcp 不存在，这个系统看起来没挂载 procfs",
        ));
    }

    let wanted: HashSet<u64> = socks.iter().map(|s| s.inode).collect();
    let (inode_pid, skipped) = map_inodes_to_pids(&wanted);

    let btime = boot_time();
    let hz = clock_ticks();
    let mut meta_cache: HashMap<i32, Option<ProcMeta>> = HashMap::new();
    let mut user_cache: HashMap<u32, String> = HashMap::new();
    let mut entries = Vec::new();

    for s in socks {
        if s.local_port == 0 {
            continue;
        }
        // 同一个 socket 可能会被多个进程持有。例如在 fork 之后，子进程会继承监听描述符。
        // 在类似 nginx / gunicorn / php-fpm 等采用 master-worker 架构的服务中，
        // 相同的 inode 会存在于多个进程的 fd 目录中。为了避免输出结果的不确定性，
        // 我们需要为每个持有该 socket 的进程生成一条独立的记录。
        let Some(pids) = inode_pid.get(&s.inode) else {
            continue; // 未找到对应的进程（通常是因为权限不足，无法读取目标进程的 `/proc/<pid>/fd`）
        };
        for &pid in pids {
            let meta = meta_cache
                .entry(pid)
                .or_insert_with(|| proc_meta(pid, btime, hz));
            let Some(meta) = meta else { continue };

            let user = user_cache
                .entry(meta.uid)
                .or_insert_with(|| username(meta.uid))
                .clone();

            entries.push(Entry {
                proto: s.proto,
                state: s.state,
                local_addr: s.local_addr.clone(),
                local_port: s.local_port,
                remote_addr: s.remote_addr.clone(),
                remote_port: s.remote_port,
                pid,
                proc_name: meta.name.clone(),
                exe: meta.exe.clone(),
                cmdline: meta.cmdline.clone(),
                user,
                uid: meta.uid,
                ppid: meta.ppid,
                start_time: meta.start_time,
            });
        }
    }

    Ok(Scan { entries, skipped })
}

fn parse_net(text: &str, proto: Proto, v6: bool, out: &mut Vec<RawSock>) {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        if f.len() < 10 {
            continue;
        }
        let Some((la, lp)) = split_addr(f[1], v6) else { continue };
        let Some((ra, rp)) = split_addr(f[2], v6) else { continue };
        let Ok(st) = u8::from_str_radix(f[3], 16) else { continue };
        let Ok(inode) = f[9].parse::<u64>() else { continue };

        out.push(RawSock {
            proto,
            local_addr: la,
            local_port: lp,
            remote_addr: if rp != 0 { Some(ra) } else { None },
            remote_port: rp,
            // 对于 UDP，系统文件中对应的状态字段表示 socket 状态而非 TCP 状态，此处不进行解析。
            state: match proto {
                Proto::Tcp => Some(tcp_state(st)),
                Proto::Udp => None,
            },
            inode,
        });
    }
}

/// `0100007F:1F90` → ("127.0.0.1", 8080)
fn split_addr(s: &str, v6: bool) -> Option<(String, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let addr = if v6 { hex_v6(a)? } else { hex_v4(a)? };
    Some((addr, port))
}

/// `/proc/net/*` 中的十六进制 IP 地址是按主机字节序排列的 32 位整数。
/// 必须使用 `to_ne_bytes` 将其转换为字节数组。如果在系统为大端序（如 s390x）的 Linux 上
/// 错误地使用 `to_le_bytes`，会导致 127.0.0.1 被误读为 1.0.0.127。
fn hex_v4(s: &str) -> Option<String> {
    if s.len() != 8 {
        return None;
    }
    let w = u32::from_str_radix(s, 16).ok()?;
    let b = w.to_ne_bytes();
    let a = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    Some(if a.is_unspecified() { "*".into() } else { a.to_string() })
}

fn hex_v6(s: &str) -> Option<String> {
    // IP 字符串长度是按字节计算的。虽然 procfs 的输出理论上保证为纯 ASCII，
    // 但为防止外部输入存在非 ASCII 字符导致通过字节切片时产生 panic，此处先进行校验。
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&s[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    let a = Ipv6Addr::from(bytes);
    Some(match a.to_ipv4_mapped() {
        Some(v4) if v4.is_unspecified() => "*".into(),
        Some(v4) => v4.to_string(),
        None if a.is_unspecified() => "*".into(),
        None => a.to_string(),
    })
}

/// 查找持有 `wanted` 中目标 inode 的所有进程 PID。
/// 返回结果包含一个映射 `inode -> Vec<PID>`，以及因权限不足而跳过的进程数量。
///
/// 值使用 Vec 而非单个 PID，是因为多进程服务（如父子进程）可能会共享同一个 socket，
/// 如果直接覆盖会导致丢失部分进程信息。
fn map_inodes_to_pids(wanted: &HashSet<u64>) -> (HashMap<u64, Vec<i32>>, usize) {
    let mut map: HashMap<u64, Vec<i32>> = HashMap::new();
    let mut skipped = 0usize;

    let Ok(rd) = fs::read_dir("/proc") else {
        return (map, 0);
    };
    for ent in rd.flatten() {
        let Ok(pid) = ent.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            skipped += 1;
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else { continue };
            let t = target.to_string_lossy();
            // 链接目标格式示例：socket:[12345]
            let Some(rest) = t.strip_prefix("socket:[") else { continue };
            let Some(num) = rest.strip_suffix(']') else { continue };
            let Ok(inode) = num.parse::<u64>() else { continue };
            if wanted.contains(&inode) {
                let holders = map.entry(inode).or_default();
                // 同一进程可能由于调用过 dup 而拥有多个指向同一个 socket 的 fd，在此仅记录一次。
                if !holders.contains(&pid) {
                    holders.push(pid);
                }
            }
        }
    }
    // readdir 返回的文件顺序是不确定的，排序以保证输出结果的稳定性和可复现性。
    for v in map.values_mut() {
        v.sort_unstable();
    }
    (map, skipped)
}

fn proc_meta(pid: i32, btime: u64, hz: u64) -> Option<ProcMeta> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // 进程状态文件 `/proc/[pid]/stat` 中的第二个字段是用括号括起来的进程名。
    // 由于进程名本身可能包含空格甚至右括号，因此需从最后一个 ')' 之后进行分割。
    let tail = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = tail.split_whitespace().collect();
    // 分割后，数组的第 0 项实际上对应 stat 文件格式中的第 3 个字段（进程状态），因此偏移量需减 3。
    let ppid = f.get(1)?.parse::<i32>().ok()?;
    let starttime = f.get(19)?.parse::<u64>().ok()?;

    let uid = fs::metadata(format!("/proc/{pid}")).ok()?.uid();
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    // `/proc/[pid]/cmdline` 中的参数以 `\0` 分隔，内核线程的 cmdline 为空。
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok().and_then(|b| {
        let s = b
            .split(|&c| c == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let s = s.trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    });

    let name = comm
        .or_else(|| exe.as_deref().and_then(|e| e.rsplit('/').next()).map(String::from))
        .unwrap_or_else(|| "?".into());

    Some(ProcMeta {
        name,
        exe,
        cmdline,
        uid,
        ppid,
        // stat 文件中的 starttime 是“系统启动以来的时钟滴答数”，加上系统启动时间转换为 Unix 时间戳。
        start_time: btime + starttime / hz.max(1),
    })
}

fn boot_time() -> u64 {
    fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("btime "))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn clock_ticks() -> u64 {
    // 安全性：sysconf 调用仅用于查询系统常量。
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

fn username(uid: u32) -> String {
    // 安全性：getpwuid 返回指向静态缓冲区的指针，获取后立即复制数据。
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return uid.to_string();
    }
    let name = unsafe { (*pw).pw_name };
    if name.is_null() {
        return uid.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

fn tcp_state(v: u8) -> TcpState {
    // Linux 内核中定义的 TCP 状态数值与 macOS 的 TSI_S_* 枚举不同，在此进行专门的映射转换。
    match v {
        0x01 => TcpState::Established,
        0x02 => TcpState::SynSent,
        0x03 => TcpState::SynRecv,
        0x04 => TcpState::FinWait1,
        0x05 => TcpState::FinWait2,
        0x06 => TcpState::TimeWait,
        0x07 => TcpState::Closed,
        0x08 => TcpState::CloseWait,
        0x09 => TcpState::LastAck,
        0x0A => TcpState::Listen,
        0x0B => TcpState::Closing,
        _ => TcpState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_v4_reverses_word_byte_order() {
        // 0100007F 是 127.0.0.1 在小端架构上以 32 位字输出的十六进制表示。
        assert_eq!(hex_v4("0100007F").unwrap(), "127.0.0.1");
        assert_eq!(hex_v4("00000000").unwrap(), "*");
        assert_eq!(hex_v4("0101A8C0").unwrap(), "192.168.1.1");
        assert!(hex_v4("XY").is_none());
    }

    #[test]
    fn hex_v6_handles_mapped_and_unspecified() {
        assert_eq!(hex_v6(&"0".repeat(32)).unwrap(), "*");
        // 处理 IPv4 映射的 IPv6 地址（如 ::ffff:127.0.0.1）。由于内核输出时按照逐个 32 位字使用主机字节序打印，
        // 在小端机器上，包含 0xffff 的部分将被表示为 FFFF0000 而非 0000FFFF，
        // 若解析顺序错误，会导致地址被错误解析为 ::ffff:0:7f00:1。
        assert_eq!(
            hex_v6("0000000000000000FFFF00000100007F").unwrap(),
            "127.0.0.1"
        );
        // 纯 IPv6 地址的解析测试（如 ::1）。
        assert_eq!(
            hex_v6("00000000000000000000000001000000").unwrap(),
            "::1"
        );
        assert!(hex_v6("00").is_none());
    }

    #[test]
    fn split_addr_parses_hex_port() {
        let (a, p) = split_addr("0100007F:1F90", false).unwrap();
        assert_eq!((a.as_str(), p), ("127.0.0.1", 8080));
        let (a, p) = split_addr("00000000:0050", false).unwrap();
        assert_eq!((a.as_str(), p), ("*", 80));
    }

    #[test]
    fn parse_net_reads_a_real_proc_line() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000 100 0 0 10 0
   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 54322 1 0000 100 0 0 10 0
";
        let mut v = Vec::new();
        parse_net(text, Proto::Tcp, false, &mut v);
        assert_eq!(v.len(), 2);

        assert_eq!(v[0].local_port, 8080);
        assert_eq!(v[0].local_addr, "127.0.0.1");
        assert_eq!(v[0].state, Some(TcpState::Listen));
        assert_eq!(v[0].inode, 54321);
        assert!(v[0].remote_addr.is_none(), "LISTEN 不该有对端");

        assert_eq!(v[1].state, Some(TcpState::Established));
        assert_eq!(v[1].remote_port, 8080);
        assert_eq!(v[1].remote_addr.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn parse_net_skips_malformed_lines() {
        let text = "header\nbroken line\n   0: zz:zz 00000000:0000 0A x x x x x 1\n";
        let mut v = Vec::new();
        parse_net(text, Proto::Tcp, false, &mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn udp_rows_carry_no_tcp_state() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 99 2 0 0
";
        let mut v = Vec::new();
        parse_net(text, Proto::Udp, false, &mut v);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].local_port, 5353);
        assert_eq!(v[0].state, None);
    }
}
