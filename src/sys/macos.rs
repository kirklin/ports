//! macOS 平台实现：基于 libproc 和 sysctl 系统调用获取信息，不依赖外部的 lsof。
//!
//! 由于部分内核结构体未在标准库中公开，此处直接定义了与内核一致的内存布局。
//! 结构体的字段偏移量通过 C 语言探针（基于 `sys/proc_info.h` 的 offsetof/sizeof）获取。
//! 在单元测试中，使用 `offset_of!` 对所有字段的偏移进行严格断言，
//! 以确保布局完全正确，防止因为内存错位读取到无效数据。

use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_int, c_void};

use crate::model::{Entry, Proto, Scan, TcpState};

// ---- libproc 常量（定义于 sys/proc_info.h）----
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_IN: c_int = 1;
const SOCKINFO_TCP: c_int = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

unsafe extern "C" {
    fn proc_listpids(r#type: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

// ---- 内核结构体（布局说明见文件头注释）----

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32,      // 0  大端网络字节序
    insi_lport: i32,      // 4  大端网络字节序
    insi_gencnt: u64,     // 8
    insi_flags: u32,      // 16
    insi_flow: u32,       // 20
    insi_vflag: u8,       // 24
    insi_ip_ttl: u8,      // 25
    _rfu_1: u32,          // 28（26..28 字节为对齐填充）
    insi_faddr: [u8; 16], // 32  联合体：IPv4 地址存储在最后 4 个字节
    insi_laddr: [u8; 16], // 48
    _v4_v6: [u8; 16],     // 64..80  预留字段 (insi_v4 + insi_v6)，未使用
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo, // 0..80
    tcpsi_state: i32,      // 80
    _tcpsi_timer: [i32; 4],
    _tcpsi_mss: i32,
    _tcpsi_flags: u32,
    _rfu_1: u32,
    _tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    // soi_stat..soi_snd 等字段在本工具中未使用。声明为 [u64] 而非 [u8] 是为了
    // 强制结构体按 8 字节对齐，否则后续对 soi_proto 进行指针转换时会违反内存对齐要求。
    _head: [u64; 29],     // 0..232
    soi_kind: i32,        // 232
    _rfu_1: u32,          // 236
    soi_proto: [u64; 66], // 240..768  联合体的原始字节数据
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    _pfi: [u64; 3],  // proc_fileinfo，0..24
    psi: SocketInfo, // 24..792
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    _pbi_flags: u32,
    _pbi_status: u32,
    _pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    _pbi_gid: u32,
    _pbi_ruid: u32,
    _pbi_rgid: u32,
    _pbi_svuid: u32,
    _pbi_svgid: u32,
    _rfu_1: u32,
    _pbi_comm: [u8; 16],  // 48  最大被截断为 16 字节，实际显示使用下方 name 字段
    pbi_name: [u8; 32],   // 64
    _pbi_nfiles: u32,
    _pbi_pgid: u32,
    _pbi_pjobc: u32,
    _e_tdev: u32,
    _e_tpgid: u32,
    _pbi_nice: i32,
    pbi_start_tvsec: u64,  // 120
    _pbi_start_tvusec: u64,
}

/// 保存单个进程只需查询一次的元数据。
struct ProcMeta {
    name: String,
    exe: Option<String>,
    cmdline: Option<String>,
    uid: u32,
    ppid: i32,
    start_time: u64,
}

pub fn scan() -> io::Result<Scan> {
    let pids = list_pids()?;
    // KERN_ARGMAX 的值通常为 1MB。如果为每个进程都单独分配内存，在进程较多时
    // 会导致显著的内存分配开销，成为性能瓶颈。因此，这里复用同一块缓冲区。
    let mut argbuf = vec![0u8; kern_argmax()];

    let mut entries = Vec::new();
    let mut meta_cache: HashMap<i32, Option<ProcMeta>> = HashMap::new();
    let mut user_cache: HashMap<u32, String> = HashMap::new();
    let mut skipped = 0usize;

    for pid in pids {
        if pid <= 0 {
            continue;
        }
        let fds = match list_fds(pid) {
            Some(f) => f,
            None => {
                // 无法获取文件描述符列表，通常是因为权限不足（例如非 root 用户尝试查看其他用户的进程）。
                skipped += 1;
                continue;
            }
        };

        for fd in fds {
            if fd.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            let Some(sock) = socket_info(pid, fd.proc_fd) else {
                continue;
            };
            let (proto, state, ini) = match sock.psi.soi_kind {
                SOCKINFO_TCP => {
                    // 安全性：soi_kind == SOCKINFO_TCP 确保当前联合体为 tcp_sockinfo；
                    // soi_proto 定义为 [u64]，已保证 8 字节对齐。
                    let tcp: TcpSockInfo =
                        unsafe { std::ptr::read(sock.psi.soi_proto.as_ptr().cast()) };
                    (Proto::Tcp, Some(tcp_state(tcp.tcpsi_state)), tcp.tcpsi_ini)
                }
                SOCKINFO_IN => {
                    // 安全性：同上，此时联合体结构为 in_sockinfo。
                    let ini: InSockInfo =
                        unsafe { std::ptr::read(sock.psi.soi_proto.as_ptr().cast()) };
                    (Proto::Udp, None, ini)
                }
                _ => continue, // 忽略 Unix 域套接字及内核控制套接字等非网络端口
            };

            let lport = ntohs(ini.insi_lport);
            if lport == 0 {
                continue;
            }

            let meta = meta_cache
                .entry(pid)
                .or_insert_with(|| proc_meta(pid, &mut argbuf));
            let Some(meta) = meta else { continue };

            let user = user_cache
                .entry(meta.uid)
                .or_insert_with(|| username(meta.uid))
                .clone();

            let (local_addr, remote_addr) = addrs(&ini);
            entries.push(Entry {
                proto,
                state,
                local_addr,
                local_port: lport,
                remote_addr,
                remote_port: ntohs(ini.insi_fport),
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

fn list_pids() -> io::Result<Vec<i32>> {
    // 首先查询所需的缓冲区大小，然后在此基础上增加 32 个 PID 的冗余，以应对查询期间新启动的进程。
    let need = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(io::Error::last_os_error());
    }
    let cap = need as usize / mem::size_of::<i32>() + 32;
    let mut buf = vec![0i32; cap];
    let got = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            buf.as_mut_ptr().cast(),
            (cap * mem::size_of::<i32>()) as c_int,
        )
    };
    if got <= 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(got as usize / mem::size_of::<i32>());
    Ok(buf)
}

fn list_fds(pid: i32) -> Option<Vec<ProcFdInfo>> {
    let need = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return None;
    }
    let cap = need as usize / mem::size_of::<ProcFdInfo>() + 16;
    let mut buf: Vec<ProcFdInfo> = Vec::with_capacity(cap);
    let got = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            (cap * mem::size_of::<ProcFdInfo>()) as c_int,
        )
    };
    if got <= 0 {
        return None;
    }
    // 限制读取的元素数量上限。必须确保不会读取超出分配容量的数据，以防引发未定义行为 (UB)。
    let n = (got as usize / mem::size_of::<ProcFdInfo>()).min(cap);
    // 安全性：内核最多写入 cap 个元素，n 不会超过 cap，且缓冲区的这些元素已被正确初始化。
    unsafe { buf.set_len(n) };
    Some(buf)
}

fn socket_info(pid: i32, fd: i32) -> Option<SocketFdInfo> {
    let mut sfi = MaybeUninit::<SocketFdInfo>::uninit();
    let size = mem::size_of::<SocketFdInfo>() as c_int;
    let got = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            sfi.as_mut_ptr().cast(),
            size,
        )
    };
    // 内核应当填满整个结构体。如果读取的字节数不足，说明结构体版本可能不匹配，丢弃该数据以防错误解析。
    if got != size {
        return None;
    }
    // 安全性：已验证内核写入了完整的 size 个字节。
    Some(unsafe { sfi.assume_init() })
}

fn proc_meta(pid: i32, argbuf: &mut [u8]) -> Option<ProcMeta> {
    let mut bsd = MaybeUninit::<ProcBsdInfo>::uninit();
    let size = mem::size_of::<ProcBsdInfo>() as c_int;
    let got =
        unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, bsd.as_mut_ptr().cast(), size) };
    if got != size {
        return None;
    }
    // 安全性：已验证内核写入了完整的 size 个字节。
    let bsd = unsafe { bsd.assume_init() };

    let name = cstr_field(&bsd.pbi_name);
    let exe = proc_path(pid);
    let cmdline = proc_cmdline(pid, argbuf);

    Some(ProcMeta {
        name: if name.is_empty() {
            exe.as_deref()
                .and_then(|p| p.rsplit('/').next())
                .unwrap_or("?")
                .to_string()
        } else {
            name
        },
        exe,
        cmdline,
        uid: bsd.pbi_uid,
        ppid: bsd.pbi_ppid as i32,
        start_time: bsd.pbi_start_tvsec,
    })
}

fn proc_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe {
        proc_pidpath(pid, buf.as_mut_ptr().cast(), PROC_PIDPATHINFO_MAXSIZE)
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// 获取进程完整的命令行参数。KERN_PROCARGS2 的内存布局为：
/// `argc(u32) | exec_path\0 | 零个或多个填充的\0 | argv[0]\0 ... argv[argc-1]\0 | env...`
fn proc_cmdline(pid: i32, buf: &mut [u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len < 4 {
        return None;
    }
    let buf = &buf[..len];

    let argc = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let rest = &buf[4..];

    // 跳过可执行文件路径（exec_path）及随后的填充零字节。
    let path_end = rest.iter().position(|&b| b == 0)?;
    let mut p = path_end;
    while p < rest.len() && rest[p] == 0 {
        p += 1;
    }

    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if p >= rest.len() {
            break;
        }
        let end = rest[p..].iter().position(|&b| b == 0).map(|i| p + i)?;
        args.push(String::from_utf8_lossy(&rest[p..end]).into_owned());
        p = end + 1;
    }
    // 部分程序（如 next-server）可能通过覆写 argv 来修改进程显示标题，
    // 这可能导致末尾出现多余的空格，需要统一进行去除。
    let joined = args.join(" ").trim().to_string();
    if joined.is_empty() { None } else { Some(joined) }
}

fn kern_argmax() -> usize {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut val: c_int = 0;
    let mut len = mem::size_of::<c_int>();
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut val).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || val <= 0 { 0 } else { val as usize }
}

fn username(uid: u32) -> String {
    // 安全性：getpwuid 返回的指针指向静态缓冲区，必须在下一次相关调用前将其数据复制出来。
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return uid.to_string();
    }
    let name = unsafe { (*pw).pw_name };
    if name.is_null() {
        return uid.to_string();
    }
    unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

/// 从 in_sockinfo 结构中解析出本地和远端的地址字符串。
fn addrs(ini: &InSockInfo) -> (String, Option<String>) {
    let v6 = ini.insi_vflag & INI_IPV6 != 0 && ini.insi_vflag & INI_IPV4 == 0;
    let local = fmt_addr(&ini.insi_laddr, v6);
    let remote = if ini.insi_fport != 0 {
        Some(fmt_addr(&ini.insi_faddr, v6))
    } else {
        None
    };
    (local, remote)
}

fn fmt_addr(raw: &[u8; 16], v6: bool) -> String {
    if v6 {
        let a = Ipv6Addr::from(*raw);
        // 对于形如 ::ffff:a.b.c.d 的 IPv4 映射地址，统一按 IPv4 格式展示（行为与 lsof 一致）。
        match a.to_ipv4_mapped() {
            Some(v4) => fmt_v4(v4),
            None if a.is_unspecified() => "*".to_string(),
            None => a.to_string(),
        }
    } else {
        // 对应联合体 in4in6_addr：前 12 字节为填充（pad），IPv4 地址存储在最后 4 字节。
        let a = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        fmt_v4(a)
    }
}

fn fmt_v4(a: Ipv4Addr) -> String {
    if a.is_unspecified() {
        "*".to_string()
    } else {
        a.to_string()
    }
}

/// `insi_lport` 为网络字节序，取其低 16 位并转换为主机字节序。
fn ntohs(v: i32) -> u16 {
    u16::from_be((v & 0xffff) as u16)
}

fn tcp_state(v: i32) -> TcpState {
    match v {
        0 => TcpState::Closed,
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynRecv,
        4 => TcpState::Established,
        5 => TcpState::CloseWait,
        6 => TcpState::FinWait1,
        7 => TcpState::Closing,
        8 => TcpState::LastAck,
        9 => TcpState::FinWait2,
        10 => TcpState::TimeWait,
        _ => TcpState::Unknown,
    }
}

fn cstr_field(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    /// 这些偏移量数字是通过 C 探针在 macOS SDK 环境中运行 offsetof/sizeof 得到的实际值。
    /// 一旦内存布局发生变化（例如由于系统更新），错误解析会导致端口信息混乱而未必会崩溃，因此必须通过测试严格锁定。
    #[test]
    fn struct_layout_matches_kernel() {
        // 这一结构体在热路径中被直接按字段名访问（如 fd.proc_fdtype 和 fd.proc_fd）。
        // 如果仅断言总体大小，即使这两个字段位置颠倒测试也能通过，但这会导致以 fdtype 作为 fd 进行后续调用。
        assert_eq!(mem::size_of::<ProcFdInfo>(), 8);
        assert_eq!(offset_of!(ProcFdInfo, proc_fd), 0);
        assert_eq!(offset_of!(ProcFdInfo, proc_fdtype), 4);

        assert_eq!(mem::size_of::<InSockInfo>(), 80);
        assert_eq!(offset_of!(InSockInfo, insi_fport), 0);
        assert_eq!(offset_of!(InSockInfo, insi_lport), 4);
        assert_eq!(offset_of!(InSockInfo, insi_gencnt), 8);
        assert_eq!(offset_of!(InSockInfo, insi_flags), 16);
        assert_eq!(offset_of!(InSockInfo, insi_vflag), 24);
        assert_eq!(offset_of!(InSockInfo, insi_ip_ttl), 25);
        assert_eq!(offset_of!(InSockInfo, insi_faddr), 32);
        assert_eq!(offset_of!(InSockInfo, insi_laddr), 48);

        assert_eq!(mem::size_of::<TcpSockInfo>(), 120);
        assert_eq!(offset_of!(TcpSockInfo, tcpsi_ini), 0);
        assert_eq!(offset_of!(TcpSockInfo, tcpsi_state), 80);

        assert_eq!(mem::size_of::<SocketInfo>(), 768);
        assert_eq!(mem::align_of::<SocketInfo>(), 8);
        assert_eq!(offset_of!(SocketInfo, soi_kind), 232);
        assert_eq!(offset_of!(SocketInfo, soi_proto), 240);

        assert_eq!(mem::size_of::<SocketFdInfo>(), 792);
        assert_eq!(offset_of!(SocketFdInfo, psi), 24);

        assert_eq!(mem::size_of::<ProcBsdInfo>(), 136);
        assert_eq!(offset_of!(ProcBsdInfo, pbi_pid), 12);
        assert_eq!(offset_of!(ProcBsdInfo, pbi_ppid), 16);
        assert_eq!(offset_of!(ProcBsdInfo, pbi_uid), 20);
        assert_eq!(offset_of!(ProcBsdInfo, _pbi_comm), 48);
        assert_eq!(offset_of!(ProcBsdInfo, pbi_name), 64);
        assert_eq!(offset_of!(ProcBsdInfo, pbi_start_tvsec), 120);
    }

    #[test]
    fn ntohs_reads_network_order() {
        // 端口 3000 (0x0BB8) 在网络字节序下存放为 0xB80B。
        assert_eq!(ntohs(0xB80B), 3000);
        assert_eq!(ntohs(0), 0);
    }

    #[test]
    fn v4_addr_lives_in_last_four_bytes() {
        let mut raw = [0u8; 16];
        raw[12..].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(fmt_addr(&raw, false), "127.0.0.1");
        assert_eq!(fmt_addr(&[0u8; 16], false), "*");
    }

    #[test]
    fn v4_mapped_v6_renders_as_v4() {
        let mut raw = [0u8; 16];
        raw[10] = 0xff;
        raw[11] = 0xff;
        raw[12..].copy_from_slice(&[10, 0, 0, 7]);
        assert_eq!(fmt_addr(&raw, true), "10.0.0.7");
        assert_eq!(fmt_addr(&[0u8; 16], true), "*");
    }
}
