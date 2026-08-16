//! 跨平台数据模型。将 macOS (libproc) 和 Linux (/proc) 的底层数据结构统一抽象。

use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// TCP 状态枚举。UDP 协议无状态，此时值为 `None`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRecv,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
    Unknown,
}

impl TcpState {
    /// 将各个平台的内部状态值映射为统一的字符串表示。
    /// （注：macOS 的 `TSI_S_*` 与 Linux `/proc/net/tcp` 的状态数值不同，由底层的 sys 模块完成解析）
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::Established => "ESTABLISHED",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Unknown => "UNKNOWN",
        }
    }
}

/// 表示一条网络连接或监听记录，包含与之关联的进程信息。
#[derive(Clone, Debug)]
pub struct Entry {
    pub proto: Proto,
    pub state: Option<TcpState>,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: u16,
    pub pid: i32,
    pub proc_name: String,
    /// 可执行文件的绝对路径。如果因权限不足或进程已退出导致无法获取，则为 None。
    pub exe: Option<String>,
    /// 进程的完整命令行参数。获取失败时为 None。
    pub cmdline: Option<String>,
    pub user: String,
    pub uid: u32,
    pub ppid: i32,
    /// 进程启动的 Unix 时间戳（以秒为单位）。
    pub start_time: u64,
}

impl Entry {
    pub fn is_listening(&self) -> bool {
        match self.proto {
            // UDP 协议没有 LISTEN 状态，只要绑定了本地端口即视为处于监听状态。
            Proto::Udp => true,
            Proto::Tcp => self.state == Some(TcpState::Listen),
        }
    }

    /// 返回用于展示的进程信息：优先级依次为完整命令行 > 可执行文件路径 > 进程名。
    pub fn display_command(&self) -> &str {
        self.cmdline
            .as_deref()
            .or(self.exe.as_deref())
            .unwrap_or(&self.proc_name)
    }
}

/// 全局端口扫描结果。
/// `skipped` 字段记录了因权限不足而跳过的进程数量，用于在输出中提示用户可能存在未显示的信息。
pub struct Scan {
    pub entries: Vec<Entry>,
    pub skipped: usize,
}
