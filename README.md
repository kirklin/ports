# ports

用于查看本地端口占用情况的命令行工具。支持 macOS 和 Linux，单二进制文件，除 libc 外无其他依赖。

```
$ ports 3000
3000 tcp LISTEN

  PID        43421
  Process    node
  User       kirk (502)
  Started    2026-08-05 02:22:13  (10d 21h ago)
  Address    *:3000
  Binary     /Users/kirk/.nvm/versions/node/v22.18.0/bin/node
  Command    next-server (v16.2.10)
  Parent     43415

  kill it:  ports 3000 -k
```

相比于原生的 `lsof -nP -iTCP:3000 -sTCP:LISTEN` 命令，`ports` 提供了更加全面和易读的信息。不仅包含了 PID，还直接展示了进程名称、运行时间、完整命令等信息，无需配合 `ps` 命令二次查询。

## 安装

```bash
cargo install --git https://github.com/kirklin/ports
```

## 使用方法

```bash
ports                 # 列出所有监听中的端口
ports 3000            # 查询 3000 端口被哪个进程占用
ports 3000 8080       # 同时查询多个端口
ports 3000-3010       # 查询端口范围
ports -a              # 包含已建立的连接 (ESTABLISHED)
ports 3000 -k         # 终止占用该端口的进程（会有交互式确认）
ports 3000 -k -9      # 强制终止进程 (SIGKILL)
ports --json | jq     # 以 JSON 格式输出，方便脚本处理
```

不带具体端口参数时，默认以表格形式展示：

```
PORT   PROTO  PID    PROCESS             USER  UPTIME   ADDRESS    COMMAND
3000   tcp    43421  node                kirk  10d 21h  *          next-server (v16.2.10)
5432   tcp    1065   com.docker.backend  kirk  10d 22h  *          /Applications/Docker.app/Cont…
6379   tcp    1065   com.docker.backend  kirk  10d 22h  *          /Applications/Docker.app/Cont…
9277   tcp    585    stable              kirk  10d 22h  127.0.0.1  /Applications/Warp.app/Conten…
```

当端口未被占用时，程序的退出码为 1，这使得它可以很方便地用于 Shell 脚本中的条件判断：

```bash
ports 3000 || npm run dev
```

对于通过 fork 产生的多进程服务（如 nginx、gunicorn、php-fpm 等），多个进程会共享同一个监听 socket。此时，`ports` 会将 master 和所有 worker 进程一并列出（与 `ss -ltnp` 的行为一致），使用 `-k` 参数也会对这些进程逐一发送信号。

## 实现细节

本工具不依赖外部命令（如 `lsof` 或 `netstat`），而是直接通过系统调用获取内核信息。

- **macOS**：通过 `libproc` 接口获取信息。使用 `proc_listpids` 获取进程列表，`proc_pidinfo(PROC_PIDLISTFDS)` 获取文件描述符，随后仅对 socket 类型的 fd 调用 `proc_pidfdinfo`，进程参数通过 `sysctl(KERN_PROCARGS2)` 获取。内核结构体的布局在代码中进行了精确的偏移量映射，并通过 C 探针在测试中进行验证以确保兼容性。
- **Linux**：通过解析 `procfs` 获取信息。首先读取 `/proc/net/{tcp,tcp6,udp,udp6}` 获取 socket 的 inode，然后遍历 `/proc/<pid>/fd` 目录下的 symlink 将 inode 映射回具体进程。

得益于直接和内核交互，且避免了 `lsof` 那样遍历所有进程的每一个 fd，`ports` 在性能上优于传统工具。在 macOS 上的基准测试中（65 条监听记录，运行 30 次取平均值）：

| 工具 | 耗时 |
|---|---|
| `ports` | ~7 ms |
| `lsof -nP -iTCP -sTCP:LISTEN` | ~77 ms |

编译后的二进制文件约 345 KB，除了 libc 之外没有其他依赖。

## 准确性说明

- 在 macOS 上，测试了与 `lsof` 输出的 56 个 TCP 监听端口进行对比，`(端口, PID)` 的映射关系完全一致。
- 在 Linux 上，与 `ss -ltnp` 进行对比，IPv4 和 IPv6 的记录均保持一致。
- 项目包含了端到端测试：在代码中绑定端口并验证输出，测试用例覆盖 macOS 和 Linux。

## 注意事项

- 在非 root 用户下运行，由于内核权限限制，无法查看属于其他用户的进程信息（与 `lsof` 限制相同）。当遇到权限不足导致被跳过的进程时，工具会在 stderr 中输出提示。如需获取完整的系统端口占用情况，请使用 `sudo ports`。
- UDP 协议没有 LISTEN 状态，只要绑定了本地端口即被视为占用。
- 为了防止被监控进程通过构造特殊的命令行参数（如 ANSI 转义序列）来影响终端显示，工具在输出前会对不可见字符进行过滤和转义。

## 许可证

MIT
