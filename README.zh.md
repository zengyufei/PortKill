# portKill

`portKill` 是一个 Windows 11 便携版端口查看和进程结束工具。

它刻意保持克制：GUI 用来查看本机 TCP/UDP 端口到底被谁占用，CLI 提供同样的核心能力。它不后台常驻，不修改防火墙规则，不写注册表，也不会自动结束任何进程。

English documentation: [README.md](./README.md)

## 功能

- 查看本机 TCP 和 UDP 端点。
- 显示协议、本地地址、本地端口、远程地址、远程端口、TCP 状态、PID、进程名和进程路径。
- 支持按端口、PID、进程名、地址、状态、路径搜索。
- 支持按协议、IP 版本和 TCP 状态筛选。
- GUI 默认聚焦 TCP `LISTENING` 和 UDP 记录；已建立 TCP 连接可通过“显示连接明细”开关查看。
- 结束进程前必须人工确认。
- 禁止结束 PID `0`、PID `4` 和正在运行的 `portKill` 自身进程。
- 便携包包含 `portKill.exe`、`portKill-cli.exe` 和 `README.txt`。

## 设计

程序使用最小 Tauri 壳，前端是原生 HTML、CSS 和 JavaScript，没有 React、Vue 或 Tailwind。系统层使用 Rust 调 Windows API，不解析 `netstat` 字符串输出。

主要使用的 Windows API 包括 `GetExtendedTcpTable`、`GetExtendedUdpTable`、`OpenProcess`、`QueryFullProcessImageNameW` 和 `TerminateProcess`。

## 目录结构

```text
.
├── README.md
├── README.zh.md
├── scripts/
│   ├── build-portable.ps1
│   └── generate-icon.ps1
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── icons/
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       └── bin/portKill-cli.rs
└── ui/
    ├── index.html
    ├── style.css
    └── app.js
```

## 运行

构建后直接使用 `dist\portKill-portable` 下的便携程序：

```text
dist\portKill-portable\portKill.exe
dist\portKill-portable\portKill-cli.exe
```

最终 zip 包路径：

```text
dist\portKill-windows-x64-portable.zip
```

## CLI 用法

列出端口：

```powershell
.\portKill-cli.exe list
```

只列出“占用视角”的记录，也就是 TCP `LISTENING` 和 UDP：

```powershell
.\portKill-cli.exe list --listeners-only
```

按协议、TCP 状态或文本筛选：

```powershell
.\portKill-cli.exe list --protocol tcp --state LISTENING
.\portKill-cli.exe list --query nginx
```

查找指定本地端口：

```powershell
.\portKill-cli.exe find --port 3000
.\portKill-cli.exe find --port 3000 --json
```

结束进程：

```powershell
.\portKill-cli.exe kill --pid 12345
```

不带 `--yes` 时，CLI 会要求输入 `yes` 二次确认。跳过确认：

```powershell
.\portKill-cli.exe kill --pid 12345 --yes
```

## 开发

环境要求：

- Windows 11 x64。
- Rust MSVC 工具链。
- Visual Studio Build Tools 或带 `vcvars64.bat` 的 Visual Studio。
- Windows SDK。
- WebView2 Runtime，Windows 11 默认包含。

运行测试：

```powershell
cd D:\cache\portKill\src-tauri
cargo test
```

构建 CLI：

```powershell
cargo build --release --bin portKill-cli
```

直接构建 GUI exe：

```powershell
cargo build --release --bin portKill
```

如果本机安装了 `cargo-tauri`，便携构建脚本会使用 `cargo tauri build --no-bundle`。如果没有安装，脚本会回退到 `cargo build --release --bin portKill`，仍然会生成可用的便携 GUI 程序。

## 便携打包

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-portable.ps1
```

脚本会完成：

- 生成本地图标。
- 加载 Visual Studio x64 构建环境。
- 运行 `cargo test`。
- 构建 `portKill-cli.exe`。
- 构建 `portKill.exe`。
- 复制 release 文件到 `dist\portKill-portable`。
- 生成 `dist\portKill-windows-x64-portable.zip`。

## 安全说明

`portKill` 结束的是进程，不是端口。端口由进程占用，所以 GUI 和 CLI 都使用“结束进程”这个表述，而不是“杀端口”。

工具会拒绝结束 PID `0`、PID `4` 和自身进程。其他受保护或需要更高权限的进程也可能由 Windows 返回权限错误，程序会把错误提示给用户。

## 已验证

当前实现已通过：

```powershell
cargo test
cargo build --release --bin portKill-cli
cargo build --release --bin portKill
```

测试覆盖端口字节序转换、TCP 状态映射、IPv4/IPv6 地址格式化、筛选逻辑、受保护 PID 逻辑、临时 TCP/UDP 端口发现，以及测试子进程结束链路。
