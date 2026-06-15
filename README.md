# portKill

`portKill` is a Windows 11 portable port viewer and process terminator.

It is intentionally small: the GUI shows who owns local TCP/UDP ports, and the CLI provides the same core workflow for terminal use. It does not run in the background, does not modify firewall rules, does not write to the registry, and never terminates a process automatically.

Chinese documentation: [README.zh.md](./README.zh.md)

## Features

- View local TCP and UDP endpoints.
- Show protocol, local address, local port, remote address, remote port, TCP state, PID, process name, and process path.
- Search by port, PID, process name, address, state, or path.
- Filter by protocol, IP version, and TCP state.
- Default GUI view focuses on TCP `LISTENING` rows and UDP rows; established TCP connections can be shown with the details toggle.
- End a process only after manual confirmation.
- Protect PID `0`, PID `4`, and the running `portKill` process from termination.
- Portable package with `portKill.exe`, `portKill-cli.exe`, and `README.txt`.

## Design

The application uses a minimal Tauri shell with vanilla HTML, CSS, and JavaScript. The system layer is Rust and Windows API calls. The code does not parse `netstat` output.

The main APIs used are `GetExtendedTcpTable`, `GetExtendedUdpTable`, `OpenProcess`, `QueryFullProcessImageNameW`, and `TerminateProcess`.

## Repository Layout

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

## Run

Use the portable package under `dist\portKill-portable` after building:

```text
dist\portKill-portable\portKill.exe
dist\portKill-portable\portKill-cli.exe
```

The final zip is:

```text
dist\portKill-windows-x64-portable.zip
```

## CLI

List ports:

```powershell
.\portKill-cli.exe list
```

List only listener-style rows, which means TCP `LISTENING` and UDP:

```powershell
.\portKill-cli.exe list --listeners-only
```

Filter by protocol, TCP state, or text:

```powershell
.\portKill-cli.exe list --protocol tcp --state LISTENING
.\portKill-cli.exe list --query nginx
```

Find a local port:

```powershell
.\portKill-cli.exe find --port 3000
.\portKill-cli.exe find --port 3000 --json
```

End a process:

```powershell
.\portKill-cli.exe kill --pid 12345
```

Without `--yes`, the CLI asks for confirmation. To skip the prompt:

```powershell
.\portKill-cli.exe kill --pid 12345 --yes
```

## Development

Requirements:

- Windows 11 x64.
- Rust MSVC toolchain.
- Visual Studio Build Tools or Visual Studio with `vcvars64.bat`.
- Windows SDK.
- WebView2 runtime, included with Windows 11.

Run tests:

```powershell
cd D:\cache\portKill\src-tauri
cargo test
```

Build the CLI:

```powershell
cargo build --release --bin portKill-cli
```

Build the GUI exe directly:

```powershell
cargo build --release --bin portKill
```

If `cargo-tauri` is installed, the portable build script uses `cargo tauri build --no-bundle`. If it is not installed, the script falls back to `cargo build --release --bin portKill`, which still produces the portable GUI executable.

## Portable Build

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-portable.ps1
```

The script:

- Generates the local icon.
- Loads the Visual Studio x64 build environment.
- Runs `cargo test`.
- Builds `portKill-cli.exe`.
- Builds `portKill.exe`.
- Copies release files to `dist\portKill-portable`.
- Creates `dist\portKill-windows-x64-portable.zip`.

## Safety Notes

`portKill` ends processes, not ports. A port is owned by a process, so the GUI and CLI both use the wording "end process" instead of "kill port".

The tool refuses to terminate PID `0`, PID `4`, and its own process. Other protected or elevated processes may also fail with a Windows permission error, which is shown to the user.

## Verified

The current implementation has been verified with:

```powershell
cargo test
cargo build --release --bin portKill-cli
cargo build --release --bin portKill
```

The test suite covers port byte order conversion, TCP state mapping, IPv4/IPv6 formatting, filter behavior, protected PID behavior, temporary TCP/UDP socket discovery, and termination of a test child process.
