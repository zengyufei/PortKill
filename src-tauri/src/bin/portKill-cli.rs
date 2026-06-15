use portkill_core::{list_filtered_ports, terminate_process_by_pid, PortEntry, PortFilter};
use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "list" => list_command(&args),
        "find" => find_command(&args),
        "kill" => kill_command(&args),
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("未知命令：{other}")),
    }
}

fn list_command(args: &[String]) -> Result<(), String> {
    let (filter, json) = parse_filter_args(args)?;
    let entries = list_filtered_ports(&filter)?;
    if json {
        print_json(&entries)
    } else {
        print_table(&entries);
        Ok(())
    }
}

fn find_command(args: &[String]) -> Result<(), String> {
    let mut port = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = Some(parse_required_u16(args.get(i), "--port")?);
            }
            "--json" => json = true,
            unknown => return Err(format!("find 不支持参数：{unknown}")),
        }
        i += 1;
    }

    let port = port.ok_or_else(|| "find 必须提供 --port <port>".to_string())?;
    let entries = list_filtered_ports(&PortFilter {
        port: Some(port),
        ..Default::default()
    })?;
    if json {
        print_json(&entries)
    } else {
        print_table(&entries);
        Ok(())
    }
}

fn kill_command(args: &[String]) -> Result<(), String> {
    let mut pid = None;
    let mut yes = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pid" => {
                i += 1;
                pid = Some(parse_required_u32(args.get(i), "--pid")?);
            }
            "--yes" => yes = true,
            unknown => return Err(format!("kill 不支持参数：{unknown}")),
        }
        i += 1;
    }

    let pid = pid.ok_or_else(|| "kill 必须提供 --pid <pid>".to_string())?;
    if !yes {
        print!("确认结束 PID {pid} 对应的进程？输入 yes 继续：");
        io::stdout().flush().map_err(|err| err.to_string())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|err| err.to_string())?;
        if answer.trim() != "yes" {
            return Err("已取消。".to_string());
        }
    }

    terminate_process_by_pid(pid)?;
    println!("已结束 PID {pid}。");
    Ok(())
}

fn parse_filter_args(args: &[String]) -> Result<(PortFilter, bool), String> {
    let mut filter = PortFilter {
        protocol: Some("all".to_string()),
        ..Default::default()
    };
    let mut json = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--protocol" => {
                i += 1;
                let protocol = args
                    .get(i)
                    .ok_or_else(|| "--protocol 缺少值".to_string())?
                    .to_ascii_lowercase();
                match protocol.as_str() {
                    "tcp" | "udp" | "all" => filter.protocol = Some(protocol),
                    _ => return Err("--protocol 只支持 tcp、udp、all".to_string()),
                }
            }
            "--state" => {
                i += 1;
                filter.state = Some(
                    args.get(i)
                        .ok_or_else(|| "--state 缺少值".to_string())?
                        .to_ascii_uppercase(),
                );
            }
            "--query" => {
                i += 1;
                filter.query = Some(
                    args.get(i)
                        .ok_or_else(|| "--query 缺少值".to_string())?
                        .to_string(),
                );
            }
            "--listeners-only" => filter.listeners_only = true,
            unknown => return Err(format!("list 不支持参数：{unknown}")),
        }
        i += 1;
    }

    Ok((filter, json))
}

fn parse_required_u16(value: Option<&String>, name: &str) -> Result<u16, String> {
    value
        .ok_or_else(|| format!("{name} 缺少值"))?
        .parse::<u16>()
        .map_err(|_| format!("{name} 必须是 0-65535 的端口号"))
}

fn parse_required_u32(value: Option<&String>, name: &str) -> Result<u32, String> {
    value
        .ok_or_else(|| format!("{name} 缺少值"))?
        .parse::<u32>()
        .map_err(|_| format!("{name} 必须是数字"))
}

fn print_json(entries: &[PortEntry]) -> Result<(), String> {
    let json = serde_json::to_string_pretty(entries).map_err(|err| err.to_string())?;
    println!("{json}");
    Ok(())
}

fn print_table(entries: &[PortEntry]) {
    println!(
        "{:<4} {:<22} {:<6} {:<22} {:<6} {:<13} {:<8} {}",
        "协议", "本地地址", "端口", "远程地址", "端口", "状态", "PID", "进程"
    );
    println!("{}", "-".repeat(96));
    for entry in entries {
        println!(
            "{:<4} {:<22} {:<6} {:<22} {:<6} {:<13} {:<8} {}",
            entry.protocol,
            truncate(&entry.local_addr, 22),
            entry.local_port,
            truncate(&entry.remote_addr, 22),
            entry.remote_port,
            entry.state,
            entry.pid,
            entry.process
        );
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut out = String::new();
    for _ in 0..max_chars {
        if let Some(ch) = chars.next() {
            out.push(ch);
        } else {
            return out;
        }
    }
    if chars.next().is_some() && max_chars > 1 {
        out.truncate(max_chars - 1);
        out.push('…');
    }
    out
}

fn print_help() {
    println!(
        "portKill-cli

用法：
  portKill-cli list [--json] [--protocol tcp|udp|all] [--state LISTENING] [--query text] [--listeners-only]
  portKill-cli find --port <port> [--json]
  portKill-cli kill --pid <pid> [--yes]

说明：
  list 默认列出 TCP/UDP 端口。
  find 按本地端口查找。
  kill 结束的是进程，不是端口；未带 --yes 时需要输入 yes 确认。"
    );
}
