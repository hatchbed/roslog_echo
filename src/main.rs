extern crate path_absolutize;

use clap::{App, Arg};
use colored::*;
use dynfmt::{Format, SimpleCurlyFormat};
use lazy_static::lazy_static;
use linemux::MuxedLines;
use path_absolutize::*;
use regex::Regex;
use std::{cmp::Ordering, path::Path, thread, time};

lazy_static! {
    static ref FIND_SPACE: regex::Regex = Regex::new(" ").unwrap();
    static ref FIND_OPEN_SQR: regex::Regex = Regex::new("\\[").unwrap();
    static ref FIND_CLOSE_SQR: regex::Regex = Regex::new("\\] ").unwrap();
    static ref KINETIC_SPLIT: regex::Regex = Regex::new("\\) \\[topics:").unwrap();
    static ref MELODIC_SPLIT: regex::Regex = Regex::new("\\)\\]").unwrap();
    static ref LOC_MATCH: regex::Regex = Regex::new(r"\[(.*):(\d*)\((.*)").unwrap();
}

enum RosLogVersion {
    Kinetic,
    Melodic,
    Unknown,
}

#[derive(Copy, Clone)]
enum Severity {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Unknown,
}

impl Severity {
    fn from_str(text: &str) -> Severity {
        match text {
            "INFO" => Severity::Info,
            "WARN" => Severity::Warn,
            "ERROR" => Severity::Error,
            "FATAL" => Severity::Fatal,
            "DEBUG" => Severity::Debug,
            _ => Severity::Unknown,
        }
    }

    fn to_str(&self) -> &'static str {
        match *self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
            Severity::Fatal => "FATAL",
            Severity::Debug => "DEBUG",
            Severity::Unknown => "",
        }
    }
}

struct LogEntry {
    message: String,
    severity: Severity,
    stamp: String,
    node: String,
    loc: String,
}

struct LogFormat {
    format: String,
    show_loc: bool,
    stamp_len: i32,
    severity_len: i32,
}

impl LogFormat {
    fn new(user_format: &str, stamp_len: i32, severity_len: i32) -> LogFormat {
        let mut log_format = user_format.to_string();
        log_format = log_format.replace("{severity}", "{0}");
        log_format = log_format.replace("{time}", "{1}");
        log_format = log_format.replace("{message}", "{2}");
        log_format = log_format.replace("{line}", "{3}");
        log_format = log_format.replace("{node}", "{4}");
        log_format = log_format.replace("{file}", "{5}");
        log_format = log_format.replace("{function}", "{6}");

        LogFormat {
            format: log_format,
            show_loc: user_format.contains("{file}")
                || user_format.contains("{line}")
                || user_format.contains("{function}"),
            stamp_len,
            severity_len,
        }
    }
}

fn print_colored(text: &str, severity: Severity, colored: bool) {
    if colored {
        match severity {
            Severity::Info => println!("{}", text),
            Severity::Warn => println!("{}", text.yellow()),
            Severity::Error => println!("{}", text.red()),
            Severity::Fatal => println!("{}", text.on_red()),
            Severity::Debug => println!("{}", text.dimmed()),
            Severity::Unknown => println!("{}", text.dimmed()),
        };
    } else {
        println!("{}", text);
    }
}

fn printlog(fmt: &LogFormat, log: LogEntry, colored: bool) {
    let mut file: &str = "";
    let mut line: &str = "";
    let mut function: &str = "";
    let mut stamp = &log.stamp[..];
    let mut severity = log.severity.to_str();

    let stamp_str: String;
    if fmt.stamp_len > 0 {
        let stamp_len = fmt.stamp_len as usize;
        match stamp_len.cmp(&stamp.len()) {
            Ordering::Greater => {
                stamp_str = format!("{:1$}", stamp, width = stamp_len);
                stamp = &stamp_str[..];
            }
            Ordering::Less => stamp = &log.stamp[0..stamp_len],
            _ => (),
        }
    }

    let severity_str: String;
    if fmt.severity_len > 0 {
        let severity_len = fmt.severity_len as usize;
        match severity_len.cmp(&severity.len()) {
            Ordering::Greater => {
                severity_str = format!("{:1$}", severity, width = severity_len);
                severity = &severity_str[..];
            }
            Ordering::Less => severity = &severity[0..severity_len],
            _ => (),
        }
    }

    if fmt.show_loc {
        if let Some(caps) = LOC_MATCH.captures(&log.loc) {
            file = caps.get(1).map_or("", |m| m.as_str());
            line = caps.get(2).map_or("", |m| m.as_str());
            function = caps.get(3).map_or("", |m| m.as_str());
        }
    }

    let formatted = SimpleCurlyFormat.format(
        &fmt.format,
        &[
            severity,
            stamp,
            &log.message,
            line,
            &log.node,
            file,
            function,
        ],
    );
    match formatted {
        Ok(v) => print_colored(&v, log.severity, colored),
        Err(e) => println!("error: {:?}", e),
    }
}

fn parse_line_kinetic(line: &str) -> Option<LogEntry> {
    let split = KINETIC_SPLIT.splitn(line, 2).collect::<Vec<&str>>();
    if split.len() < 2 {
        return None;
    }

    let split2 = FIND_SPACE.splitn(split[0], 3).collect::<Vec<&str>>();
    if split2.len() < 3 {
        return None;
    }

    let severity = Severity::from_str(split2[1]);
    if matches!(severity, Severity::Unknown) {
        return None;
    }

    let split3 = FIND_CLOSE_SQR.splitn(split[1], 2).collect::<Vec<&str>>();
    if split3.len() < 2 {
        return None;
    }

    Some(LogEntry {
        message: split3[1].to_string(),
        severity,
        stamp: split2[0].to_string(),
        node: String::new(),
        loc: split2[2].to_string(),
    })
}

fn parse_line_melodic(line: &str) -> Option<LogEntry> {
    let split = MELODIC_SPLIT.splitn(line, 2).collect::<Vec<&str>>();
    if split.len() < 2 {
        return None;
    }

    let split2 = FIND_SPACE.splitn(split[0], 4).collect::<Vec<&str>>();
    if split2.len() < 4 {
        return None;
    }

    let severity = Severity::from_str(split2[1]);
    if matches!(severity, Severity::Unknown) {
        return None;
    }

    let message: &str;

    if split[1].starts_with(" [topics: ") {
        let split3 = FIND_CLOSE_SQR.splitn(split[1], 2).collect::<Vec<&str>>();
        if split3.len() < 2 {
            return None;
        }
        message = split3[1];
    } else {
        message = split[1];
    }

    Some(LogEntry {
        message: message.to_string(),
        severity,
        stamp: split2[0].to_string(),
        node: split2[2].to_string(),
        loc: split2[3].to_string(),
    })
}

fn identify_version(line: &str) -> RosLogVersion {
    let split = FIND_SPACE.splitn(line, 4).collect::<Vec<&str>>();

    if split.len() < 4 {
        return RosLogVersion::Unknown;
    }

    if split[2].starts_with('[') && parse_line_kinetic(line).is_some() {
        RosLogVersion::Kinetic
    } else if split[3].starts_with('[') && parse_line_melodic(line).is_some() {
        RosLogVersion::Melodic
    } else {
        RosLogVersion::Unknown
    }
}

#[tokio::main]
pub async fn main() -> std::io::Result<()> {
    let args = App::new("roslog_echo")
        .version("0.1.0")
        .author("Marc Alban <marcalban@hatchbed.com>")
        .about("\nEchos and reformats new entries in rosout.log to stdout")
        .arg(
            Arg::with_name("FILE")
                .takes_value(true)
                .required(true)
                .help("Rosout log file."),
        )
        .arg(
            Arg::with_name("format")
                .long("format")
                .takes_value(true)
                .required(false)
                .default_value("{time} [{severity}] {message}")
                .hide_default_value(true)
                .help("Format string."),
        )
        .after_help(
            "
Note:  The log file doesn't need to exist to begin with, but the parent directory does.

Format String Specification
----------------------------

metavariables:
    {file}        source file
    {function}    source function
    {line}        source line
    {message}     log message
    {node}        source node
    {severity}    log level
    {time}        message timestamp

default format: \"{time} [{severity}] {message}\"

",
        )
        .arg(
            Arg::with_name("severity-len")
                .short("s")
                .long("severity-len")
                .takes_value(true)
                .required(false)
                .help("Length to truncate or pad the log severity"),
        )
        .arg(
            Arg::with_name("time-len")
                .short("t")
                .long("time-len")
                .takes_value(true)
                .required(false)
                .help("Length to truncate or pad the log timestamp"),
        )
        .arg(
            Arg::with_name("debug-off")
                .short("d")
                .long("debug-off")
                .takes_value(false)
                .display_order(1)
                .help("Ignore debug level log messages"),
        )
        .arg(
            Arg::with_name("info-off")
                .short("i")
                .long("info-off")
                .takes_value(false)
                .display_order(2)
                .help("Ignore info level log messages"),
        )
        .arg(
            Arg::with_name("warn-off")
                .short("w")
                .long("warn-off")
                .takes_value(false)
                .display_order(3)
                .help("Ignore warning level log messages"),
        )
        .arg(
            Arg::with_name("error-off")
                .short("e")
                .long("error-off")
                .takes_value(false)
                .display_order(4)
                .help("Ignore error level log messages"),
        )
        .arg(
            Arg::with_name("fatal-off")
                .short("f")
                .long("fatal-off")
                .takes_value(false)
                .display_order(5)
                .help("Ignore fatal level log messages"),
        )
        .arg(
            Arg::with_name("colored")
                .short("c")
                .long("colored")
                .takes_value(false)
                .help("Color output based on severity"),
        )
        .get_matches();

    let logfile = Path::new(args.value_of("FILE").unwrap())
        .absolutize()
        .expect("Error: valid path not provided");
    let logdir = logfile.parent().expect("Error: valid path not provided");

    while !logdir.is_dir() {
        thread::sleep(time::Duration::from_millis(50));
    }

    let use_colors = args.is_present("colored");
    let ignore_debug = args.is_present("debug-off");
    let ignore_info = args.is_present("info-off");
    let ignore_warn = args.is_present("warn-off");
    let ignore_error = args.is_present("error-off");
    let ignore_fatal = args.is_present("fatal-off");
    let time_len = args
        .value_of("time-len")
        .unwrap_or("-1")
        .parse::<i32>()
        .unwrap_or(-1);
    let severity_len = args
        .value_of("severity-len")
        .unwrap_or("-1")
        .parse::<i32>()
        .unwrap_or(-1);
    let user_format = args.value_of("format").unwrap();

    let log_format = LogFormat::new(user_format, time_len, severity_len);

    let mut rosout_version = RosLogVersion::Unknown;
    let mut severity = Severity::Unknown;

    let mut lines = MuxedLines::new()?;
    lines.add_file(logfile).await?;
    while let Ok(Some(line)) = lines.next_line().await {
        if matches!(rosout_version, RosLogVersion::Unknown) {
            rosout_version = identify_version(line.line());
        }

        let entry: Option<LogEntry> = match rosout_version {
            RosLogVersion::Kinetic => parse_line_kinetic(line.line()),
            RosLogVersion::Melodic => parse_line_melodic(line.line()),
            _ => None,
        };

        if let Some(e) = entry {
            let sev = e.severity;
            if match e.severity {
                Severity::Info => !ignore_info,
                Severity::Warn => !ignore_warn,
                Severity::Error => !ignore_error,
                Severity::Fatal => !ignore_fatal,
                Severity::Debug => !ignore_debug,
                Severity::Unknown => true,
            } {
                printlog(&log_format, e, use_colors);
            }

            severity = sev;
        } else if match severity {
            Severity::Info => !ignore_info,
            Severity::Warn => !ignore_warn,
            Severity::Error => !ignore_error,
            Severity::Fatal => !ignore_fatal,
            Severity::Debug => !ignore_debug,
            Severity::Unknown => true,
        } {
            print_colored(line.line(), severity, use_colors);
        }
    }

    Ok(())
}
