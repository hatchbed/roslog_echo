# roslog_echo

A CLI tool written in Rust to echo and reformat [ROS](https://www.ros.org/) log messages to stdout as
they are added to [rosout.log](http://wiki.ros.org/rosout#rosout.log).

## Motivation

Rosout log messages don't seem to be guaranteed to make it to the console, especially if they are INFO level.  This can
make debugging difficult.  The rosout.log file doesn't seem to have this problem.  It also contains some extra metadata
that makes it a bit noisy to skim through.  This tool will tail the rosout.log file and echo new lines to stdout as they
are written in a user specified formatting.


## Building

1. Install rust: https://www.rust-lang.org/tools/install
2. From the repo directory:
```
$ cargo build --release
```

## Usage
```
USAGE:
    roslog_echo [FLAGS] [OPTIONS] <FILE>

FLAGS:
    -d, --debug-off    Ignore debug level log messages
    -i, --info-off     Ignore info level log messages
    -w, --warn-off     Ignore warning level log messages
    -e, --error-off    Ignore error level log messages
    -f, --fatal-off    Ignore fatal level log messages
    -c, --colored      Color output based on severity
    -h, --help         Prints help information
    -V, --version      Prints version information

OPTIONS:
        --format <format>                Format string.
    -s, --severity-len <severity-len>    Length to truncate or pad the log severity
    -t, --time-len <time-len>            Length to truncate or pad the log timestamp

ARGS:
    <FILE>    Rosout log file.


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

default format: "{time} [{severity}] {message}"

```