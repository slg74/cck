//! cck — SSL/TLS Certificate Checker (Rust)
//!
//! Checks X.509 certificates from PEM files or live TLS hostnames.
//! Reports expired, expiring-soon, and valid certs.
//!
//! Usage:
//!   cck cert.pem [cert2.pem ...]     # check cert files
//!   cck -H example.com               # check live TLS cert
//!   cck -H example.com:8443 -w 14   # custom port and warn threshold

use std::fs;
use std::io::IsTerminal;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use chrono::{Duration as ChrDur, Utc};
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

// ── exit codes ────────────────────────────────────────────────────────
const EXIT_OK: i32 = 0;
const EXIT_PROBLEM: i32 = 1; // expired or expiring soon
const EXIT_ERROR: i32 = 2;   // i/o, parse, or connection failure

// ── defaults ──────────────────────────────────────────────────────────
const DEFAULT_PORT: u16 = 443;
const DEFAULT_WARN_DAYS: i64 = 30;
const DEFAULT_TIMEOUT: u64 = 10; // seconds

// ── ANSI escape sequences ─────────────────────────────────────────────
const RED: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[1;36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// ── CertStatus ────────────────────────────────────────────────────────

/// Outcome of evaluating one certificate.
///
/// Derives `Ord` so `.max()` over a collection of results gives the
/// worst (highest-severity) status across all certs in one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CertStatus {
    Ok,
    Warn,
    Expired,
    Error,
}

impl CertStatus {
    fn exit_code(self) -> i32 {
        match self {
            Self::Ok => EXIT_OK,
            Self::Warn | Self::Expired => EXIT_PROBLEM,
            Self::Error => EXIT_ERROR,
        }
    }
}

// ── Target ────────────────────────────────────────────────────────────

enum Target {
    File(PathBuf),
    Host { hostname: String, port: u16 },
}

// ── Config ────────────────────────────────────────────────────────────

struct Config {
    warn_days: i64,
    timeout: u64,
    quiet: bool,
    no_color: bool,
    verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            warn_days: DEFAULT_WARN_DAYS,
            timeout: DEFAULT_TIMEOUT,
            quiet: false,
            no_color: false,
            verbose: false,
        }
    }
}

impl Config {
    /// Return the ANSI escape sequence, or `""` when colour is disabled.
    fn c<'a>(&self, code: &'a str) -> &'a str {
        if self.no_color { "" } else { code }
    }
}

// ── helpers ───────────────────────────────────────────────────────────

/// Format an ASN.1 timestamp as `"YYYY-MM-DD"`.
///
/// Strategy: measure the ASN.1 time's offset from the current moment
/// using OpenSSL's `ASN1_TIME_diff`, then add that delta to `Utc::now()`
/// and format the result.  This avoids needing a Unix-timestamp accessor
/// on `Asn1TimeRef`, which the openssl crate does not expose directly.
fn fmt_asn1_date(asn1: &openssl::asn1::Asn1TimeRef) -> String {
    let now_asn1 = match Asn1Time::days_from_now(0) {
        Ok(t) => t,
        Err(_) => return "(unknown)".to_string(),
    };
    let diff = match now_asn1.diff(asn1) {
        Ok(d) => d,
        Err(_) => return "(unknown)".to_string(),
    };
    (Utc::now()
        + ChrDur::days(diff.days as i64)
        + ChrDur::seconds(diff.secs as i64))
    .format("%Y-%m-%d")
    .to_string()
}

// ── certificate evaluation ────────────────────────────────────────────

fn evaluate_cert(cert: &X509, label: &str, cfg: &Config) -> CertStatus {
    // Compute the signed offset from now to the notAfter field.
    // Positive  → cert still valid (days remaining).
    // Negative  → cert has expired (days since expiry).
    let now_asn1 = match Asn1Time::days_from_now(0) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — failed to read system clock: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            return CertStatus::Error;
        }
    };

    let diff = match now_asn1.diff(cert.not_after()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — could not parse certificate dates: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            return CertStatus::Error;
        }
    };

    let days = diff.days as i64;
    let expired = days < 0 || (days == 0 && diff.secs < 0);
    let expiry_str = fmt_asn1_date(cert.not_after());

    if expired {
        let days_ago = if days == 0 { 1u64 } else { days.unsigned_abs() };
        eprintln!(
            "{}EXPIRED{} {}\n         expired {} ({} day{} ago)",
            cfg.c(RED), cfg.c(RESET), label,
            expiry_str,
            days_ago,
            if days_ago == 1 { "" } else { "s" },
        );
        if cfg.verbose {
            eprintln!("         valid from {}", fmt_asn1_date(cert.not_before()));
        }
        CertStatus::Expired
    } else if days <= cfg.warn_days {
        println!(
            "{}WARN{}    {}\n         expires {} (in {} day{})",
            cfg.c(YELLOW), cfg.c(RESET), label,
            expiry_str,
            days,
            if days == 1 { "" } else { "s" },
        );
        CertStatus::Warn
    } else {
        if !cfg.quiet {
            println!(
                "{}OK{}      {}\n         expires {} (in {} day{})",
                cfg.c(GREEN), cfg.c(RESET), label,
                expiry_str,
                days,
                if days == 1 { "" } else { "s" },
            );
        }
        CertStatus::Ok
    }
}

// ── file-based check ──────────────────────────────────────────────────

fn check_file(path: &PathBuf, cfg: &Config) -> CertStatus {
    let label = path.display().to_string();

    let pem = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{}ERROR{}  {} — {}", cfg.c(RED), cfg.c(RESET), label, e);
            return CertStatus::Error;
        }
    };

    // `stack_from_pem` parses every certificate block in the file,
    // handling PEM chains (multiple certs concatenated) transparently.
    let certs = match X509::stack_from_pem(&pem) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            eprintln!(
                "{}ERROR{}  {} — no valid PEM certificate found",
                cfg.c(RED), cfg.c(RESET), label
            );
            return CertStatus::Error;
        }
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — failed to parse PEM: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            return CertStatus::Error;
        }
    };

    // Evaluate every cert; `max()` gives worst (highest-ordinal) status.
    certs
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let cert_label = if i == 0 {
                label.clone()
            } else {
                format!("{} [cert {}]", label, i + 1)
            };
            evaluate_cert(cert, &cert_label, cfg)
        })
        .max()
        .unwrap_or(CertStatus::Ok) // unreachable: certs is non-empty
}

// ── live TLS check ────────────────────────────────────────────────────

fn check_host(hostname: &str, port: u16, cfg: &Config) -> CertStatus {
    let label = format!("{}:{}", hostname, port);
    let timeout = Duration::from_secs(cfg.timeout);

    // DNS resolution (blocking, but bounded by the OS resolver timeout)
    let addr = match format!("{}:{}", hostname, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a,
        None => {
            eprintln!(
                "{}ERROR{}  {} — DNS resolution failed",
                cfg.c(RED), cfg.c(RESET), label
            );
            return CertStatus::Error;
        }
    };

    // TCP connect with timeout.  `connect_timeout` is the idiomatic
    // alternative to alarm()/SIGALRM — no signal handler needed.
    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — connection failed: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            return CertStatus::Error;
        }
    };

    // Guard TLS I/O so a slow handshake also respects the timeout.
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // TLS setup.
    //
    // SslVerifyMode::NONE is intentional: cck must inspect whatever cert
    // the server presents — self-signed, from a private CA, already expired
    // — without letting verification abort the handshake.  The connection is
    // read-only; no sensitive data crosses the wire.  If you ever add a
    // feature that sends data over this connection, revisit this setting.
    let mut builder = match SslConnector::builder(SslMethod::tls_client()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — SSL setup failed: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            return CertStatus::Error;
        }
    };
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    // Handshake (connect performs the full TLS negotiation)
    let ssl_stream = match connector.connect(hostname, stream) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{}ERROR{}  {} — TLS handshake failed: {}",
                cfg.c(RED), cfg.c(RESET), label, e
            );
            // Detailed error only under -v to avoid leaking internal state
            if cfg.verbose {
                eprintln!("         detail: {:?}", e);
            }
            return CertStatus::Error;
        }
    };

    let cert = match ssl_stream.ssl().peer_certificate() {
        Some(c) => c,
        None => {
            eprintln!(
                "{}ERROR{}  {} — server presented no certificate",
                cfg.c(RED), cfg.c(RESET), label
            );
            return CertStatus::Error;
        }
    };

    if cfg.verbose {
        let cn = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "(unknown)".to_string());
        println!(
            "         subject CN: {}{}{}",
            cfg.c(CYAN), cn, cfg.c(RESET)
        );
    }

    evaluate_cert(&cert, &label, cfg)
}

// ── argument parsing ──────────────────────────────────────────────────

/// Split `"host:port"`, `"[::1]:port"`, or bare `"host"` into `(hostname, port)`.
fn parse_host_port(arg: &str) -> (String, u16) {
    // IPv6 bracket notation: [addr]:port  or  [addr]
    if let Some(rest) = arg.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = rest[..close].to_string();
            let port = rest[close + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            return (host, port);
        }
    }
    // Plain host  or  host:port (rfind so IPv6 literals without brackets still work)
    if let Some(pos) = arg.rfind(':') {
        if let Ok(port) = arg[pos + 1..].parse::<u16>() {
            return (arg[..pos].to_string(), port);
        }
    }
    (arg.to_string(), DEFAULT_PORT)
}

fn usage(no_color: bool) {
    let b = if no_color { "" } else { BOLD };
    let r = if no_color { "" } else { RESET };
    eprintln!(
        "{b}cck{r} — SSL/TLS Certificate Checker\n\n\
         Usage:\n  \
           cck [OPTIONS] <file.pem> [file2.pem ...]   check certificate files\n  \
           cck [OPTIONS] -H <host[:port]> [...]       check live TLS certs\n\n\
         Options:\n  \
           -H <host[:port]>   connect to host and check its TLS certificate\n  \
                              (port defaults to {DEFAULT_PORT})\n  \
           -w <days>          warn if expiring within N days (default: {DEFAULT_WARN_DAYS})\n  \
           -t <secs>          TLS connect timeout in seconds (default: {DEFAULT_TIMEOUT})\n  \
           -q                 quiet mode — only show problems\n  \
           -v                 verbose — show extra cert details\n  \
           --no-color         disable ANSI colour output\n  \
           --help             show this help\n\n\
         Exit codes:\n  \
           0  all certificates valid\n  \
           1  one or more certificates expired or expiring soon\n  \
           2  error (file not found, parse failure, connection error)\n\n\
         Examples:\n  \
           cck /etc/ssl/certs/my.pem\n  \
           cck -H example.com\n  \
           cck -H example.com:8443 -w 14\n  \
           cck -q /etc/ssl/certs/*.pem",
        b = b, r = r,
    );
}

/// Parse a bounded integer from a CLI argument, exiting with an error on bad input.
/// Uses `str::parse` (not `atoi`) so non-numeric and out-of-range input is rejected.
fn parse_int_arg(flag: &str, val: &str, min: i64, max: i64) -> i64 {
    match val.parse::<i64>() {
        Ok(n) if (min..=max).contains(&n) => n,
        _ => {
            eprintln!("cck: {} requires an integer between {} and {}", flag, min, max);
            process::exit(EXIT_ERROR);
        }
    }
}

fn parse_args() -> (Config, Vec<Target>) {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = Config {
        // Disable colour automatically when stdout is not a TTY
        no_color: !std::io::stdout().is_terminal(),
        ..Config::default()
    };
    let mut targets: Vec<Target> = Vec::new();
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                usage(cfg.no_color);
                process::exit(EXIT_OK);
            }
            "--no-color" => cfg.no_color = true,
            "-q" => cfg.quiet = true,
            "-v" => cfg.verbose = true,

            "-H" => {
                i += 1;
                let val = match args.get(i) {
                    Some(v) => v.as_str(),
                    None => {
                        eprintln!("cck: -H requires a host argument");
                        process::exit(EXIT_ERROR);
                    }
                };
                let (hostname, port) = parse_host_port(val);
                targets.push(Target::Host { hostname, port });
            }
            "-w" => {
                i += 1;
                let val = match args.get(i) {
                    Some(v) => v.as_str(),
                    None => {
                        eprintln!("cck: -w requires a value");
                        process::exit(EXIT_ERROR);
                    }
                };
                cfg.warn_days = parse_int_arg("-w", val, 0, 36500);
            }
            "-t" => {
                i += 1;
                let val = match args.get(i) {
                    Some(v) => v.as_str(),
                    None => {
                        eprintln!("cck: -t requires a value");
                        process::exit(EXIT_ERROR);
                    }
                };
                cfg.timeout = parse_int_arg("-t", val, 1, 300) as u64;
            }

            arg if arg.starts_with('-') => {
                eprintln!("cck: unknown option: {}", arg);
                process::exit(EXIT_ERROR);
            }
            path => {
                targets.push(Target::File(PathBuf::from(path)));
            }
        }
        i += 1;
    }

    (cfg, targets)
}

// ── main ──────────────────────────────────────────────────────────────

fn main() {
    let (cfg, targets) = parse_args();

    if targets.is_empty() {
        usage(cfg.no_color);
        process::exit(EXIT_OK);
    }

    // Evaluate every target; collect the worst status across all of them.
    let worst = targets
        .iter()
        .map(|target| match target {
            Target::File(path) => check_file(path, &cfg),
            Target::Host { hostname, port } => check_host(hostname, *port, &cfg),
        })
        .max()
        .unwrap_or(CertStatus::Ok); // unreachable: targets is non-empty

    process::exit(worst.exit_code());
}
