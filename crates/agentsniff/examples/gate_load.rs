//! Load and soak generator for the gate's `/check` endpoint.
//!
//! Sends a realistic mix of request profiles (complete browsers, browsers
//! missing headers, HTTP libraries, self-declared agents, garbage Web Bot Auth
//! signatures) from many distinct client addresses, and reports throughput,
//! status counts, latency percentiles, and the gate's resident memory.
//!
//! ```text
//! cargo run --release -p agentsniff --example gate_load -- \
//!     --rps 2000 --duration 3600 --clients 300000 --pid $(pgrep -f 'agentsniff gate')
//! ```
//!
//! `--rps 0` runs unthrottled. The gate must trust the generator's address
//! (loopback is trusted by default) for `X-Forwarded-For` to count.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Gate check URL.
    #[arg(long, default_value = "http://127.0.0.1:9091/check")]
    url: String,
    /// Target requests per second across all workers; 0 for unthrottled.
    #[arg(long, default_value_t = 2000)]
    rps: u64,
    /// Run length in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Concurrent connections.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// Distinct client addresses to draw from (up to 16,777,216).
    #[arg(long, default_value_t = 300_000)]
    clients: u32,
    /// Seconds between progress lines.
    #[arg(long, default_value_t = 10)]
    report_secs: u64,
    /// Gate process id, for resident-memory samples.
    #[arg(long)]
    pid: Option<u32>,
}

/// Share of traffic in percent, name, headers.
type Profile = (u32, &'static str, &'static [(&'static str, &'static str)]);

/// Request profiles with the share of traffic each gets, in percent.
const PROFILES: &[Profile] = &[
    (60, "browser", &[
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Dest", "document"),
    ]),
    (10, "browser_bare", &[
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"),
    ]),
    (10, "curl", &[("User-Agent", "curl/8.5.0"), ("Accept", "*/*")]),
    (5, "python", &[("User-Agent", "python-requests/2.32.3")]),
    (5, "no_ua", &[]),
    (5, "claimed_agent", &[("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot")]),
    (5, "bad_signature", &[
        ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Signature-Agent", "\"https://example.com\""),
        ("Signature-Input", "sig1=(\"@authority\" \"signature-agent\");created=1735690000;keyid=\"abc\";alg=\"ed25519\";expires=1735693600;nonce=\"n\";tag=\"web-bot-auth\""),
        ("Signature", "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"),
    ]),
];

/// Latency histogram: 10µs buckets to 100ms, then one overflow bucket.
struct Hist([u64; 10_001]);

impl Hist {
    fn new() -> Self {
        Hist([0; 10_001])
    }
    fn record(&mut self, d: Duration) {
        let b = (d.as_micros() / 10).min(10_000) as usize;
        self.0[b] += 1;
    }
    fn diff(&self, base: &Hist) -> Hist {
        let mut out = Hist::new();
        for (i, v) in out.0.iter_mut().enumerate() {
            *v = self.0[i] - base.0[i];
        }
        out
    }
    fn merge(&mut self, other: &Hist) {
        for (i, v) in self.0.iter_mut().enumerate() {
            *v += other.0[i];
        }
    }
    fn count(&self) -> u64 {
        self.0.iter().sum()
    }
    fn percentile(&self, p: f64) -> String {
        let total = self.count();
        if total == 0 {
            return "-".into();
        }
        let target = ((total as f64) * p).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (i, v) in self.0.iter().enumerate() {
            seen += v;
            if seen >= target {
                return if i == 10_000 {
                    ">100ms".into()
                } else {
                    format!("{:.2}ms", (i as f64 + 1.0) / 100.0)
                };
            }
        }
        unreachable!()
    }
    fn line(&self) -> String {
        format!(
            "p50 {} p90 {} p99 {} p99.9 {} max {}",
            self.percentile(0.5),
            self.percentile(0.9),
            self.percentile(0.99),
            self.percentile(0.999),
            self.percentile(1.0)
        )
    }
}

#[derive(Default)]
struct Counts {
    allow: AtomicU64,
    challenge: AtomicU64,
    block: AtomicU64,
    other: AtomicU64,
    error: AtomicU64,
}

impl Counts {
    fn total(&self) -> u64 {
        self.allow.load(Ordering::Relaxed)
            + self.challenge.load(Ordering::Relaxed)
            + self.block.load(Ordering::Relaxed)
            + self.other.load(Ordering::Relaxed)
            + self.error.load(Ordering::Relaxed)
    }
}

fn pick_profile(r: u32) -> &'static Profile {
    let mut x = r % 100;
    for p in PROFILES {
        if x < p.0 {
            return p;
        }
        x -= p.0;
    }
    &PROFILES[0]
}

fn rss_mb(pid: u32) -> Option<f64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kb: f64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb / 1024.0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(args.concurrency)
        .build()?;
    let counts = Arc::new(Counts::default());
    let hists: Vec<Arc<Mutex<Hist>>> = (0..args.concurrency)
        .map(|_| Arc::new(Mutex::new(Hist::new())))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let per_worker_interval = if args.rps == 0 {
        None
    } else {
        Some(Duration::from_secs_f64(
            args.concurrency as f64 / args.rps as f64,
        ))
    };

    let mut workers = Vec::new();
    for (w, hist) in hists.iter().enumerate() {
        let client = client.clone();
        let counts = Arc::clone(&counts);
        let hist = Arc::clone(hist);
        let url = args.url.clone();
        let clients = args.clients.max(1);
        workers.push(tokio::spawn(async move {
            let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ ((w as u64 + 1) * 0xD1B5_4A32_D192_ED03);
            let mut tick = per_worker_interval.map(tokio::time::interval);
            if let Some(t) = tick.as_mut() {
                t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            }
            while Instant::now() < deadline {
                if let Some(t) = tick.as_mut() {
                    t.tick().await;
                }
                // xorshift64*
                rng ^= rng >> 12;
                rng ^= rng << 25;
                rng ^= rng >> 27;
                let r = rng.wrapping_mul(0x2545_F491_4F6C_DD1D);
                let ip = (r >> 32) as u32 % clients;
                let profile = pick_profile((r & 0xFFFF_FFFF) as u32);
                let mut req = client
                    .get(&url)
                    .header(
                        "X-Forwarded-For",
                        format!("10.{}.{}.{}", (ip >> 16) & 255, (ip >> 8) & 255, ip & 255),
                    )
                    .header("X-Forwarded-Method", "GET")
                    .header("X-Forwarded-Uri", "/")
                    .header("X-Forwarded-Host", "www.example.com")
                    .header("X-Forwarded-Proto", "https");
                for (k, v) in profile.2 {
                    req = req.header(*k, *v);
                }
                let started = Instant::now();
                let slot = match req.send().await {
                    Ok(resp) => match resp.status().as_u16() {
                        200..=299 => &counts.allow,
                        401 => &counts.challenge,
                        403 => &counts.block,
                        _ => &counts.other,
                    },
                    Err(_) => &counts.error,
                };
                slot.fetch_add(1, Ordering::Relaxed);
                hist.lock().unwrap().record(started.elapsed());
            }
        }));
    }

    let started = Instant::now();
    let mut last = Instant::now();
    let mut last_total = 0;
    let mut last_hist = Hist::new();
    println!(
        "{} workers, {} clients, target {} rps, {}s",
        args.concurrency,
        args.clients,
        if args.rps == 0 {
            "max".to_string()
        } else {
            args.rps.to_string()
        },
        args.duration
    );
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(args.report_secs).min(deadline - Instant::now()))
            .await;
        let mut cum = Hist::new();
        for h in &hists {
            cum.merge(&h.lock().unwrap());
        }
        let interval = cum.diff(&last_hist);
        let total = counts.total();
        let elapsed = last.elapsed().as_secs_f64();
        let rss = args
            .pid
            .and_then(rss_mb)
            .map(|m| format!(" rss {m:.1}MB"))
            .unwrap_or_default();
        println!(
            "[{:>5}s] {:>7.0} rps  allow {} challenge {} block {} other {} err {}  {}{}",
            started.elapsed().as_secs(),
            (total - last_total) as f64 / elapsed,
            counts.allow.load(Ordering::Relaxed),
            counts.challenge.load(Ordering::Relaxed),
            counts.block.load(Ordering::Relaxed),
            counts.other.load(Ordering::Relaxed),
            counts.error.load(Ordering::Relaxed),
            interval.line(),
            rss
        );
        last = Instant::now();
        last_total = total;
        last_hist = cum;
    }
    for w in workers {
        w.await?;
    }
    let mut cum = Hist::new();
    for h in &hists {
        cum.merge(&h.lock().unwrap());
    }
    let total = counts.total();
    println!(
        "total {} requests in {:.0}s ({:.0} rps): allow {} challenge {} block {} other {} err {}",
        total,
        started.elapsed().as_secs_f64(),
        total as f64 / started.elapsed().as_secs_f64(),
        counts.allow.load(Ordering::Relaxed),
        counts.challenge.load(Ordering::Relaxed),
        counts.block.load(Ordering::Relaxed),
        counts.other.load(Ordering::Relaxed),
        counts.error.load(Ordering::Relaxed)
    );
    println!("latency overall: {}", cum.line());
    if let Some(m) = args.pid.and_then(rss_mb) {
        println!("gate rss at end: {m:.1}MB");
    }
    Ok(())
}
