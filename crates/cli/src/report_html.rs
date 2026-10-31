//! `fleetreach report html` (spec 09): the history as one self-contained HTML page (inline
//! CSS, SVG and a few lines of script; nothing fetched), to publish on GitHub Pages or any
//! static host. Summary tiles, open findings per run by severity, SLA breaches, each owner's
//! queue, fix campaigns from a saved `fix status`, and time to fix.
//!
//! Every string from the history is HTML-escaped, and only `https://` links are kept from a
//! `fix status` file. The page is deterministic for a given history and `SOURCE_DATE_EPOCH`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use fleetreach_core::Severity;

use crate::cli::fail;
use crate::config::Config;
use crate::history::{self, Entry, GroupBy, History, SlaPolicy, Status};

/// Most rows in one owner's queue or the breach table.
const MAX_ROWS: usize = 500;

#[derive(Subcommand)]
pub enum ReportCommand {
    /// One self-contained HTML page from `scan --history-dir` snapshots.
    Html(HtmlArgs),
}

#[derive(Args)]
pub struct HtmlArgs {
    /// The directory `scan --history-dir` writes
    #[arg(long)]
    history_dir: PathBuf,
    /// Where to write the page (`-` for stdout)
    #[arg(short, long, default_value = "fleet-report.html")]
    output: PathBuf,
    /// fleet.toml whose `[settings.sla]` sets deadlines (without it no breaches are shown)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// A saved `fleetreach fix status` (JSON) to list the fix campaigns
    #[arg(long)]
    fix_status: Option<PathBuf>,
    /// The page title
    #[arg(long, default_value = "Fleet security report")]
    title: String,
    /// Only runs this recent in the trend (`90d`)
    #[arg(long)]
    since: Option<String>,
}

pub fn run_report(command: ReportCommand) -> u8 {
    match command {
        ReportCommand::Html(args) => run_html(&args),
    }
}

fn run_html(args: &HtmlArgs) -> u8 {
    let policy = match &args.config {
        Some(path) => match Config::load(path) {
            Ok(c) => c.sla,
            Err(e) => return fail(&e.to_string()),
        },
        None => SlaPolicy::default(),
    };
    let campaigns = match &args.fix_status {
        Some(path) => match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| {
                serde_json::from_str::<Vec<serde_json::Value>>(&t).map_err(|e| e.to_string())
            }) {
            Ok(rows) => Some(rows),
            Err(e) => return fail(&format!("--fix-status {}: {e}", path.display())),
        },
        None => None,
    };
    let h = match history::load(&args.history_dir) {
        Ok(h) => h,
        Err(e) => return fail(&e),
    };
    for u in &h.unreadable {
        eprintln!("warning: unreadable snapshot skipped: {u}");
    }
    if h.snapshots.is_empty() {
        return fail(&format!(
            "no scan history in {}; record some with `fleetreach scan --history-dir`",
            args.history_dir.display()
        ));
    }
    let at = history::now();
    let since = match args
        .since
        .as_deref()
        .map(crate::db::parse_duration_secs)
        .transpose()
    {
        Ok(s) => s.map(|secs| at - time::Duration::seconds(secs)),
        Err(e) => return fail(&format!("--since: {e}")),
    };
    let page = render(&Input {
        title: &args.title,
        history: &h,
        policy: &policy,
        campaigns: campaigns.as_deref(),
        at,
        since,
    });
    if args.output.as_os_str() == "-" {
        print!("{page}");
        return 0;
    }
    match std::fs::write(&args.output, page) {
        Ok(()) => {
            eprintln!("wrote {}", args.output.display());
            0
        }
        Err(e) => fail(&format!("{}: {e}", args.output.display())),
    }
}

pub struct Input<'a> {
    pub title: &'a str,
    pub history: &'a History,
    pub policy: &'a SlaPolicy,
    pub campaigns: Option<&'a [serde_json::Value]>,
    pub at: time::OffsetDateTime,
    pub since: Option<time::OffsetDateTime>,
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn day(rfc3339: &str) -> &str {
    rfc3339.get(..10).unwrap_or(rfc3339)
}

/// The severities in stacking order, most severe at the baseline.
const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Unknown,
];

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "s-critical",
        Severity::High => "s-high",
        Severity::Medium => "s-medium",
        Severity::Low => "s-low",
        Severity::Unknown => "s-unknown",
    }
}

/// An open finding with its deadline, for the queues.
struct Queued<'a> {
    entry: &'a Entry,
    url: String,
    age_days: f64,
    due: Option<time::OffsetDateTime>,
    overdue_days: Option<f64>,
}

fn days(seconds: i64) -> f64 {
    (seconds as f64 / 86_400.0 * 10.0).round() / 10.0
}

fn queue<'a>(h: &'a History, policy: &SlaPolicy, at: time::OffsetDateTime) -> Vec<Queued<'a>> {
    let links = history::AdvisoryLinks::new(h);
    let mut out: Vec<Queued<'a>> = h
        .index
        .entries
        .iter()
        .filter(|e| e.status == Status::Open)
        .map(|e| {
            let first = history::parse_time(&e.first_seen);
            let due = policy
                .deadline(e.severity, e.ssvc)
                .zip(first)
                .map(|(d, f)| f + time::Duration::seconds(d));
            let overdue = due
                .map(|d| (at - d).whole_seconds())
                .filter(|s| *s > 0)
                .map(days);
            Queued {
                entry: e,
                url: links.url(&e.key.advisory),
                age_days: first.map_or(0.0, |f| days((at - f).whole_seconds())),
                due,
                overdue_days: overdue,
            }
        })
        .collect();
    // Past due first (most overdue first), then severity, then age.
    out.sort_by(|a, b| {
        b.overdue_days
            .unwrap_or(-1.0)
            .total_cmp(&a.overdue_days.unwrap_or(-1.0))
            .then(b.entry.severity.cmp(&a.entry.severity))
            .then(b.age_days.total_cmp(&a.age_days))
            .then(a.entry.key.cmp(&b.entry.key))
    });
    out
}

pub fn render(input: &Input<'_>) -> String {
    let h = input.history;
    let latest = h.snapshots.last();
    let queued = queue(h, input.policy, input.at);
    let breaches = queued.iter().filter(|q| q.overdue_days.is_some()).count();
    let changes = history::changes(h);
    let (new, fixed) = changes
        .as_ref()
        .map_or((0, 0), |c| (c.new.len(), c.fixed.len()));
    let mttr = history::mttr(h, GroupBy::Severity);
    let all_fixed: Vec<f64> = h
        .index
        .entries
        .iter()
        .filter_map(|e| {
            if e.status != Status::Fixed {
                return None;
            }
            let fixed_at = history::parse_time(e.fixed_at.as_deref()?)?;
            Some(days(
                (fixed_at - history::parse_time(&e.first_seen)?).whole_seconds(),
            ))
        })
        .collect();
    let median_fix = median(all_fixed);

    let mut b = String::new();
    let generated = history::format_time(input.at);
    let _ = writeln!(
        b,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"generator\" content=\"fleetreach {}\">\n<title>{}</title>\n<style>{}</style>\n\
         </head>\n<body>\n<main>",
        env!("CARGO_PKG_VERSION"),
        esc(input.title),
        CSS
    );
    let _ = writeln!(
        b,
        "<header><h1>{}</h1><p class=\"meta\">Generated {} from {} run(s){}.</p></header>",
        esc(input.title),
        esc(&generated),
        h.snapshots.len(),
        latest.map_or(String::new(), |s| format!(
            "; newest <code>{}</code> at {}",
            esc(&s.run.id),
            esc(&s.run.at)
        ))
    );
    if latest.is_some_and(|s| s.run.exit_code == 2) {
        b.push_str(
            "<p class=\"notice\" role=\"note\"><span class=\"icon\" aria-hidden=\"true\">!</span> \
             The newest run exited 2: part of the fleet was not read, so these counts are a \
             floor and nothing there could be marked fixed.</p>\n",
        );
    }
    if !h.unreadable.is_empty() {
        let _ = writeln!(
            b,
            "<p class=\"notice\" role=\"note\"><span class=\"icon\" aria-hidden=\"true\">!</span> \
             {} snapshot(s) could not be read and were skipped.</p>",
            h.unreadable.len()
        );
    }

    // ---- tiles ----
    let open = queued.len();
    b.push_str("<section class=\"tiles\" aria-label=\"Summary\">\n");
    let _ = writeln!(
        b,
        "<div class=\"tile hero\"><div class=\"label\">Open findings</div><div class=\"value\">{open}</div></div>"
    );
    let breach_value = if input.policy.is_empty() {
        "<div class=\"value muted\">no policy</div>".to_string()
    } else if breaches > 0 {
        format!(
            "<div class=\"value\"><span class=\"status critical\" aria-hidden=\"true\">!</span>{breaches}</div>"
        )
    } else {
        "<div class=\"value\"><span class=\"status good\" aria-hidden=\"true\">✓</span>0</div>"
            .to_string()
    };
    let _ = writeln!(
        b,
        "<div class=\"tile\"><div class=\"label\">Past SLA</div>{breach_value}</div>\n\
         <div class=\"tile\"><div class=\"label\">New in the newest run</div><div class=\"value\">{new}</div></div>\n\
         <div class=\"tile\"><div class=\"label\">Fixed in the newest run</div><div class=\"value\">{fixed}</div></div>\n\
         <div class=\"tile\"><div class=\"label\">Median days to fix</div><div class=\"value{}\">{}</div></div>",
        if median_fix.is_none() { " muted" } else { "" },
        median_fix.map_or("none fixed yet".to_string(), |d| format!("{d:.1}"))
    );
    b.push_str("</section>\n");

    trend_section(&mut b, h, input.since);
    breach_section(&mut b, &queued, input.policy);
    owner_section(&mut b, &queued, input.policy);
    if let Some(rows) = input.campaigns {
        campaign_section(&mut b, rows);
    }
    mttr_section(&mut b, &mttr);

    let _ = writeln!(
        b,
        "<footer>fleetreach {} · open findings are those the newest trustworthy scan of their \
         repo still has; a run that exited 2 never marks anything fixed.</footer>\n</main>\n\
         <div id=\"tip\" role=\"tooltip\" hidden></div>\n<script>{}</script>\n</body>\n</html>",
        env!("CARGO_PKG_VERSION"),
        SCRIPT
    );
    b
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let n = values.len();
    Some(if n % 2 == 1 {
        values[n / 2]
    } else {
        ((values[n / 2 - 1] + values[n / 2]) / 2.0 * 10.0).round() / 10.0
    })
}

/// A round axis maximum at or above `max`.
fn nice_max(max: usize) -> usize {
    if max <= 4 {
        return 4;
    }
    let mag = 10_usize.pow((max as f64).log10().floor() as u32);
    for step in [1, 2, 4, 5, 10] {
        let top = step * mag;
        if top >= max {
            return top;
        }
    }
    10 * mag
}

fn trend_section(b: &mut String, h: &History, since: Option<time::OffsetDateTime>) {
    let points = history::trend(h, GroupBy::Severity, since);
    b.push_str(
        "<section aria-labelledby=\"trend-h\">\n<h2 id=\"trend-h\">Open findings per run</h2>\n",
    );
    if points.is_empty() {
        b.push_str("<p class=\"muted\">No runs in this range.</p>\n</section>\n");
        return;
    }
    let present: Vec<Severity> = SEVERITIES
        .into_iter()
        .filter(|s| {
            points
                .iter()
                .any(|p| p.groups.get(&label(s)).copied().unwrap_or(0) > 0)
        })
        .collect();
    b.push_str("<ul class=\"legend\">");
    for s in &present {
        let _ = write!(
            b,
            "<li><span class=\"swatch {}\"></span>{}</li>",
            sev_class(*s),
            label(s)
        );
    }
    if points.iter().any(|p| p.gap) {
        b.push_str("<li><span class=\"gapkey\"></span>gap run (part of the fleet unread)</li>");
    }
    b.push_str("</ul>\n");

    let (w, hgt) = (960.0_f64, 280.0_f64);
    let (left, right, top, bottom) = (40.0, 16.0, 12.0, 40.0);
    let plot_w = w - left - right;
    let plot_h = hgt - top - bottom;
    let max = nice_max(points.iter().map(|p| p.open).max().unwrap_or(0));
    let times: Vec<i64> = points
        .iter()
        .map(|p| history::parse_time(&p.at).map_or(0, |t| t.unix_timestamp()))
        .collect();
    let (t0, t1) = (
        times.iter().copied().min().unwrap_or(0),
        times.iter().copied().max().unwrap_or(0),
    );
    let n = points.len() as f64;
    let bar = (plot_w / n * 0.6).clamp(2.0, 24.0);
    let x_of = |t: i64| {
        if t1 == t0 {
            left + plot_w / 2.0
        } else {
            left + bar / 2.0 + (t - t0) as f64 / (t1 - t0) as f64 * (plot_w - bar)
        }
    };
    let y_of = |v: f64| top + plot_h - v / max as f64 * plot_h;
    let _ = writeln!(
        b,
        "<figure class=\"chart scroll\"><svg viewBox=\"0 0 {w} {hgt}\" role=\"img\" aria-label=\"Open findings per run, stacked by severity\">"
    );
    for i in 0..=4 {
        let v = max as f64 * f64::from(i) / 4.0;
        let y = y_of(v);
        let _ = writeln!(
            b,
            "<line class=\"{}\" x1=\"{left}\" x2=\"{}\" y1=\"{y:.1}\" y2=\"{y:.1}\"/>\
             <text class=\"tick\" x=\"{}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            if i == 0 { "axis" } else { "grid" },
            w - right,
            left - 6.0,
            y + 4.0,
            v.round()
        );
    }
    // Hairline gap of the surface colour between stacked segments.
    let gap = 2.0;
    for (p, t) in points.iter().zip(&times) {
        let x = x_of(*t) - bar / 2.0;
        let mut base = 0.0;
        let mut tip = vec![format!("{} · {} open", day(&p.at), p.open)];
        let stacked: Vec<(Severity, usize)> = present
            .iter()
            .map(|s| (*s, p.groups.get(&label(s)).copied().unwrap_or(0)))
            .filter(|(_, c)| *c > 0)
            .collect();
        let last = stacked.len().saturating_sub(1);
        for (i, (s, count)) in stacked.iter().enumerate() {
            let y_bottom = y_of(base);
            let y_top = y_of(base + *count as f64);
            let hgt_seg = (y_bottom - y_top - if i == 0 { 0.0 } else { gap }).max(1.0);
            let y = y_bottom - hgt_seg - if i == 0 { 0.0 } else { gap };
            let radius = if i == last {
                (bar / 2.0).min(4.0).min(hgt_seg)
            } else {
                0.0
            };
            if radius > 0.0 {
                // Rounded data-end, square at the stack.
                let _ = writeln!(
                    b,
                    "<path class=\"{c}{g}\" d=\"M{x:.1},{yb:.1}V{yt:.1}a{r},{r} 0 0 1 {r},-{r}H{x2:.1}a{r},{r} 0 0 1 {r},{r}V{yb:.1}Z\"/>",
                    c = sev_class(*s),
                    g = if p.gap { " gap" } else { "" },
                    yb = y + hgt_seg,
                    yt = y + radius,
                    r = radius,
                    x2 = x + bar - radius,
                );
            } else {
                let _ = writeln!(
                    b,
                    "<rect class=\"{}{}\" x=\"{x:.1}\" y=\"{y:.1}\" width=\"{bar:.1}\" height=\"{hgt_seg:.1}\"/>",
                    sev_class(*s),
                    if p.gap { " gap" } else { "" }
                );
            }
            tip.push(format!("{}: {count}", label(s)));
            base += *count as f64;
        }
        if p.gap {
            tip.push("gap run: part of the fleet unread".to_string());
            let _ = writeln!(
                b,
                "<rect class=\"gapmark\" x=\"{:.1}\" y=\"{:.1}\" width=\"{bar:.1}\" height=\"3\"/>",
                x,
                top + plot_h + 4.0
            );
        }
        // A hit target taller and wider than the column.
        let slot = (plot_w / n).max(bar + 4.0);
        let _ = writeln!(
            b,
            "<rect class=\"hit\" x=\"{:.1}\" y=\"{top}\" width=\"{slot:.1}\" height=\"{plot_h}\" tabindex=\"0\" data-tip=\"{}\"/>",
            x_of(*t) - slot / 2.0,
            tip.iter().map(|t| esc(t)).collect::<Vec<_>>().join("&#10;")
        );
    }
    // Dates: first, last, and the middle when there is room.
    let mut labelled = vec![0, points.len() - 1];
    if points.len() > 2 {
        labelled.insert(1, points.len() / 2);
    }
    labelled.dedup();
    for i in labelled {
        let anchor = if points.len() == 1 {
            "middle"
        } else if i == 0 {
            "start"
        } else if i == points.len() - 1 {
            "end"
        } else {
            "middle"
        };
        let x = match anchor {
            "start" => left,
            "end" => w - right,
            _ => x_of(times[i]),
        };
        let _ = writeln!(
            b,
            "<text class=\"tick\" x=\"{x:.1}\" y=\"{}\" text-anchor=\"{anchor}\">{}</text>",
            hgt - 12.0,
            esc(day(&points[i].at))
        );
    }
    b.push_str("</svg></figure>\n<details><summary>Table view</summary>\n<div class=\"scroll\"><table><thead><tr><th>Run</th><th>Date</th><th class=\"num\">Open</th>");
    for s in &present {
        let _ = write!(b, "<th class=\"num\">{}</th>", label(s));
    }
    b.push_str("</tr></thead><tbody>\n");
    for p in &points {
        let _ = write!(
            b,
            "<tr><td><code>{}</code>{}</td><td>{}</td><td class=\"num\">{}</td>",
            esc(&p.run),
            if p.gap {
                " <span class=\"tag\">gap</span>"
            } else {
                ""
            },
            esc(&p.at),
            p.open
        );
        for s in &present {
            let _ = write!(
                b,
                "<td class=\"num\">{}</td>",
                p.groups.get(&label(s)).copied().unwrap_or(0)
            );
        }
        b.push_str("</tr>\n");
    }
    b.push_str("</tbody></table></div></details>\n</section>\n");
}

fn sev_cell(e: &Entry) -> String {
    let mut s = format!(
        "<span class=\"swatch {}\"></span>{}",
        sev_class(e.severity),
        label(&e.severity)
    );
    if let Some(o) = e.ssvc {
        let _ = write!(s, " <span class=\"tag\">SSVC {}</span>", esc(o.label()));
    }
    s
}

fn finding_cells(e: &Entry, url: &str) -> String {
    format!(
        "<td><a href=\"{u}\">{a}</a></td><td><code>{p}@{v}</code></td><td>{r}</td><td>{s}</td>",
        a = esc(&e.key.advisory),
        u = esc(url),
        p = esc(&e.key.package),
        v = esc(&e.key.version),
        r = esc(&e.key.repo),
        s = sev_cell(e)
    )
}

fn more(b: &mut String, total: usize) {
    if total > MAX_ROWS {
        let _ = writeln!(
            b,
            "<p class=\"muted\">…and {} more; `fleetreach history age -f json` lists them all.</p>",
            total - MAX_ROWS
        );
    }
}

fn breach_section(b: &mut String, queued: &[Queued<'_>], policy: &SlaPolicy) {
    b.push_str("<section aria-labelledby=\"sla-h\">\n<h2 id=\"sla-h\">Past SLA</h2>\n");
    if policy.is_empty() {
        b.push_str("<p class=\"muted\">No <code>[settings.sla]</code> given (<code>-c fleet.toml</code>), so no deadlines.</p>\n</section>\n");
        return;
    }
    let over: Vec<&Queued<'_>> = queued.iter().filter(|q| q.overdue_days.is_some()).collect();
    if over.is_empty() {
        b.push_str("<p><span class=\"status good\" aria-hidden=\"true\">✓</span>No open finding is past its deadline.</p>\n</section>\n");
        return;
    }
    b.push_str("<div class=\"scroll\"><table><thead><tr><th>Advisory</th><th>Package</th><th>Repo</th><th>Severity</th><th>Owner</th><th>Due</th><th class=\"num\">Overdue (days)</th></tr></thead><tbody>\n");
    for q in over.iter().take(MAX_ROWS) {
        let _ = writeln!(
            b,
            "<tr>{}<td>{}</td><td>{}</td><td class=\"num\">{:.1}</td></tr>",
            finding_cells(q.entry, &q.url),
            esc(q.entry.owner.as_deref().unwrap_or("-")),
            q.due
                .map_or(String::new(), |d| esc(day(&history::format_time(d)))),
            q.overdue_days.unwrap_or(0.0)
        );
    }
    b.push_str("</tbody></table></div>\n");
    more(b, over.len());
    b.push_str("</section>\n");
}

fn owner_section(b: &mut String, queued: &[Queued<'_>], policy: &SlaPolicy) {
    b.push_str(
        "<section aria-labelledby=\"owners-h\">\n<h2 id=\"owners-h\">Queues by owner</h2>\n",
    );
    let mut by_owner: BTreeMap<Option<&str>, Vec<&Queued<'_>>> = BTreeMap::new();
    for q in queued {
        by_owner
            .entry(q.entry.owner.as_deref())
            .or_default()
            .push(q);
    }
    if by_owner.is_empty() {
        b.push_str("<p><span class=\"status good\" aria-hidden=\"true\">✓</span>Nothing open.</p>\n</section>\n");
        return;
    }
    // Named owners first, the unowned last.
    let mut owners: Vec<(Option<&str>, Vec<&Queued<'_>>)> = by_owner.into_iter().collect();
    owners.sort_by_key(|(o, _)| (o.is_none(), o.map(str::to_string)));
    for (owner, items) in owners {
        let overdue = items.iter().filter(|q| q.overdue_days.is_some()).count();
        let _ = writeln!(
            b,
            "<details open><summary><strong>{}</strong> · {} open{}</summary>",
            esc(owner.unwrap_or("(no owner)")),
            items.len(),
            if overdue > 0 {
                format!(", <span class=\"status critical\" aria-hidden=\"true\">!</span>{overdue} past SLA")
            } else {
                String::new()
            }
        );
        let _ = writeln!(
            b,
            "<div class=\"scroll\"><table><thead><tr><th>Advisory</th><th>Package</th><th>Repo</th><th>Severity</th>{}<th>First seen</th><th class=\"num\">Age (days)</th></tr></thead><tbody>",
            if policy.is_empty() { "" } else { "<th>Due</th>" }
        );
        for q in items.iter().take(MAX_ROWS) {
            let due = if policy.is_empty() {
                String::new()
            } else {
                format!(
                    "<td>{}{}</td>",
                    q.due
                        .map_or("-".to_string(), |d| esc(day(&history::format_time(d)))),
                    if q.overdue_days.is_some() {
                        " <span class=\"tag over\">overdue</span>"
                    } else {
                        ""
                    }
                )
            };
            let _ = writeln!(
                b,
                "<tr>{}{due}<td>{}</td><td class=\"num\">{:.1}</td></tr>",
                finding_cells(q.entry, &q.url),
                esc(day(&q.entry.first_seen)),
                q.age_days
            );
        }
        b.push_str("</tbody></table></div>\n");
        more(b, items.len());
        b.push_str("</details>\n");
    }
    b.push_str("</section>\n");
}

fn campaign_section(b: &mut String, rows: &[serde_json::Value]) {
    b.push_str("<section aria-labelledby=\"fix-h\">\n<h2 id=\"fix-h\">Fix campaigns</h2>\n");
    if rows.is_empty() {
        b.push_str("<p class=\"muted\">No <code>fleetreach/*</code> pull or merge requests.</p>\n</section>\n");
        return;
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in rows {
        *counts
            .entry(r["state"].as_str().unwrap_or("UNKNOWN").to_string())
            .or_default() += 1;
    }
    b.push_str("<p>");
    let summary: Vec<String> = counts
        .iter()
        .map(|(s, n)| format!("{n} {}", esc(&s.to_ascii_lowercase())))
        .collect();
    b.push_str(&summary.join(" · "));
    b.push_str("</p>\n<div class=\"scroll\"><table><thead><tr><th>Repo</th><th>Request</th><th>Branch</th><th>State</th></tr></thead><tbody>\n");
    for r in rows.iter().take(MAX_ROWS) {
        let s = |k: &str| r[k].as_str().unwrap_or_default();
        let title = if s("title").is_empty() {
            s("branch")
        } else {
            s("title")
        };
        let link = if s("url").starts_with("https://") {
            format!("<a href=\"{}\">{}</a>", esc(s("url")), esc(title))
        } else {
            esc(title)
        };
        let _ = writeln!(
            b,
            "<tr><td>{}</td><td>{link}</td><td><code>{}</code></td><td><span class=\"tag\">{}</span></td></tr>",
            esc(s("repo")),
            esc(s("branch")),
            esc(&s("state").to_ascii_lowercase())
        );
    }
    b.push_str("</tbody></table></div>\n");
    more(b, rows.len());
    b.push_str("</section>\n");
}

fn mttr_section(b: &mut String, rows: &[history::Mttr]) {
    b.push_str(
        "<section aria-labelledby=\"mttr-h\">\n<h2 id=\"mttr-h\">Time to fix by severity</h2>\n",
    );
    if rows.is_empty() {
        b.push_str("<p class=\"muted\">No findings yet.</p>\n</section>\n");
        return;
    }
    b.push_str("<div class=\"scroll\"><table><thead><tr><th>Severity</th><th class=\"num\">Fixed</th><th class=\"num\">Mean (days)</th><th class=\"num\">Median (days)</th><th class=\"num\">Still open</th></tr></thead><tbody>\n");
    let rank = |g: &str| SEVERITIES.iter().position(|s| label(s) == g).unwrap_or(9);
    let mut rows: Vec<&history::Mttr> = rows.iter().collect();
    rows.sort_by_key(|r| rank(&r.group));
    for r in rows {
        let (mean, median) = if r.fixed == 0 {
            ("-".to_string(), "-".to_string())
        } else {
            (
                format!("{:.1}", r.mean_days),
                format!("{:.1}", r.median_days),
            )
        };
        let _ = writeln!(
            b,
            "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{mean}</td><td class=\"num\">{median}</td><td class=\"num\">{}</td></tr>",
            esc(&r.group),
            r.fixed,
            r.open
        );
    }
    b.push_str("</tbody></table></div>\n</section>\n");
}

/// Severity is ordinal, so one blue ramp (validated light and dark as an ordinal ramp);
/// red is kept for the past-SLA status, always with its `!` icon and a label.
const CSS: &str = r#"
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);
--s-low:#86b6ef;--s-medium:#5598e7;--s-high:#256abf;--s-critical:#104281;--s-unknown:#c3c2b7;
--critical:#d03b3b;--good:#0ca30c;--warning:#fab219}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;
--ink:#f0efec;--ink-2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);
--s-low:#184f95;--s-medium:#2a78d6;--s-high:#6da7ec;--s-critical:#b7d3f6;--s-unknown:#5d5c57}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink-2:#c3c2b7;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);
--s-low:#184f95;--s-medium:#2a78d6;--s-high:#6da7ec;--s-critical:#b7d3f6;--s-unknown:#5d5c57}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:0 0 12px}
.meta,.muted,footer{color:var(--ink-2)}footer{margin-top:32px;font-size:13px}
section{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-top:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;background:none;border:0;padding:0}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.tile .label{color:var(--ink-2);font-size:13px}.tile .value{font-size:28px;font-weight:600}
.tile.hero .value{font-size:48px;line-height:1.1}.tile .value.muted{font-size:16px;font-weight:400;padding-top:10px}
.notice{border:1px solid var(--border);border-left:4px solid var(--warning);background:var(--surface);border-radius:8px;padding:10px 14px}
.icon,.status{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;font-size:12px;font-weight:700;margin-right:6px;vertical-align:2px}
.icon{background:var(--warning);color:#0b0b0b}.status.critical{background:var(--critical);color:#fff}.status.good{background:var(--good);color:#fff}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;list-style:none;padding:0;margin:0 0 8px;color:var(--ink-2);font-size:13px}
.swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.gapkey{display:inline-block;width:12px;height:3px;background:var(--muted);margin-right:6px;vertical-align:3px}
.s-critical{background:var(--s-critical);fill:var(--s-critical)}.s-high{background:var(--s-high);fill:var(--s-high)}
.s-medium{background:var(--s-medium);fill:var(--s-medium)}.s-low{background:var(--s-low);fill:var(--s-low)}
.s-unknown{background:var(--s-unknown);fill:var(--s-unknown)}
.chart{margin:0}.chart svg{width:100%;min-width:720px;height:auto;display:block}
svg .grid{stroke:var(--grid);stroke-width:1}svg .axis{stroke:var(--axis);stroke-width:1}
svg .tick{fill:var(--muted);font-size:14px;font-variant-numeric:tabular-nums}
svg .gap{opacity:.55}svg .gapmark{fill:var(--muted)}
svg .hit{fill:transparent;outline:none}svg .hit:hover,svg .hit:focus{fill:var(--ink);fill-opacity:.05}
#tip{position:fixed;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--border);
border-radius:8px;padding:8px 10px;font-size:13px;white-space:pre-line;box-shadow:0 4px 16px rgba(0,0,0,.12);z-index:10}
details{margin-top:8px}summary{cursor:pointer;color:var(--ink-2)}details[open]>summary{margin-bottom:8px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid);vertical-align:top;white-space:nowrap}
td code{word-break:normal}
th{color:var(--ink-2);font-weight:600;white-space:nowrap}
.num{text-align:right;font-variant-numeric:tabular-nums}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;word-break:break-all}
a{color:inherit;text-decoration-color:var(--muted)}
.tag{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:0 8px;font-size:12px;color:var(--ink-2)}
.tag.over{border-color:var(--critical);color:var(--ink)}
@media (forced-colors:active){svg rect,svg path{forced-color-adjust:none}}
"#;

/// The hover and focus layer for the trend chart.
const SCRIPT: &str = r#"
(function(){var tip=document.getElementById('tip');
function show(e){var t=e.target.getAttribute('data-tip');if(!t)return;tip.textContent=t;tip.hidden=false;
var r=e.clientX!==undefined&&e.type!=='focus'?{x:e.clientX,y:e.clientY}:(function(){var b=e.target.getBoundingClientRect();return{x:b.left+b.width/2,y:b.top}})();
var w=tip.offsetWidth,x=Math.min(r.x+12,window.innerWidth-w-8);tip.style.left=Math.max(8,x)+'px';tip.style.top=Math.max(8,r.y-tip.offsetHeight-12)+'px'}
function hide(){tip.hidden=true}
document.querySelectorAll('[data-tip]').forEach(function(el){el.addEventListener('mousemove',show);el.addEventListener('mouseleave',hide);
el.addEventListener('focus',show);el.addEventListener('blur',hide)})})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_and_attributes() {
        assert_eq!(
            esc("<a href=\"x\" onclick='y'>&</a>"),
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;"
        );
        assert_eq!(esc("a\u{1b}[2Jb"), "a\u{fffd}[2Jb");
    }

    #[test]
    fn axis_maximums_are_round() {
        assert_eq!(nice_max(0), 4);
        assert_eq!(nice_max(7), 10);
        assert_eq!(nice_max(13), 20);
        assert_eq!(nice_max(41), 50);
        assert_eq!(nice_max(260), 400);
    }
}
