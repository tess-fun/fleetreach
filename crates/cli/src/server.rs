//! `fleetreach serve` (spec 16, row 6): the history report and the triage files over HTTP.
//!
//! No database: every page reads the history directory and the triage files afresh, so a scan
//! that records a run, or a `git pull` of the triage directory, shows on the next request. The
//! one write is a triage decision, recorded exactly as `fleetreach triage set` records it (the
//! same checks, the same append-only log); committing it is left to the user.
//!
//! Who may do what:
//!
//! - Without `--trust-proxy` the server listens on a loopback address only, serves only
//!   loopback peers, and only requests whose `Host` is a loopback name, so a web page cannot
//!   reach it by rebinding a domain to 127.0.0.1. Decisions are recorded as `--by`, else git's
//!   `user.name`, else `$USER`.
//! - With `--trust-proxy IP` it serves only those addresses, and the reviewer is the identity
//!   header the proxy sends (`X-Forwarded-User` by default); a request without one is refused.
//! - A decision is posted with a token the server made at start and put in its own forms, and
//!   a post whose `Origin` is another site is refused, so a page elsewhere cannot post one.

use crate::hexenc::ToHex;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Form, Query, State as Shared};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use fleetreach_core::{Ecosystem, FleetReport, Occurrence, Severity};
use serde::Deserialize;

use crate::cli::fail;
use crate::config::{Config, VEX_JUSTIFICATIONS};
use crate::history::{self, SlaPolicy};
use crate::report_html::{esc, render, sev_class, Input, CSS, SCRIPT};
use crate::serve::ServeArgs;
use crate::triage::{self, Change, Decision, State};

/// What every request shares.
pub(crate) struct App {
    pub history_dir: PathBuf,
    pub triage_dir: PathBuf,
    pub policy: SlaPolicy,
    pub trust: Vec<IpAddr>,
    pub identity_header: HeaderName,
    /// The reviewer without a proxy; `None` when it cannot be told, which allows reading only.
    pub local_by: Option<String>,
    pub token: String,
    pub title: String,
    /// One decision is written at a time, so two posts to one file both reach its log.
    pub write: Mutex<()>,
    /// The history as last read, and the files it was read from: every page needs it, and
    /// reading it means inflating and parsing every snapshot.
    pub history: Mutex<Option<(Vec<FileStamp>, Arc<history::History>)>>,
}

/// A history file's name, size and modification time: when none of them changed, neither
/// did what reading the directory gives.
type FileStamp = (std::ffi::OsString, u64, Option<std::time::SystemTime>);

/// The history in `app.history_dir`, read again only when its files changed.
fn load_history(app: &App) -> Result<Arc<history::History>, String> {
    let stamps = history_stamps(&app.history_dir)?;
    let mut cached = app
        .history
        .lock()
        .map_err(|_| "the history cache is poisoned".to_string())?;
    if let Some((seen, h)) = cached.as_ref() {
        if *seen == stamps {
            return Ok(Arc::clone(h));
        }
    }
    let h = Arc::new(history::load(&app.history_dir)?);
    *cached = Some((stamps, Arc::clone(&h)));
    Ok(h)
}

/// The stamps of every file `history::load` reads: the snapshots and the index.
fn history_stamps(dir: &std::path::Path) -> Result<Vec<FileStamp>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut stamps: Vec<FileStamp> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.ends_with(".json.gz") || name == history::INDEX_FILE
        })
        .map(|e| {
            // Followed like `history::load` reads it, so a link's new target is a change.
            let meta = std::fs::metadata(e.path()).ok();
            (
                e.file_name(),
                meta.as_ref().map_or(0, std::fs::Metadata::len),
                meta.and_then(|m| m.modified().ok()),
            )
        })
        .collect();
    stamps.sort();
    Ok(stamps)
}

pub(crate) fn run(args: ServeArgs) -> u8 {
    if let Err(e) = check_listen(args.listen, &args.trust_proxy) {
        return fail(&e);
    }
    let config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    let identity_header = match HeaderName::try_from(args.identity_header.as_str()) {
        Ok(h) => h,
        Err(_) => {
            return fail(&format!(
                "--identity-header `{}` is not a header name",
                args.identity_header
            ))
        }
    };
    let token = match new_token() {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let local_by = if args.trust_proxy.is_empty() {
        match triage::who(args.by) {
            Ok(who) => Some(who),
            Err(e) => {
                eprintln!("warning: {e}; decisions cannot be recorded");
                None
            }
        }
    } else {
        None
    };
    let app = Arc::new(App {
        history_dir: args.history_dir,
        triage_dir: config.triage.dir.clone(),
        policy: config.sla.clone(),
        trust: args.trust_proxy,
        identity_header,
        local_by,
        token,
        title: args.title,
        write: Mutex::new(()),
        history: Mutex::new(None),
    });
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(&format!("cannot start the server: {e}")),
    };
    let addr = args.listen;
    let result: Result<(), String> = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("{addr}: {e}"))?;
        eprintln!(
            "serving http://{addr}/ (history {}, triage {})",
            app.history_dir.display(),
            app.triage_dir.display()
        );
        axum::serve(
            listener,
            router(app).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| e.to_string())
    });
    match result {
        Ok(()) => 0,
        Err(e) => fail(&e),
    }
}

/// No authentication of its own, so it only listens beyond loopback behind a named proxy.
pub(crate) fn check_listen(listen: SocketAddr, trust: &[IpAddr]) -> Result<(), String> {
    if trust.is_empty() && !listen.ip().is_loopback() {
        return Err(format!(
            "--listen {listen} is not a loopback address: serve has no login of its own, so \
             listen beyond this machine only behind a reverse proxy, named with --trust-proxy"
        ));
    }
    Ok(())
}

fn new_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("no random source for the form token: {e}"))?;
    Ok(bytes.to_hex())
}

pub(crate) fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/triage", get(triage_list))
        .route("/triage/decide", get(decide_form).post(decide))
        .route("/api/decisions", get(api_decisions))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app)
}

/// The policy every page carries: the one script that may run is the report's own chart
/// tooltip, allowed by its hash, so nothing a finding's text smuggles in can execute.
fn csp() -> &'static HeaderValue {
    static CSP: std::sync::OnceLock<HeaderValue> = std::sync::OnceLock::new();
    CSP.get_or_init(|| {
        use base64::Engine as _;
        use sha2::Digest as _;
        let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(SCRIPT));
        let policy = format!(
            "default-src 'none'; script-src 'sha256-{hash}'; style-src 'unsafe-inline'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        );
        HeaderValue::from_str(&policy).unwrap_or(HeaderValue::from_static("default-src 'none'"))
    })
}

/// A response with the headers every page carries: one hashed script, no framing, no caching.
fn respond(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CONTENT_SECURITY_POLICY, csp().clone());
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Not `no-referrer`: under it browsers send `Origin: null` on the server's own form
    // posts, which the same-origin check must refuse.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn html(status: StatusCode, body: String) -> Response {
    respond(status, "text/html; charset=utf-8", body)
}

fn refuse(status: StatusCode, why: &str) -> Response {
    respond(status, "text/plain; charset=utf-8", format!("{why}\n"))
}

/// A request turned away: its status and a plain-text reason.
pub(crate) struct Refusal(StatusCode, &'static str);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        refuse(self.0, self.1)
    }
}

/// The reviewer behind a request, or the response refusing it. `Ok(None)` is a local request
/// when no reviewer could be told: it may read, not write.
fn gate(app: &App, peer: SocketAddr, headers: &HeaderMap) -> Result<Option<String>, Refusal> {
    if app.trust.is_empty() {
        if !peer.ip().is_loopback() {
            return Err(Refusal(
                StatusCode::FORBIDDEN,
                "only this machine is served",
            ));
        }
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !loopback_host(host) {
            return Err(Refusal(
                StatusCode::FORBIDDEN,
                "the Host header is not a loopback name; open the page as localhost or 127.0.0.1",
            ));
        }
        return Ok(app.local_by.clone());
    }
    if !app.trust.contains(&peer.ip()) {
        return Err(Refusal(
            StatusCode::FORBIDDEN,
            "requests are taken only from the trusted proxy",
        ));
    }
    let who = headers
        .get(&app.identity_header)
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|w| !w.is_empty() && w.len() <= 256 && !w.chars().any(char::is_control));
    match who {
        Some(who) => Ok(Some(who.to_string())),
        None => Err(Refusal(
            StatusCode::UNAUTHORIZED,
            "the proxy sent no identity header; sign in through it",
        )),
    }
}

/// `localhost`, `127.0.0.1`, `[::1]` or another loopback address, with or without a port.
pub(crate) fn loopback_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, port))
                if port.is_empty() || port.strip_prefix(':').is_some_and(all_digits) =>
            {
                inside
            }
            _ => return false,
        }
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) if all_digits(port) => name,
            Some(_) => return false,
            None => host,
        }
    };
    name.eq_ignore_ascii_case("localhost")
        || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A form post from this server's own page: the token matches, and the browser does not say it
/// came from elsewhere.
fn same_site_post(app: &App, headers: &HeaderMap, token: &str) -> Result<(), Refusal> {
    let a = app.token.as_bytes();
    let b = token.as_bytes();
    let equal = a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0;
    if !equal {
        return Err(Refusal(
            StatusCode::FORBIDDEN,
            "the form is stale or not this server's; reload the page",
        ));
    }
    let text = |name: HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = text(HeaderName::from_static("sec-fetch-site")) {
        if !matches!(site, "same-origin" | "none") {
            return Err(Refusal(
                StatusCode::FORBIDDEN,
                "a cross-site post was refused",
            ));
        }
    }
    if let Some(origin) = text(header::ORIGIN) {
        let authority = origin.split_once("://").map_or("", |(_, a)| a);
        if text(header::HOST) != Some(authority) {
            return Err(Refusal(
                StatusCode::FORBIDDEN,
                "a post from another origin was refused",
            ));
        }
    }
    Ok(())
}

fn nav(who: Option<&str>) -> String {
    let who = match who {
        Some(w) => format!("signed in as <b>{}</b>", esc(w)),
        None => "read only (no reviewer known)".to_string(),
    };
    format!(
        "<nav class=\"serve\"><a href=\"/\">Overview</a> <a href=\"/triage\">Triage</a> \
         <span>{who}</span></nav>"
    )
}

const SERVE_CSS: &str = "nav.serve{display:flex;gap:1.2em;align-items:baseline;flex-wrap:wrap;\
padding:.6em 0;border-bottom:1px solid #8884;margin-bottom:1em}nav.serve span{margin-left:auto;\
opacity:.75}form.decide{display:grid;gap:.6em;max-width:40em}form.decide label{display:grid;gap:.2em}\
form.decide input,form.decide select,form.decide textarea{font:inherit;padding:.3em}\
.note{padding:.5em .8em;border-left:3px solid #2a7;background:#2a71}\
.error{padding:.5em .8em;border-left:3px solid #c33;background:#c331}\
form.filter{display:flex;gap:.6em;flex-wrap:wrap;margin:.6em 0}";

fn page(title: &str, nav: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n<style>{CSS}{SERVE_CSS}</style>\n</head>\n<body>\n<main>\n{nav}\n{body}\n</main>\n</body>\n</html>\n",
        esc(title)
    )
}

/// Run blocking file work off the async thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| Refusal(StatusCode::INTERNAL_SERVER_ERROR, "the request failed"))
}

async fn overview(
    Shared(app): Shared<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let who = match gate(&app, peer, &headers) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let result = blocking(move || {
        let h = load_history(&app)?;
        let nav = nav(who.as_deref());
        if h.snapshots.is_empty() {
            let body = format!(
                "<h1>{}</h1><p>No scan history in <code>{}</code> yet; record some with \
                 <code>fleetreach scan --history-dir</code>.</p>",
                esc(&app.title),
                esc(&app.history_dir.display().to_string())
            );
            return Ok(page(&app.title, &nav, &body));
        }
        Ok::<_, String>(render(&Input {
            title: &app.title,
            history: &h,
            policy: &app.policy,
            campaigns: None,
            at: history::now(),
            since: None,
            nav: Some(&format!("<style>{SERVE_CSS}</style>{nav}")),
        }))
    })
    .await;
    match result {
        Ok(Ok(body)) => html(StatusCode::OK, body),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(r) => r.into_response(),
    }
}

/// One finding of the newest run, across the repos it is in.
struct Row {
    advisory: String,
    aliases: Vec<String>,
    title: String,
    ecosystem: Ecosystem,
    package: String,
    severity: Severity,
    repos: BTreeSet<String>,
    set_aside: bool,
}

fn rows(report: &FleetReport) -> Vec<Row> {
    let mut by: BTreeMap<(String, Ecosystem, String), Row> = BTreeMap::new();
    let findings = report
        .vulnerabilities
        .iter()
        .map(|v| (v, false))
        .chain(report.set_aside.iter().map(|s| (&s.finding, true)));
    for (v, set_aside) in findings {
        for occ in &v.occurrences {
            let Occurrence::InRepo { repo, package, .. } = occ else {
                continue;
            };
            let row = by
                .entry((v.advisory_id.clone(), v.ecosystem, package.clone()))
                .or_insert_with(|| Row {
                    advisory: v.advisory_id.clone(),
                    aliases: v.aliases.clone(),
                    title: v.title.clone(),
                    ecosystem: v.ecosystem,
                    package: package.clone(),
                    severity: v.severity,
                    repos: BTreeSet::new(),
                    set_aside,
                });
            row.repos.insert(repo.0.clone());
            row.set_aside &= set_aside;
        }
    }
    let mut out: Vec<Row> = by.into_values().collect();
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.advisory.cmp(&b.advisory))
    });
    out
}

/// The decision on a finding: same ecosystem and package, and its advisory or one of the
/// aliases on either side.
fn decision_for<'a>(
    decisions: &'a [Decision],
    advisory: &str,
    aliases: &[String],
    ecosystem: Ecosystem,
    package: &str,
) -> Option<&'a Decision> {
    decisions.iter().find(|d| {
        d.ecosystem == ecosystem
            && d.package == package
            && (d.advisory == advisory
                || aliases.contains(&d.advisory)
                || d.aliases.iter().any(|a| a == advisory))
    })
}

fn ecosystem_label(e: Ecosystem) -> String {
    serde_json::to_value(e)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn decide_link(advisory: &str, ecosystem: Ecosystem, package: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("advisory", advisory)
        .append_pair("ecosystem", &ecosystem_label(ecosystem))
        .append_pair("package", package)
        .finish();
    format!("/triage/decide?{query}")
}

fn read_decisions(app: &App) -> Result<Vec<Decision>, String> {
    if app.triage_dir.exists() {
        triage::read_all(&app.triage_dir)
    } else {
        Ok(Vec::new())
    }
}

const STATES: [State; 6] = [
    State::Affected,
    State::InTriage,
    State::AcceptedRisk,
    State::FalsePositive,
    State::NotAffected,
    State::Fixed,
];

#[derive(Deserialize, Default)]
struct ListQuery {
    #[serde(default)]
    state: String,
    #[serde(default)]
    q: String,
}

async fn triage_list(
    Shared(app): Shared<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let who = match gate(&app, peer, &headers) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let result = blocking(move || -> Result<String, String> {
        let h = load_history(&app)?;
        let decisions = read_decisions(&app)?;
        let today = history::now().date();
        let rows = h
            .snapshots
            .last()
            .map(|s| rows(&s.report))
            .unwrap_or_default();
        let needle = query.q.trim().to_lowercase();
        let mut b = String::new();
        let _ = write!(
            b,
            "<h1>Triage</h1><p class=\"meta\">{} finding(s) in the newest run, {} decision(s) in \
             <code>{}</code>. Decisions are written as files; commit them to keep them.</p>",
            rows.len(),
            decisions.len(),
            esc(&app.triage_dir.display().to_string())
        );
        let _ = write!(
            b,
            "<form class=\"filter\" method=\"get\" action=\"/triage\"><select name=\"state\">"
        );
        let current = query.state.as_str();
        for (value, label) in std::iter::once(("", "every state"))
            .chain(std::iter::once(("undecided", "undecided")))
            .chain(STATES.iter().map(|s| (s.as_str(), s.as_str())))
        {
            let selected = if value == current { " selected" } else { "" };
            let _ = write!(b, "<option value=\"{value}\"{selected}>{label}</option>");
        }
        let _ = write!(
            b,
            "</select><input name=\"q\" placeholder=\"advisory, package or repo\" value=\"{}\">\
             <button>Filter</button></form>",
            esc(&query.q)
        );
        let _ = write!(
            b,
            "<div class=\"scroll\"><table><thead><tr><th>Severity</th><th>Advisory</th><th>Package</th><th>Repos</th>\
             <th>Decision</th><th>Assignee</th><th></th></tr></thead><tbody>"
        );
        let mut shown = 0usize;
        for r in &rows {
            let d = decision_for(&decisions, &r.advisory, &r.aliases, r.ecosystem, &r.package);
            let state = d.map(|d| d.state.as_str()).unwrap_or("undecided");
            if !current.is_empty() && current != state {
                continue;
            }
            let haystack = format!(
                "{} {} {}",
                r.advisory,
                r.package,
                r.repos.iter().cloned().collect::<Vec<_>>().join(" ")
            )
            .to_lowercase();
            if !needle.is_empty() && !haystack.contains(&needle) {
                continue;
            }
            shown += 1;
            let mut decision = esc(state);
            if d.is_some_and(|d| d.expired(today)) {
                decision.push_str(" <b>(expired)</b>");
            } else if r.set_aside {
                decision.push_str(" (set aside)");
            }
            let _ = write!(
                b,
                "<tr><td><span class=\"swatch {}\"></span>{}</td><td><code>{}</code><br><small>{}</small></td>\
                 <td>{} <small>({})</small></td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><a href=\"{}\">Decide</a></td></tr>",
                sev_class(r.severity),
                esc(&format!("{:?}", r.severity).to_lowercase()),
                esc(&r.advisory),
                esc(&r.title),
                esc(&r.package),
                esc(&ecosystem_label(r.ecosystem)),
                esc(&r.repos.iter().cloned().collect::<Vec<_>>().join(", ")),
                decision,
                esc(d.and_then(|d| d.assignee.as_deref()).unwrap_or("")),
                esc(&decide_link(&r.advisory, r.ecosystem, &r.package)),
            );
        }
        let _ = write!(b, "</tbody></table></div><p class=\"meta\">{shown} shown.</p>");
        let others: Vec<&Decision> = decisions
            .iter()
            .filter(|d| {
                !rows.iter().any(|r| {
                    decision_for(
                        std::slice::from_ref(*d),
                        &r.advisory,
                        &r.aliases,
                        r.ecosystem,
                        &r.package,
                    )
                    .is_some()
                })
            })
            .collect();
        if !others.is_empty() {
            let _ = write!(
                b,
                "<h2>Decisions on findings not in the newest run</h2><div class=\"scroll\"><table><thead><tr>\
                 <th>Advisory</th><th>Package</th><th>Decision</th><th></th></tr></thead><tbody>"
            );
            for d in others {
                let _ = write!(
                    b,
                    "<tr><td><code>{}</code></td><td>{} <small>({})</small></td><td>{}</td>\
                     <td><a href=\"{}\">Open</a></td></tr>",
                    esc(&d.advisory),
                    esc(&d.package),
                    esc(&ecosystem_label(d.ecosystem)),
                    esc(d.state.as_str()),
                    esc(&decide_link(&d.advisory, d.ecosystem, &d.package)),
                );
            }
            b.push_str("</tbody></table></div>");
        }
        Ok(page("Triage", &nav(who.as_deref()), &b))
    })
    .await;
    match result {
        Ok(Ok(body)) => html(StatusCode::OK, body),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(r) => r.into_response(),
    }
}

#[derive(Deserialize)]
struct FindingQuery {
    advisory: String,
    ecosystem: String,
    package: String,
    #[serde(default)]
    saved: Option<String>,
}

async fn decide_form(
    Shared(app): Shared<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<FindingQuery>,
) -> Response {
    let who = match gate(&app, peer, &headers) {
        Ok(w) => w,
        Err(r) => return r.into_response(),
    };
    let Ok(ecosystem) = triage::parse_ecosystem(&query.ecosystem) else {
        return refuse(StatusCode::BAD_REQUEST, "unknown ecosystem");
    };
    let result = blocking(move || -> Result<String, String> {
        let decisions = read_decisions(&app)?;
        let h = load_history(&app)?;
        let row = h.snapshots.last().and_then(|s| {
            rows(&s.report).into_iter().find(|r| {
                r.ecosystem == ecosystem
                    && r.package == query.package
                    && (r.advisory == query.advisory || r.aliases.contains(&query.advisory))
            })
        });
        let aliases = row.as_ref().map(|r| r.aliases.clone()).unwrap_or_default();
        let d = decision_for(
            &decisions,
            &query.advisory,
            &aliases,
            ecosystem,
            &query.package,
        );
        let notice = if query.saved.is_some() {
            "<p class=\"note\">Saved. The file is written; commit it to keep it.</p>"
        } else {
            ""
        };
        Ok(page(
            &query.advisory,
            &nav(who.as_deref()),
            &decide_body(
                &app,
                &query.advisory,
                ecosystem,
                &query.package,
                row.as_ref(),
                d,
                who.is_some(),
                notice,
            ),
        ))
    })
    .await;
    match result {
        Ok(Ok(body)) => html(StatusCode::OK, body),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(r) => r.into_response(),
    }
}

#[allow(clippy::too_many_arguments)]
fn decide_body(
    app: &App,
    advisory: &str,
    ecosystem: Ecosystem,
    package: &str,
    row: Option<&Row>,
    d: Option<&Decision>,
    can_write: bool,
    notice: &str,
) -> String {
    let mut b = String::new();
    let _ = write!(
        b,
        "<h1>{}</h1>{notice}<p>{} <small>({})</small></p>",
        esc(advisory),
        esc(package),
        esc(&ecosystem_label(ecosystem))
    );
    match row {
        Some(r) => {
            let _ = write!(
                b,
                "<p>{}</p><p class=\"meta\">Severity {}; in {}.</p>",
                esc(&r.title),
                esc(&format!("{:?}", r.severity).to_lowercase()),
                esc(&r.repos.iter().cloned().collect::<Vec<_>>().join(", "))
            );
        }
        None => b.push_str("<p class=\"meta\">Not in the newest run.</p>"),
    }
    if let Some(d) = d {
        let _ = write!(
            b,
            "<h2>Log</h2><div class=\"scroll\"><table><thead><tr><th>When</th><th>Who</th><th>State</th><th>Note</th></tr></thead><tbody>"
        );
        for entry in d.log.iter().rev() {
            let _ = write!(
                b,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&entry.at),
                esc(&entry.by),
                esc(entry.state.as_str()),
                esc(entry.note.as_deref().unwrap_or(""))
            );
        }
        b.push_str("</tbody></table></div>");
    }
    if !can_write {
        b.push_str("<p class=\"error\">No reviewer is known, so decisions cannot be recorded; start serve with --by.</p>");
        return b;
    }
    let current = d.map_or(State::InTriage, |d| d.state);
    let value = |v: Option<&str>| esc(v.unwrap_or(""));
    let _ = write!(
        b,
        "<h2>Decide</h2><form class=\"decide\" method=\"post\" action=\"/triage/decide\">\
         <input type=\"hidden\" name=\"token\" value=\"{}\">\
         <input type=\"hidden\" name=\"advisory\" value=\"{}\">\
         <input type=\"hidden\" name=\"ecosystem\" value=\"{}\">\
         <input type=\"hidden\" name=\"package\" value=\"{}\">\
         <input type=\"hidden\" name=\"aliases\" value=\"{}\">\
         <label>State<select name=\"state\">",
        esc(&app.token),
        esc(advisory),
        esc(&ecosystem_label(ecosystem)),
        esc(package),
        esc(&row.map(|r| r.aliases.join(",")).unwrap_or_default()),
    );
    for s in STATES {
        let selected = if s == current { " selected" } else { "" };
        let _ = write!(
            b,
            "<option value=\"{0}\"{selected}>{0}</option>",
            s.as_str()
        );
    }
    let _ = write!(
        b,
        "</select></label><label>Reason (required to set a finding aside)\
         <textarea name=\"reason\" rows=\"3\">{}</textarea></label>\
         <label>Justification<select name=\"justification\"><option value=\"\">none</option>",
        value(d.and_then(|d| d.reason.as_deref()))
    );
    let justification = d.and_then(|d| d.justification.as_deref());
    for j in VEX_JUSTIFICATIONS {
        let selected = if Some(j) == justification {
            " selected"
        } else {
            ""
        };
        let _ = write!(b, "<option value=\"{j}\"{selected}>{j}</option>");
    }
    let _ = write!(
        b,
        "</select></label><label>Assignee<input name=\"assignee\" value=\"{}\"></label>\
         <label>Expires (the last day it holds)<input name=\"expires\" type=\"date\" value=\"{}\"></label>\
         <label>Repos (comma-separated; empty keeps them, and a new decision covers the whole fleet)\
         <input name=\"repos\" value=\"{}\"></label><button>Record decision</button></form>",
        value(d.and_then(|d| d.assignee.as_deref())),
        value(d.and_then(|d| d.expires.as_deref())),
        esc(&d.map(|d| d.repos.join(", ")).unwrap_or_default()),
    );
    b
}

#[derive(Deserialize)]
struct DecideForm {
    token: String,
    advisory: String,
    ecosystem: String,
    package: String,
    state: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    justification: String,
    #[serde(default)]
    assignee: String,
    #[serde(default)]
    expires: String,
    #[serde(default)]
    repos: String,
    #[serde(default)]
    aliases: String,
}

fn given(s: &str) -> Option<String> {
    Some(s.trim().to_string()).filter(|s| !s.is_empty())
}

fn list(s: &str) -> Vec<String> {
    s.split(',').filter_map(given).collect()
}

async fn decide(
    Shared(app): Shared<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<DecideForm>,
) -> Response {
    let who = match gate(&app, peer, &headers) {
        Ok(Some(w)) => w,
        Ok(None) => {
            return refuse(
                StatusCode::FORBIDDEN,
                "no reviewer is known; start serve with --by",
            )
        }
        Err(r) => return r.into_response(),
    };
    if let Err(r) = same_site_post(&app, &headers, &form.token) {
        return r.into_response();
    }
    let Ok(ecosystem) = triage::parse_ecosystem(&form.ecosystem) else {
        return refuse(StatusCode::BAD_REQUEST, "unknown ecosystem");
    };
    let Ok(state) = serde_json::from_value::<State>(serde_json::json!(form.state)) else {
        return refuse(StatusCode::BAD_REQUEST, "unknown state");
    };
    let back = decide_link(&form.advisory, ecosystem, &form.package);
    let change = Change {
        advisory: form.advisory.trim().to_string(),
        ecosystem,
        package: form.package.trim().to_string(),
        state,
        reason: given(&form.reason),
        assignee: given(&form.assignee),
        expires: given(&form.expires),
        justification: given(&form.justification),
        aliases: list(&form.aliases),
        repos: list(&form.repos),
    };
    let result = blocking(move || {
        let mut change = change;
        // The advisory's other ids, from the newest run, so export can name them all.
        if let Some(latest) = load_history(&app)?.snapshots.last() {
            let found = rows(&latest.report).into_iter().find(|r| {
                r.ecosystem == change.ecosystem
                    && r.package == change.package
                    && (r.advisory == change.advisory || r.aliases.contains(&change.advisory))
            });
            for alias in found.map(|r| r.aliases).unwrap_or_default() {
                if !change.aliases.contains(&alias) && alias != change.advisory {
                    change.aliases.push(alias);
                }
            }
        }
        let _one = app
            .write
            .lock()
            .map_err(|_| "a previous write failed".to_string())?;
        triage::record(&app.triage_dir, change, who)
    })
    .await;
    match result {
        Ok(Ok(_)) => Redirect::to(&format!("{back}&saved=1")).into_response(),
        Ok(Err(e)) => html(
            StatusCode::BAD_REQUEST,
            page(
                "Not recorded",
                "",
                &format!(
                    "<h1>Not recorded</h1><p class=\"error\">{}</p><p><a href=\"{}\">Back to the finding</a></p>",
                    esc(&e),
                    esc(&back)
                ),
            ),
        ),
        Err(r) => r.into_response(),
    }
}

async fn api_decisions(
    Shared(app): Shared<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = gate(&app, peer, &headers) {
        return r.into_response();
    }
    let result = blocking(move || {
        read_decisions(&app)
            .and_then(|d| serde_json::to_string_pretty(&d).map_err(|e| e.to_string()))
    })
    .await;
    match result {
        Ok(Ok(body)) => respond(StatusCode::OK, "application/json", body),
        Ok(Err(e)) => refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(r) => r.into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::{Read, Write};

    /// One npm finding in repo `web`, with markup in its title to check escaping.
    fn report() -> FleetReport {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "provenance": {
                "tool_version": "t", "rustsec_crate_version": "t", "db_commit": null,
                "db_timestamp": null, "host_os": "t", "host_arch": "t", "generated_at": "t",
            },
            "summary": {
                "repos_scanned": 1, "repos_errored": 0, "vuln_count": 1, "warn_count": 0,
                "max_severity": "high", "stale_ignores": [],
            },
            "vulnerabilities": [{
                "advisory_id": "GHSA-test-0001", "aliases": ["CVE-2026-0001"], "ecosystem": "npm",
                "title": "<script>alert(1)</script> in lodash", "severity": "high", "url": null,
                "occurrences": [{
                    "kind": "in_repo", "repo": "web", "package": "lodash", "installed": "4.17.20",
                    "patched": [">=4.17.21"], "dependency_kind": "direct",
                }],
            }],
            "warnings": [], "outcomes": [],
        }))
        .unwrap()
    }

    struct Server {
        addr: SocketAddr,
        dir: tempfile::TempDir,
        token: String,
    }

    fn start(trust: Vec<IpAddr>, local_by: Option<&str>) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let history_dir = dir.path().join("history");
        history::record(&history_dir, &report(), Vec::new(), 1, None, Vec::new()).unwrap();
        let token = new_token().unwrap();
        let app = Arc::new(App {
            history_dir,
            triage_dir: dir.path().join("triage"),
            policy: SlaPolicy::default(),
            trust,
            identity_header: HeaderName::from_static("x-forwarded-user"),
            local_by: local_by.map(str::to_string),
            token: token.clone(),
            title: "Fleet security report".to_string(),
            write: Mutex::new(()),
            history: Mutex::new(None),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let service = router(app).into_make_service_with_connect_info::<SocketAddr>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, service).await.unwrap();
            });
        });
        Server { addr, dir, token }
    }

    struct Reply {
        status: u16,
        head: String,
        body: String,
    }

    fn send(s: &Server, method: &str, path: &str, headers: &[(&str, String)], body: &str) -> Reply {
        let mut stream = std::net::TcpStream::connect(s.addr).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
        let mut host = false;
        for (k, v) in headers {
            host |= k.eq_ignore_ascii_case("host");
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !host {
            req.push_str(&format!("Host: {}\r\n", s.addr));
        }
        if method == "POST" {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply {
            status,
            head: head.to_string(),
            body: body.to_string(),
        }
    }

    fn get(s: &Server, path: &str) -> Reply {
        send(s, "GET", path, &[], "")
    }

    fn form(s: &Server, fields: &[(&str, &str)]) -> String {
        let mut f = form_urlencoded::Serializer::new(String::new());
        f.append_pair("token", &s.token)
            .append_pair("advisory", "GHSA-test-0001")
            .append_pair("ecosystem", "npm")
            .append_pair("package", "lodash");
        for (k, v) in fields {
            f.append_pair(k, v);
        }
        f.finish()
    }

    fn post(s: &Server, body: &str, extra: &[(&str, String)]) -> Reply {
        let mut headers = vec![("Origin", format!("http://{}", s.addr))];
        headers.extend(extra.iter().cloned());
        send(s, "POST", "/triage/decide", &headers, body)
    }

    fn decision_file(s: &Server) -> std::path::PathBuf {
        s.dir.path().join("triage/GHSA-test-0001/npm-lodash.toml")
    }

    #[test]
    fn pages_render_and_escape_what_the_report_says() {
        let s = start(Vec::new(), Some("tester"));
        let home = get(&s, "/");
        assert_eq!(home.status, 200);
        assert!(home.body.contains("Fleet security report"));
        assert!(home.body.contains("signed in as <b>tester</b>"));
        assert!(home
            .head
            .to_lowercase()
            .contains("content-security-policy: default-src 'none'"));
        assert!(home
            .head
            .to_lowercase()
            .contains("referrer-policy: same-origin"));
        // The one script allowed is the report's own, by the hash browsers compute for it.
        assert!(home
            .head
            .contains("script-src 'sha256-o6Dlf5v4C411pDWWI2UFWYh6SVLSNbR3v4OUnjd9Z5E='"));
        assert_eq!(home.body.matches("<script>").count(), 1);
        let list = get(&s, "/triage");
        assert_eq!(list.status, 200);
        assert!(list.body.contains("GHSA-test-0001") && list.body.contains("undecided"));
        assert!(!list.body.contains("<script>alert"));
        assert!(list.body.contains("&lt;script&gt;"));
        let decide = get(
            &s,
            "/triage/decide?advisory=GHSA-test-0001&ecosystem=npm&package=lodash",
        );
        assert_eq!(decide.status, 200);
        assert!(decide.body.contains(&s.token));
        assert!(decide.body.contains("CVE-2026-0001"));
        assert_eq!(get(&s, "/api/decisions").body.trim(), "[]");
        assert_eq!(get(&s, "/healthz").body, "ok");
        assert_eq!(
            get(&s, "/triage/decide?advisory=x&ecosystem=nope&package=y").status,
            400
        );
    }

    #[test]
    fn a_new_run_shows_without_a_restart() {
        let s = start(Vec::new(), Some("tester"));
        assert!(get(&s, "/").body.contains("from 1 run(s)"));
        assert!(get(&s, "/triage").body.contains("GHSA-test-0001"));
        // Read again from the cache while nothing changed.
        assert!(get(&s, "/").body.contains("from 1 run(s)"));
        let mut fixed = report();
        fixed.vulnerabilities.clear();
        fixed.summary.vuln_count = 0;
        let history_dir = s.dir.path().join("history");
        history::record(&history_dir, &fixed, Vec::new(), 1, None, Vec::new()).unwrap();
        assert!(get(&s, "/").body.contains("from 2 run(s)"));
        assert!(!get(&s, "/triage").body.contains("GHSA-test-0001"));
    }

    #[test]
    fn a_post_records_the_decision_with_the_reviewer() {
        let s = start(Vec::new(), Some("tester"));
        let body = form(
            &s,
            &[
                ("state", "accepted_risk"),
                ("reason", "only reachable from an admin tool"),
                ("expires", "2027-01-31"),
                ("repos", "web"),
            ],
        );
        let r = post(&s, &body, &[]);
        assert_eq!(r.status, 303, "{}", r.body);
        assert!(r.head.contains("saved=1"));
        let text = std::fs::read_to_string(decision_file(&s)).unwrap();
        assert!(text.contains("state = \"accepted_risk\""));
        assert!(text.contains("by = \"tester\""));
        assert!(text.contains("aliases = [\"CVE-2026-0001\"]"));
        assert!(get(&s, "/triage").body.contains("accepted_risk"));
        assert!(get(&s, "/api/decisions")
            .body
            .contains("\"by\": \"tester\""));
        // A second decision appends to the log.
        post(&s, &form(&s, &[("state", "affected")]), &[]);
        let text = std::fs::read_to_string(decision_file(&s)).unwrap();
        assert_eq!(text.matches("[[log]]").count(), 2);
    }

    #[test]
    fn posts_from_elsewhere_or_invalid_ones_write_nothing() {
        let s = start(Vec::new(), Some("tester"));
        let ok = |fields: &[(&str, &str)]| form(&s, fields);
        let mut stale = ok(&[("state", "affected")]);
        stale = stale.replacen(&s.token, "0000", 1);
        assert_eq!(post(&s, &stale, &[]).status, 403);
        let other = [("Origin", "https://evil.example".to_string())];
        let r = send(
            &s,
            "POST",
            "/triage/decide",
            &other,
            &ok(&[("state", "affected")]),
        );
        assert_eq!(r.status, 403);
        let null = [("Origin", "null".to_string())];
        let r = send(
            &s,
            "POST",
            "/triage/decide",
            &null,
            &ok(&[("state", "affected")]),
        );
        assert_eq!(r.status, 403);
        let cross = [("Sec-Fetch-Site", "cross-site".to_string())];
        assert_eq!(post(&s, &ok(&[("state", "affected")]), &cross).status, 403);
        let r = post(&s, &ok(&[("state", "accepted_risk")]), &[]);
        assert_eq!(r.status, 400);
        assert!(r.body.contains("needs a `reason`"));
        assert_eq!(post(&s, &ok(&[("state", "gone")]), &[]).status, 400);
        let r = post(&s, &ok(&[("state", "affected"), ("expires", "soon")]), &[]);
        assert_eq!(r.status, 400);
        assert!(!decision_file(&s).exists());
    }

    #[test]
    fn a_foreign_host_name_is_refused() {
        let s = start(Vec::new(), Some("tester"));
        let r = send(&s, "GET", "/", &[("Host", "evil.example".to_string())], "");
        assert_eq!(r.status, 403);
        let r = send(
            &s,
            "GET",
            "/",
            &[("Host", format!("localhost:{}", s.addr.port()))],
            "",
        );
        assert_eq!(r.status, 200);
    }

    #[test]
    fn without_a_reviewer_pages_are_read_only() {
        let s = start(Vec::new(), None);
        assert!(get(&s, "/").body.contains("read only"));
        assert!(!get(
            &s,
            "/triage/decide?advisory=GHSA-test-0001&ecosystem=npm&package=lodash"
        )
        .body
        .contains("name=\"token\""));
        assert_eq!(
            post(&s, &form(&s, &[("state", "affected")]), &[]).status,
            403
        );
        assert!(!decision_file(&s).exists());
    }

    #[test]
    fn behind_a_proxy_the_identity_header_is_the_reviewer() {
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        let s = start(vec![localhost], None);
        assert_eq!(get(&s, "/").status, 401);
        let alice = [("X-Forwarded-User", "alice@example.com".to_string())];
        let home = send(&s, "GET", "/", &alice, "");
        assert_eq!(home.status, 200);
        assert!(home.body.contains("alice@example.com"));
        // Behind a proxy the Host header is the public name.
        let mut public = alice.to_vec();
        public.push(("Host", "fleet.example.com".to_string()));
        public.push(("Origin", "https://fleet.example.com".to_string()));
        let body = form(&s, &[("state", "in_triage")]);
        assert_eq!(
            send(&s, "POST", "/triage/decide", &public, &body).status,
            303
        );
        let text = std::fs::read_to_string(decision_file(&s)).unwrap();
        assert!(text.contains("by = \"alice@example.com\""));

        let elsewhere = start(vec!["10.0.0.9".parse().unwrap()], None);
        assert_eq!(send(&elsewhere, "GET", "/", &alice, "").status, 403);
    }

    #[test]
    fn listening_beyond_loopback_needs_a_proxy() {
        let any: SocketAddr = "0.0.0.0:8484".parse().unwrap();
        assert!(check_listen(any, &[]).is_err());
        assert!(check_listen(any, &["10.0.0.9".parse().unwrap()]).is_ok());
        assert!(check_listen("127.0.0.1:8484".parse().unwrap(), &[]).is_ok());
        assert!(check_listen("[::1]:8484".parse().unwrap(), &[]).is_ok());
    }

    #[test]
    fn loopback_host_names() {
        for ok in [
            "localhost",
            "localhost:8484",
            "127.0.0.1:1",
            "[::1]:8484",
            "[::1]",
            "LOCALHOST",
        ] {
            assert!(loopback_host(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example",
            "localhost.evil.example",
            "127.0.0.1.nip.io",
            "[::1]x",
            "localhost:x",
        ] {
            assert!(!loopback_host(bad), "{bad}");
        }
    }
}
