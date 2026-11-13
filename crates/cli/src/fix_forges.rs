//! Pull requests on Gitea and Forgejo, Bitbucket Cloud and Data Center, and Azure DevOps, for
//! `fix apply --open-pr` (spec 16, row 5, phase B). GitHub and GitLab go through `gh` and
//! `glab` in [`crate::fix`]; these forges have no such CLI, so their REST APIs are called
//! directly, with the tokens [`crate::sources`] reads for listings.
//!
//! Every call goes through a `send` closure, so each forge's request shapes, paging and
//! states are tested without a server.

use serde_json::{json, Value};

use crate::forges::{encode_segment, Reply};

/// The forges this module speaks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gitea,
    Forgejo,
    Bitbucket,
    BitbucketServer,
    Azure,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Gitea => "gitea",
            Kind::Forgejo => "forgejo",
            Kind::Bitbucket => "bitbucket",
            Kind::BitbucketServer => "bitbucket-server",
            Kind::Azure => "azure",
        }
    }

    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    fn token_vars(self) -> &'static [&'static str] {
        match self {
            Kind::Gitea => &["GITEA_TOKEN"],
            Kind::Forgejo => &["FORGEJO_TOKEN", "GITEA_TOKEN"],
            Kind::Bitbucket => &["BITBUCKET_TOKEN"],
            Kind::BitbucketServer => &["BITBUCKET_SERVER_TOKEN"],
            Kind::Azure => &["AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_EXT_PAT"],
        }
    }

    /// The `Authorization` value for the API, as [`crate::sources`] sends it.
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn auth(self) -> Result<String, String> {
        let token = self
            .token_vars()
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
            .ok_or_else(|| {
                format!(
                    "set {} to a token that can write pull requests",
                    self.token_vars().join(" or ")
                )
            })?;
        Ok(match self {
            Kind::Gitea | Kind::Forgejo => format!("token {token}"),
            Kind::Bitbucket => match crate::sources::bitbucket_user() {
                Some(user) => format!(
                    "Basic {}",
                    crate::sources::base64(&format!("{user}:{token}"))
                ),
                None => format!("Bearer {token}"),
            },
            Kind::BitbucketServer => format!("Bearer {token}"),
            Kind::Azure => format!("Basic {}", crate::sources::base64(&format!(":{token}"))),
        })
    }

    fn noun(self) -> &'static str {
        "pull request"
    }
}

/// Where one repo's pull requests live: the API base and the repo's coordinates there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: Kind,
    /// e.g. `https://git.example.com/api/v1`, `https://api.bitbucket.org/2.0`,
    /// `https://bitbucket.example.com/rest/api/1.0`, `https://dev.azure.com/org/project/_apis`.
    pub api: String,
    /// Gitea owner, Bitbucket workspace, Data Center project key, Azure organization.
    pub owner: String,
    /// Azure only: the project.
    pub project: String,
    pub repo: String,
    /// The web root, for request links the API does not give (Azure).
    web: String,
}

fn decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Host, port and path of a git remote, for https, `ssh://` and scp-like `user@host:path`.
fn split_remote(url: &str) -> Option<(String, Option<u16>, String, bool)> {
    if let Some((scheme, rest)) = url.split_once("://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let authority = authority.rsplit('@').next()?;
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()),
            None => (authority, None),
        };
        return Some((
            host.to_ascii_lowercase(),
            port,
            path.trim_end_matches('/').to_string(),
            scheme == "https" || scheme == "http",
        ));
    }
    let (left, path) = url.split_once(':')?;
    let host = left.rsplit('@').next()?;
    Some((host.to_ascii_lowercase(), None, path.to_string(), false))
}

impl Target {
    /// The target for a repo whose `origin` is `remote`. `api` overrides the derived API base
    /// (an ssh remote, or a forge on a non-default port or under a path).
    pub fn from_remote(kind: Kind, remote: &str, api: Option<&str>) -> Result<Target, String> {
        let bad = |why: &str| format!("origin `{remote}`: {why}");
        let (host, port, path, web_port) =
            split_remote(remote).ok_or_else(|| bad("not a URL git understands"))?;
        let path = path.trim_end_matches(".git").to_string();
        let parts: Vec<String> = path
            .split('/')
            .filter(|p| !p.is_empty())
            .map(decode)
            .collect();
        // The web origin: an https remote keeps its port; ssh ports are not web ports.
        let origin = match (web_port, port) {
            (true, Some(p)) => format!("https://{host}:{p}"),
            _ => format!("https://{host}"),
        };
        let given = api.map(|a| a.trim_end_matches('/').to_string());
        match kind {
            Kind::Gitea | Kind::Forgejo => {
                let [.., owner, repo] = parts.as_slice() else {
                    return Err(bad("expected .../owner/repo"));
                };
                let prefix = parts[..parts.len() - 2].join("/");
                let web = if prefix.is_empty() {
                    origin.clone()
                } else {
                    format!("{origin}/{prefix}")
                };
                Ok(Target {
                    kind,
                    api: given.unwrap_or_else(|| format!("{web}/api/v1")),
                    owner: owner.clone(),
                    project: String::new(),
                    repo: repo.clone(),
                    web,
                })
            }
            Kind::Bitbucket => {
                let [workspace, repo] = parts.as_slice() else {
                    return Err(bad("expected bitbucket.org/workspace/repo"));
                };
                Ok(Target {
                    kind,
                    api: given.unwrap_or_else(|| "https://api.bitbucket.org/2.0".to_string()),
                    owner: workspace.clone(),
                    project: String::new(),
                    repo: repo.clone(),
                    web: "https://bitbucket.org".to_string(),
                })
            }
            Kind::BitbucketServer => {
                // https://host[/context]/scm/PROJECT/repo.git, or ssh://git@host:7999/project/repo.git
                let (context, project, repo) = match parts.iter().position(|p| p == "scm") {
                    Some(i) if parts.len() == i + 3 => (
                        parts[..i].join("/"),
                        parts[i + 1].clone(),
                        parts[i + 2].clone(),
                    ),
                    _ if parts.len() == 2 => (String::new(), parts[0].clone(), parts[1].clone()),
                    _ => return Err(bad("expected .../scm/PROJECT/repo")),
                };
                let web = if context.is_empty() {
                    origin.clone()
                } else {
                    format!("{origin}/{context}")
                };
                Ok(Target {
                    kind,
                    api: given.unwrap_or_else(|| format!("{web}/rest/api/1.0")),
                    owner: project.to_ascii_uppercase(),
                    project: String::new(),
                    repo,
                    web,
                })
            }
            Kind::Azure => {
                // https://dev.azure.com/org/project/_git/repo
                // https://org.visualstudio.com/project/_git/repo
                // git@ssh.dev.azure.com:v3/org/project/repo
                let (org, project, repo) = if host == "ssh.dev.azure.com" {
                    match parts.as_slice() {
                        [v3, org, project, repo] if v3 == "v3" => {
                            (org.clone(), project.clone(), repo.clone())
                        }
                        _ => return Err(bad("expected v3/org/project/repo")),
                    }
                } else if let Some(org) = host.strip_suffix(".visualstudio.com") {
                    match parts.as_slice() {
                        [project, git, repo] if git == "_git" => {
                            (org.to_string(), project.clone(), repo.clone())
                        }
                        _ => return Err(bad("expected project/_git/repo")),
                    }
                } else {
                    match parts.as_slice() {
                        [org, project, git, repo] if git == "_git" => {
                            (org.clone(), project.clone(), repo.clone())
                        }
                        _ => return Err(bad("expected org/project/_git/repo")),
                    }
                };
                let web = format!(
                    "https://dev.azure.com/{}/{}",
                    encode_segment(&org),
                    encode_segment(&project)
                );
                Ok(Target {
                    kind,
                    api: given.unwrap_or_else(|| format!("{web}/_apis")),
                    owner: org,
                    project,
                    repo,
                    web,
                })
            }
        }
    }

    /// The repo's own API root.
    fn repo_api(&self) -> String {
        let (o, r) = (encode_segment(&self.owner), encode_segment(&self.repo));
        match self.kind {
            Kind::Gitea | Kind::Forgejo => format!("{}/repos/{o}/{r}", self.api),
            Kind::Bitbucket => format!("{}/repositories/{o}/{r}", self.api),
            Kind::BitbucketServer => format!("{}/projects/{o}/repos/{r}", self.api),
            Kind::Azure => format!("{}/git/repositories/{r}", self.api),
        }
    }

    fn pulls(&self) -> String {
        match self.kind {
            Kind::Gitea | Kind::Forgejo => format!("{}/pulls", self.repo_api()),
            Kind::Bitbucket => format!("{}/pullrequests", self.repo_api()),
            Kind::BitbucketServer => format!("{}/pull-requests", self.repo_api()),
            Kind::Azure => format!("{}/pullrequests", self.repo_api()),
        }
    }

    fn pull(&self, id: &str) -> String {
        format!("{}/{id}", self.pulls())
    }
}

/// Issues `method url` with a JSON body.
pub type Send<'a> = dyn FnMut(&str, &str, Option<&Value>) -> Result<Reply, String> + 'a;

const AZURE_VERSION: &str = "api-version=7.1";

fn with_query(url: &str, query: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{query}")
}

/// Call and require a 2xx reply, parsed as JSON (an empty body is `null`).
fn call(send: &mut Send, method: &str, url: &str, body: Option<&Value>) -> Result<Value, String> {
    let url = if url.contains("/_apis/") {
        with_query(url, AZURE_VERSION)
    } else {
        url.to_string()
    };
    let reply = send(method, &url, body)?;
    if !(200..300).contains(&reply.status) {
        let detail: String = reply.body.chars().take(300).collect();
        let hint = match reply.status {
            401 | 403 => " (the token cannot write pull requests here)",
            404 => " (no such repo or request, or the token cannot see it)",
            _ => "",
        };
        return Err(format!(
            "{method} {url}: HTTP {}{hint}: {}",
            reply.status,
            detail.trim()
        ));
    }
    if reply.body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&reply.body).map_err(|e| format!("{method} {url}: not JSON: {e}"))
}

fn text(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for key in path {
        cur = &cur[*key];
    }
    match cur {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// One request, normalized: states as GitHub spells them (`OPEN`, `MERGED`, `CLOSED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub branch: String,
    pub state: String,
    pub title: String,
    pub url: String,
}

impl Request {
    pub fn to_json(&self, forge: Kind) -> Value {
        json!({
            "branch": self.branch, "state": self.state, "title": self.title,
            "url": self.url, "forge": forge.name(),
        })
    }
}

fn normalize(target: &Target, item: &Value) -> Request {
    let (id, branch, state, url) = match target.kind {
        Kind::Gitea | Kind::Forgejo => {
            let state = match (text(item, &["state"]).as_str(), item["merged"].as_bool()) {
                ("open", _) => "OPEN",
                (_, Some(true)) => "MERGED",
                _ => "CLOSED",
            };
            (
                text(item, &["number"]),
                text(item, &["head", "ref"]),
                state,
                text(item, &["html_url"]),
            )
        }
        Kind::Bitbucket => {
            let state = match text(item, &["state"]).as_str() {
                "OPEN" => "OPEN",
                "MERGED" => "MERGED",
                _ => "CLOSED",
            };
            (
                text(item, &["id"]),
                text(item, &["source", "branch", "name"]),
                state,
                text(item, &["links", "html", "href"]),
            )
        }
        Kind::BitbucketServer => {
            let state = match text(item, &["state"]).as_str() {
                "OPEN" => "OPEN",
                "MERGED" => "MERGED",
                _ => "CLOSED",
            };
            let url = item["links"]["self"]
                .as_array()
                .and_then(|l| l.first())
                .map(|l| text(l, &["href"]))
                .unwrap_or_default();
            (
                text(item, &["id"]),
                text(item, &["fromRef", "displayId"]),
                state,
                url,
            )
        }
        Kind::Azure => {
            let state = match text(item, &["status"]).as_str() {
                "active" => "OPEN",
                "completed" => "MERGED",
                _ => "CLOSED",
            };
            let id = text(item, &["pullRequestId"]);
            let branch = text(item, &["sourceRefName"]);
            let url = format!(
                "{}/_git/{}/pullrequest/{id}",
                target.web,
                encode_segment(&target.repo)
            );
            (
                id,
                branch.trim_start_matches("refs/heads/").to_string(),
                state,
                url,
            )
        }
    };
    Request {
        id,
        branch,
        state: state.to_string(),
        title: text(item, &["title"]),
        url,
    }
}

const MAX_PAGES: usize = 50;

/// Every `fleetreach/*` request of the repo, in any state.
pub fn list(target: &Target, send: &mut Send) -> Result<Vec<Request>, String> {
    let mut items: Vec<Value> = Vec::new();
    match target.kind {
        Kind::Gitea | Kind::Forgejo => {
            for page in 1..=MAX_PAGES {
                let url = format!("{}?state=all&limit=50&page={page}", target.pulls());
                let body = call(send, "GET", &url, None)?;
                let batch = body.as_array().cloned().unwrap_or_default();
                if batch.is_empty() {
                    return Ok(keep(target, items));
                }
                items.extend(batch);
            }
        }
        Kind::Bitbucket => {
            let mut url = format!(
                "{}?state=OPEN&state=MERGED&state=DECLINED&state=SUPERSEDED&pagelen=50",
                target.pulls()
            );
            for _ in 0..MAX_PAGES {
                let body = call(send, "GET", &url, None)?;
                items.extend(body["values"].as_array().cloned().unwrap_or_default());
                match body["next"].as_str() {
                    None => return Ok(keep(target, items)),
                    // The token goes with it, so it must stay on this API.
                    Some(next) if next.starts_with(&format!("{}/", target.api)) => {
                        url = next.to_string();
                    }
                    Some(next) => return Err(format!("refusing a next page off the API: {next}")),
                }
            }
        }
        Kind::BitbucketServer => {
            let mut start = 0u64;
            for _ in 0..MAX_PAGES {
                let url = format!("{}?state=ALL&limit=100&start={start}", target.pulls());
                let body = call(send, "GET", &url, None)?;
                items.extend(body["values"].as_array().cloned().unwrap_or_default());
                if body["isLastPage"].as_bool() != Some(false) {
                    return Ok(keep(target, items));
                }
                let next = body["nextPageStart"]
                    .as_u64()
                    .ok_or("a page with no nextPageStart")?;
                if next <= start {
                    return Err("the pull request pager did not advance".to_string());
                }
                start = next;
            }
        }
        Kind::Azure => {
            for page in 0..MAX_PAGES {
                let url = format!(
                    "{}?searchCriteria.status=all&$top=100&$skip={}",
                    target.pulls(),
                    page * 100
                );
                let body = call(send, "GET", &url, None)?;
                let batch = body["value"].as_array().cloned().unwrap_or_default();
                let short = batch.len() < 100;
                items.extend(batch);
                if short {
                    return Ok(keep(target, items));
                }
            }
        }
    }
    Err(format!("more than {MAX_PAGES} pages of pull requests"))
}

fn keep(target: &Target, items: Vec<Value>) -> Vec<Request> {
    items
        .iter()
        .map(|i| normalize(target, i))
        .filter(|r| r.branch.starts_with("fleetreach/"))
        .collect()
}

/// Data Center wants the request's current version on every change.
fn server_version(target: &Target, id: &str, send: &mut Send) -> Result<u64, String> {
    let body = call(send, "GET", &target.pull(id), None)?;
    body["version"]
        .as_u64()
        .ok_or_else(|| format!("request {id} has no version"))
}

/// Azure caps a description at 4000 characters.
fn azure_description(body: &str) -> String {
    if body.chars().count() <= 4000 {
        return body.to_string();
    }
    let cut: String = body.chars().take(3900).collect();
    format!("{cut}\n\n(cut to Azure DevOps' 4000-character limit)")
}

/// Open the request for `branch` into `base`, or update the open one. The URL, and whether it
/// already existed.
#[allow(clippy::too_many_arguments)]
pub fn open_or_update(
    target: &Target,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
    draft: bool,
    send: &mut Send,
) -> Result<(String, bool, String), String> {
    let open = list(target, send)?
        .into_iter()
        .find(|r| r.branch == branch && r.state == "OPEN");
    if let Some(r) = open {
        let url = target.pull(&r.id);
        match target.kind {
            Kind::Gitea | Kind::Forgejo => {
                call(
                    send,
                    "PATCH",
                    &url,
                    Some(&json!({"title": title, "body": body})),
                )?;
            }
            Kind::Bitbucket => {
                call(
                    send,
                    "PUT",
                    &url,
                    Some(&json!({"title": title, "description": body})),
                )?;
            }
            Kind::BitbucketServer => {
                let version = server_version(target, &r.id, send)?;
                call(
                    send,
                    "PUT",
                    &url,
                    Some(&json!({"version": version, "title": title, "description": body})),
                )?;
            }
            Kind::Azure => {
                call(
                    send,
                    "PATCH",
                    &url,
                    Some(&json!({"title": title, "description": azure_description(body)})),
                )?;
            }
        }
        return Ok((r.url, true, r.id));
    }
    let created = match target.kind {
        Kind::Gitea | Kind::Forgejo => {
            // Gitea's draft is a `WIP:` title.
            let title = if draft {
                format!("WIP: {title}")
            } else {
                title.to_string()
            };
            call(
                send,
                "POST",
                &target.pulls(),
                Some(&json!({"head": branch, "base": base, "title": title, "body": body})),
            )?
        }
        Kind::Bitbucket => call(
            send,
            "POST",
            &target.pulls(),
            Some(&json!({
                "title": title, "description": body, "draft": draft,
                "source": {"branch": {"name": branch}},
                "destination": {"branch": {"name": base}},
            })),
        )?,
        Kind::BitbucketServer => call(
            send,
            "POST",
            &target.pulls(),
            Some(&json!({
                "title": title, "description": body, "draft": draft,
                "fromRef": {"id": format!("refs/heads/{branch}")},
                "toRef": {"id": format!("refs/heads/{base}")},
            })),
        )?,
        Kind::Azure => call(
            send,
            "POST",
            &target.pulls(),
            Some(&json!({
                "title": title, "description": azure_description(body), "isDraft": draft,
                "sourceRefName": format!("refs/heads/{branch}"),
                "targetRefName": format!("refs/heads/{base}"),
            })),
        )?,
    };
    let request = normalize(target, &created);
    if request.id.is_empty() {
        return Err(format!(
            "the forge did not say which {} it opened",
            target.kind.noun()
        ));
    }
    Ok((request.url, false, request.id))
}

/// Comment why, then close (Gitea), decline (Bitbucket) or abandon (Azure) the request.
pub fn close(target: &Target, id: &str, note: &str, send: &mut Send) -> Result<(), String> {
    let url = target.pull(id);
    match target.kind {
        Kind::Gitea | Kind::Forgejo => {
            let comment = format!("{}/issues/{id}/comments", target.repo_api());
            call(send, "POST", &comment, Some(&json!({"body": note})))?;
            call(send, "PATCH", &url, Some(&json!({"state": "closed"})))?;
        }
        Kind::Bitbucket => {
            call(
                send,
                "POST",
                &format!("{url}/comments"),
                Some(&json!({"content": {"raw": note}})),
            )?;
            call(send, "POST", &format!("{url}/decline"), None)?;
        }
        Kind::BitbucketServer => {
            call(
                send,
                "POST",
                &format!("{url}/comments"),
                Some(&json!({"text": note})),
            )?;
            let version = server_version(target, id, send)?;
            call(
                send,
                "POST",
                &format!("{url}/decline?version={version}"),
                Some(&json!({})),
            )?;
        }
        Kind::Azure => {
            call(
                send,
                "POST",
                &format!("{url}/threads"),
                Some(&json!({
                    "comments": [{"parentCommentId": 0, "content": note, "commentType": 1}],
                    "status": "closed",
                })),
            )?;
            call(send, "PATCH", &url, Some(&json!({"status": "abandoned"})))?;
        }
    }
    Ok(())
}

/// Auto-merge on these forges. None can pin it to the commit fleetreach verified: Bitbucket
/// and Azure take no commit, and Forgejo 11 checks `head_commit_id` only when auto-merge is
/// armed, then merged a commit pushed after it (tested live). A later push by anyone would
/// merge unverified, so this only says why it stays off; nothing is sent.
pub fn automerge(
    target: &Target,
    _id: &str,
    _head: &str,
    _method: &str,
    _send: &mut Send,
) -> Result<(), String> {
    Err(format!(
        "{}'s auto-merge cannot be pinned to the verified commit, so it is left to a person",
        target.kind.name()
    ))
}

/// The request id at the end of a request URL.
pub fn id_from_url(url: &str) -> Option<String> {
    url.trim_end_matches('/')
        .rsplit('/')
        .find(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_string)
}

/// A sender over HTTPS with the forge's token.
#[cfg(feature = "network")]
pub fn http_send(kind: Kind) -> Result<Box<Send<'static>>, String> {
    let auth = kind.auth()?;
    let agent = crate::forges::agent(false)?;
    Ok(Box::new(
        move |method: &str, url: &str, body: Option<&Value>| {
            let ua = concat!("fleetreach/", env!("CARGO_PKG_VERSION"));
            let read = |mut resp: ureq::http::Response<ureq::Body>| -> Result<Reply, String> {
                let status = resp.status().as_u16();
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(16 * 1024 * 1024)
                    .read_to_string()
                    .map_err(|e| format!("reading {url}: {e}"))?;
                Ok(Reply { status, body })
            };
            let fail = |e: ureq::Error| format!("{method} {url}: {e}");
            match method {
                "GET" => read(
                    agent
                        .get(url)
                        .header("Accept", "application/json")
                        .header("User-Agent", ua)
                        .header("Authorization", &auth)
                        .call()
                        .map_err(fail)?,
                ),
                _ => {
                    let payload = body.map_or_else(String::new, Value::to_string);
                    let req = match method {
                        "POST" => agent.post(url),
                        "PUT" => agent.put(url),
                        "PATCH" => agent.patch(url),
                        other => return Err(format!("unsupported method {other}")),
                    };
                    read(
                        req.header("Accept", "application/json")
                            .header("Content-Type", "application/json")
                            .header("User-Agent", ua)
                            .header("Authorization", &auth)
                            .send(payload)
                            .map_err(fail)?,
                    )
                }
            }
        },
    ))
}

/// Refuses without the network feature.
#[cfg(not(feature = "network"))]
pub fn http_send(kind: Kind) -> Result<Box<Send<'static>>, String> {
    Err(format!(
        "pull requests on {} need a network build (`--features network`)",
        kind.name()
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::VecDeque;

    /// A fake forge: replies in order, and every call recorded.
    struct Fake {
        replies: VecDeque<(u16, Value)>,
        calls: Vec<(String, String, Option<Value>)>,
    }

    impl Fake {
        fn new(replies: Vec<(u16, Value)>) -> Fake {
            Fake {
                replies: replies.into(),
                calls: Vec::new(),
            }
        }

        fn send(&mut self) -> impl FnMut(&str, &str, Option<&Value>) -> Result<Reply, String> + '_ {
            move |method, url, body| {
                self.calls
                    .push((method.to_string(), url.to_string(), body.cloned()));
                let (status, value) = self.replies.pop_front().expect("an unexpected call");
                let body = if value.is_null() {
                    String::new()
                } else {
                    value.to_string()
                };
                Ok(Reply { status, body })
            }
        }
    }

    #[test]
    fn targets_come_from_the_origin_remote() {
        let t =
            Target::from_remote(Kind::Gitea, "https://git.example.com/acme/api.git", None).unwrap();
        assert_eq!(t.api, "https://git.example.com/api/v1");
        assert_eq!(
            t.pulls(),
            "https://git.example.com/api/v1/repos/acme/api/pulls"
        );
        let t = Target::from_remote(
            Kind::Forgejo,
            "https://code.example.com:3000/forge/acme/api",
            None,
        )
        .unwrap();
        assert_eq!(t.api, "https://code.example.com:3000/forge/api/v1");
        let t = Target::from_remote(Kind::Gitea, "git@git.example.com:acme/api.git", None).unwrap();
        assert_eq!(t.api, "https://git.example.com/api/v1");
        let t = Target::from_remote(
            Kind::Gitea,
            "ssh://git@git.example.com:2222/acme/api.git",
            Some("https://git.example.com/api/v1/"),
        )
        .unwrap();
        assert_eq!(t.api, "https://git.example.com/api/v1");

        let t = Target::from_remote(
            Kind::Bitbucket,
            "https://me@bitbucket.org/acme/api.git",
            None,
        )
        .unwrap();
        assert_eq!(
            t.pulls(),
            "https://api.bitbucket.org/2.0/repositories/acme/api/pullrequests"
        );
        let t = Target::from_remote(
            Kind::BitbucketServer,
            "https://bb.example.com/stash/scm/ops/api.git",
            None,
        )
        .unwrap();
        assert_eq!(
            t.pulls(),
            "https://bb.example.com/stash/rest/api/1.0/projects/OPS/repos/api/pull-requests"
        );
        let t = Target::from_remote(
            Kind::BitbucketServer,
            "ssh://git@bb.example.com:7999/ops/api.git",
            None,
        )
        .unwrap();
        assert_eq!(t.api, "https://bb.example.com/rest/api/1.0");

        for remote in [
            "https://acme@dev.azure.com/acme/Web%20Apps/_git/api",
            "git@ssh.dev.azure.com:v3/acme/Web%20Apps/api",
            "https://acme.visualstudio.com/Web%20Apps/_git/api",
        ] {
            let t = Target::from_remote(Kind::Azure, remote, None).unwrap();
            assert_eq!(t.project, "Web Apps", "{remote}");
            assert_eq!(
                t.pulls(),
                "https://dev.azure.com/acme/Web%20Apps/_apis/git/repositories/api/pullrequests",
                "{remote}"
            );
        }
        assert!(Target::from_remote(Kind::Bitbucket, "https://bitbucket.org/acme", None).is_err());
    }

    #[test]
    fn gitea_lists_opens_updates_closes_and_automerges() {
        let t = Target::from_remote(Kind::Gitea, "https://git.example.com/acme/api", None).unwrap();
        let page = json!([
            {"number": 4, "state": "closed", "merged": true, "title": "a",
             "head": {"ref": "fleetreach/c1/a-1"}, "html_url": "https://git.example.com/acme/api/pulls/4"},
            {"number": 5, "state": "closed", "merged": false, "title": "b",
             "head": {"ref": "fleetreach/c2/b-1"}, "html_url": "https://git.example.com/acme/api/pulls/5"},
            {"number": 6, "state": "open", "title": "c",
             "head": {"ref": "fleetreach/c3/c-1"}, "html_url": "https://git.example.com/acme/api/pulls/6"},
            {"number": 7, "state": "open", "title": "a person's", "head": {"ref": "feature"},
             "html_url": "https://git.example.com/acme/api/pulls/7"},
        ]);
        let mut fake = Fake::new(vec![(200, page.clone()), (200, json!([]))]);
        let listed = list(&t, &mut fake.send()).unwrap();
        let states: Vec<&str> = listed.iter().map(|r| r.state.as_str()).collect();
        assert_eq!(states, ["MERGED", "CLOSED", "OPEN"]);
        assert!(fake.calls[1].1.ends_with("page=2"));

        // The open request is updated in place.
        let mut fake = Fake::new(vec![
            (200, page.clone()),
            (200, json!([])),
            (200, json!({})),
        ]);
        let (url, updated, id) = open_or_update(
            &t,
            "fleetreach/c3/c-1",
            "main",
            "T",
            "B",
            false,
            &mut fake.send(),
        )
        .unwrap();
        assert!(updated);
        assert_eq!(
            (url.as_str(), id.as_str()),
            ("https://git.example.com/acme/api/pulls/6", "6")
        );
        assert_eq!(fake.calls[2].0, "PATCH");
        assert_eq!(fake.calls[2].2, Some(json!({"title": "T", "body": "B"})));

        // A new one, as a draft.
        let made = json!({"number": 8, "state": "open", "title": "WIP: T",
            "head": {"ref": "fleetreach/c9/x-1"}, "html_url": "https://git.example.com/acme/api/pulls/8"});
        let mut fake = Fake::new(vec![(200, json!([])), (201, made)]);
        let (url, updated, _) = open_or_update(
            &t,
            "fleetreach/c9/x-1",
            "main",
            "T",
            "B",
            true,
            &mut fake.send(),
        )
        .unwrap();
        assert!(!updated);
        assert!(url.ends_with("/pulls/8"));
        assert_eq!(
            fake.calls[1].2,
            Some(
                json!({"head": "fleetreach/c9/x-1", "base": "main", "title": "WIP: T", "body": "B"})
            )
        );

        let mut fake = Fake::new(vec![(201, json!({})), (201, json!({}))]);
        close(&t, "6", "no longer needed", &mut fake.send()).unwrap();
        assert!(fake.calls[0]
            .1
            .ends_with("/repos/acme/api/issues/6/comments"));
        assert_eq!(fake.calls[1].2, Some(json!({"state": "closed"})));

        // Forgejo merged a commit pushed after auto-merge was armed: never turned on.
        let mut fake = Fake::new(vec![]);
        let err = automerge(&t, "6", "abc123", "squash", &mut fake.send()).unwrap_err();
        assert!(err.contains("cannot be pinned"), "{err}");
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn bitbucket_cloud_pages_by_next_and_refuses_a_foreign_one() {
        let t =
            Target::from_remote(Kind::Bitbucket, "https://bitbucket.org/acme/api", None).unwrap();
        let first = json!({"values": [
            {"id": 3, "state": "DECLINED", "title": "x", "source": {"branch": {"name": "fleetreach/c/x-1"}},
             "links": {"html": {"href": "https://bitbucket.org/acme/api/pull-requests/3"}}}],
            "next": "https://api.bitbucket.org/2.0/repositories/acme/api/pullrequests?page=2"});
        let second = json!({"values": [
            {"id": 4, "state": "OPEN", "title": "y", "source": {"branch": {"name": "fleetreach/c/y-1"}},
             "links": {"html": {"href": "https://bitbucket.org/acme/api/pull-requests/4"}}}]});
        let mut fake = Fake::new(vec![(200, first.clone()), (200, second)]);
        let listed = list(&t, &mut fake.send()).unwrap();
        assert_eq!(
            listed.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(),
            ["CLOSED", "OPEN"]
        );
        let evil = json!({"values": [], "next": "https://evil.example/steal"});
        let mut fake = Fake::new(vec![(200, evil)]);
        assert!(list(&t, &mut fake.send())
            .unwrap_err()
            .contains("off the API"));

        let mut fake = Fake::new(vec![(201, json!({})), (200, json!({}))]);
        close(&t, "4", "n", &mut fake.send()).unwrap();
        assert!(fake.calls[1].1.ends_with("/pullrequests/4/decline"));
        assert!(
            automerge(&t, "4", "abc", "squash", &mut Fake::new(vec![]).send())
                .unwrap_err()
                .contains("cannot be pinned")
        );
    }

    #[test]
    fn bitbucket_server_sends_the_version_on_every_change() {
        let t = Target::from_remote(
            Kind::BitbucketServer,
            "https://bb.example.com/scm/OPS/api.git",
            None,
        )
        .unwrap();
        let page = json!({"isLastPage": true, "values": [
            {"id": 9, "version": 2, "state": "OPEN", "title": "x",
             "fromRef": {"displayId": "fleetreach/c/x-1"},
             "links": {"self": [{"href": "https://bb.example.com/projects/OPS/repos/api/pull-requests/9"}]}}]});
        let mut fake = Fake::new(vec![
            (200, page),
            (200, json!({"id": 9, "version": 2})),
            (200, json!({})),
        ]);
        let (_, updated, id) = open_or_update(
            &t,
            "fleetreach/c/x-1",
            "main",
            "T",
            "B",
            false,
            &mut fake.send(),
        )
        .unwrap();
        assert!(updated && id == "9");
        assert_eq!(fake.calls[2].0, "PUT");
        assert_eq!(fake.calls[2].2.as_ref().unwrap()["version"], 2);

        let mut fake = Fake::new(vec![
            (201, json!({})),
            (200, json!({"id": 9, "version": 3})),
            (200, json!({})),
        ]);
        close(&t, "9", "n", &mut fake.send()).unwrap();
        assert!(fake.calls[2]
            .1
            .ends_with("/pull-requests/9/decline?version=3"));

        // A pager that does not advance is an error, never a shorter list.
        let stuck = json!({"isLastPage": false, "nextPageStart": 0, "values": []});
        let mut fake = Fake::new(vec![(200, stuck)]);
        assert!(list(&t, &mut fake.send())
            .unwrap_err()
            .contains("did not advance"));
    }

    #[test]
    fn azure_adds_the_api_version_and_abandons_with_a_closed_thread() {
        let t = Target::from_remote(Kind::Azure, "https://dev.azure.com/acme/web/_git/api", None)
            .unwrap();
        let page = json!({"value": [
            {"pullRequestId": 12, "status": "completed", "title": "x",
             "sourceRefName": "refs/heads/fleetreach/c/x-1"},
            {"pullRequestId": 13, "status": "abandoned", "title": "y",
             "sourceRefName": "refs/heads/fleetreach/c/y-1"}]});
        let mut fake = Fake::new(vec![(200, page)]);
        let listed = list(&t, &mut fake.send()).unwrap();
        assert_eq!(listed[0].state, "MERGED");
        assert_eq!(listed[1].state, "CLOSED");
        assert_eq!(
            listed[0].url,
            "https://dev.azure.com/acme/web/_git/api/pullrequest/12"
        );
        assert!(fake.calls[0].1.contains("searchCriteria.status=all"));
        assert!(fake.calls[0].1.ends_with("&api-version=7.1"));

        let long = "x".repeat(5000);
        let made = json!({"pullRequestId": 14, "status": "active", "title": "T",
            "sourceRefName": "refs/heads/fleetreach/c/z-1"});
        let mut fake = Fake::new(vec![(200, json!({"value": []})), (201, made)]);
        let (url, updated, _) = open_or_update(
            &t,
            "fleetreach/c/z-1",
            "main",
            "T",
            &long,
            true,
            &mut fake.send(),
        )
        .unwrap();
        assert!(!updated && url.ends_with("/pullrequest/14"));
        let sent = fake.calls[1].2.clone().unwrap();
        assert_eq!(sent["targetRefName"], "refs/heads/main");
        assert_eq!(sent["isDraft"], true);
        assert!(sent["description"].as_str().unwrap().chars().count() <= 4000);

        let mut fake = Fake::new(vec![(200, json!({})), (200, json!({}))]);
        close(&t, "14", "n", &mut fake.send()).unwrap();
        assert!(fake.calls[0]
            .1
            .contains("/pullrequests/14/threads?api-version=7.1"));
        assert_eq!(fake.calls[1].2, Some(json!({"status": "abandoned"})));
    }

    #[test]
    fn errors_say_what_the_token_lacks() {
        let t = Target::from_remote(Kind::Gitea, "https://git.example.com/acme/api", None).unwrap();
        let mut fake = Fake::new(vec![(403, json!({"message": "forbidden"}))]);
        let err = list(&t, &mut fake.send()).unwrap_err();
        assert!(
            err.contains("HTTP 403") && err.contains("cannot write"),
            "{err}"
        );
        assert_eq!(
            id_from_url("https://bb.example.com/projects/OPS/repos/api/pull-requests/9/overview"),
            Some("9".to_string())
        );
        assert_eq!(
            id_from_url("https://x/acme/api/pulls/12"),
            Some("12".to_string())
        );
    }
}
