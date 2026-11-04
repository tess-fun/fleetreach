//! Repo listings for Gitea and Forgejo, Bitbucket Cloud and Data Center, and Azure DevOps.
//!
//! Each listing is written against a `fetch` closure, so paging and its failure modes are
//! tested without a server. Fail-closed: a page that cannot be read stops the listing, a
//! `next` link off the configured API is refused (it would carry the token elsewhere), and a
//! pager that stops advancing is an error, never a shorter fleet.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::sources::Listed;

/// One HTTP response.
pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// Issues a GET.
pub type Fetch<'a> = dyn FnMut(&str) -> Result<Reply, String> + 'a;

fn text(item: &Value, key: &str) -> Option<String> {
    item.get(key).and_then(Value::as_str).map(str::to_string)
}

fn flag(item: &Value, key: &str) -> bool {
    item.get(key).and_then(Value::as_bool) == Some(true)
}

/// A number or string id as text, for spotting a rename.
fn stable_key(item: &Value, key: &str) -> Option<String> {
    match item.get(key)? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// `https://user@host/path` to `https://host/path`: Bitbucket and Azure name the caller in
/// clone URLs, and the checkout path and token scope both go by the bare host.
fn strip_userinfo(url: &str) -> String {
    let Some(rest) = url.strip_prefix("https://") else {
        return url.to_string();
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("https://{host}/{path}")
}

/// One URL path segment.
pub(crate) fn encode_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A name as a repo id part: Azure allows spaces and punctuation that a checkout path and
/// `owner/name` id do not.
fn id_part(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn json(url: &str, body: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|e| format!("{url}: not the expected JSON: {e}"))
}

fn http_error(url: &str, status: u16, hint: &str) -> String {
    let hint = match status {
        401 | 403 => hint,
        429 => " (rate limited; retry later)",
        _ => "",
    };
    format!("GET {url}: HTTP {status}{hint}")
}

/// One page of a Gitea or Forgejo repo listing. Empty repositories are left out, as there is
/// nothing to clone.
pub(crate) fn parse_gitea(body: &Value) -> Vec<Listed> {
    let items = body.as_array().map_or(&[][..], Vec::as_slice);
    items
        .iter()
        .filter(|r| !flag(r, "empty"))
        .filter_map(|r| {
            Some(Listed {
                id: text(r, "full_name")?,
                clone_url: text(r, "clone_url")?,
                default_branch: text(r, "default_branch"),
                archived: flag(r, "archived"),
                fork: flag(r, "fork"),
                topics: r
                    .get("topics")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                key: stable_key(r, "id"),
            })
        })
        .collect()
}

/// `GET /orgs/:org/repos`, falling back to `/users/:user/repos`. The page size is capped by
/// the server's `MAX_RESPONSE_ITEMS`, so the end is an empty page, not a short one.
pub fn gitea(api: &str, owner: &str, fetch: &mut Fetch) -> Result<Vec<Listed>, String> {
    let encoded = encode_segment(owner);
    for kind in ["orgs", "users"] {
        let mut all = Vec::new();
        let mut seen = BTreeSet::new();
        let mut page = 1u32;
        loop {
            let url = format!("{api}/{kind}/{encoded}/repos?limit=50&page={page}");
            let reply = fetch(&url)?;
            if reply.status == 404 && kind == "orgs" && page == 1 {
                break;
            }
            if reply.status != 200 {
                let hint = " (set a token with read:organization and read:repository scope)";
                return Err(http_error(&url, reply.status, hint));
            }
            let body = json(&url, &reply.body)?;
            let items = body
                .as_array()
                .ok_or_else(|| format!("{url}: not a list of repos"))?;
            if items.is_empty() {
                return Ok(all);
            }
            let ids: Vec<u64> = items
                .iter()
                .filter_map(|r| r.get("id").and_then(Value::as_u64))
                .collect();
            if !ids.is_empty() && ids.iter().all(|id| seen.contains(id)) {
                return Err(format!("{url}: the server repeated a page"));
            }
            seen.extend(ids);
            all.extend(parse_gitea(&body));
            page += 1;
        }
    }
    Err(format!("no organization or user `{owner}` at {api}"))
}

/// The `href` of a repo's https clone link.
fn clone_link(repo: &Value, name: &str) -> Option<String> {
    let links = repo.get("links")?.get("clone")?.as_array()?;
    links
        .iter()
        .find(|l| l.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|l| text(l, "href"))
        .filter(|href| href.starts_with("https://"))
        .map(|href| strip_userinfo(&href))
}

/// One page of `GET /repositories/:workspace`. A repo with no main branch is empty.
/// Bitbucket Cloud has no archived flag and no topics.
pub(crate) fn parse_bitbucket(body: &Value) -> Vec<Listed> {
    let items = body
        .get("values")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    items
        .iter()
        .filter(|r| r.get("scm").and_then(Value::as_str).unwrap_or("git") == "git")
        .filter_map(|r| {
            Some(Listed {
                id: text(r, "full_name")?,
                clone_url: clone_link(r, "https")?,
                default_branch: Some(text(r.get("mainbranch")?, "name")?),
                archived: false,
                fork: r.get("parent").is_some_and(|p| !p.is_null()),
                topics: Vec::new(),
                key: stable_key(r, "uuid"),
            })
        })
        .collect()
}

/// `GET /repositories/:workspace`, following `next`.
pub fn bitbucket(api: &str, workspace: &str, fetch: &mut Fetch) -> Result<Vec<Listed>, String> {
    let mut url = format!(
        "{api}/repositories/{}?pagelen=100",
        encode_segment(workspace)
    );
    let mut visited = BTreeSet::new();
    let mut all = Vec::new();
    loop {
        if !visited.insert(url.clone()) {
            return Err(format!("{url}: the server repeated a page"));
        }
        let reply = fetch(&url)?;
        if reply.status == 404 {
            return Err(format!("Bitbucket has no workspace `{workspace}`"));
        }
        if reply.status != 200 {
            let hint = " (set BITBUCKET_TOKEN to a token with repository read scope)";
            return Err(http_error(&url, reply.status, hint));
        }
        let body = json(&url, &reply.body)?;
        if !body.get("values").is_some_and(Value::is_array) {
            return Err(format!("{url}: no `values` list"));
        }
        all.extend(parse_bitbucket(&body));
        match text(&body, "next") {
            Some(next) if next.starts_with(&format!("{api}/")) => url = next,
            Some(next) => return Err(format!("{url}: `next` left the API: {next}")),
            None => return Ok(all),
        }
    }
}

/// One page of `GET /projects/:key/repos`. The listing does not say which repos are empty or
/// name their default branch; `git clone` takes HEAD and an empty repo is an errored gap.
pub(crate) fn parse_bitbucket_server(body: &Value) -> Vec<Listed> {
    let items = body
        .get("values")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    items
        .iter()
        .filter(|r| r.get("scmId").and_then(Value::as_str).unwrap_or("git") == "git")
        .filter_map(|r| {
            let project = text(r.get("project")?, "key")?;
            Some(Listed {
                id: format!("{project}/{}", text(r, "slug")?),
                clone_url: clone_link(r, "http")?,
                default_branch: None,
                archived: flag(r, "archived"),
                fork: r.get("origin").is_some_and(|o| !o.is_null()),
                topics: Vec::new(),
                key: stable_key(r, "id"),
            })
        })
        .collect()
}

/// `GET /projects/:key/repos`, following `nextPageStart`. A personal project is `~user`.
pub fn bitbucket_server(
    api: &str,
    project: &str,
    fetch: &mut Fetch,
) -> Result<Vec<Listed>, String> {
    let encoded = encode_segment(project);
    let mut start = 0u64;
    let mut all = Vec::new();
    loop {
        let url = format!("{api}/projects/{encoded}/repos?limit=100&start={start}");
        let reply = fetch(&url)?;
        if reply.status == 404 {
            return Err(format!("no project `{project}` at {api}"));
        }
        if reply.status != 200 {
            let hint = " (no such project, or set BITBUCKET_SERVER_TOKEN to a token with \
                        project read permission)";
            return Err(http_error(&url, reply.status, hint));
        }
        let body = json(&url, &reply.body)?;
        if !body.get("values").is_some_and(Value::is_array) {
            return Err(format!("{url}: no `values` list"));
        }
        all.extend(parse_bitbucket_server(&body));
        if flag(&body, "isLastPage") {
            return Ok(all);
        }
        match body.get("nextPageStart").and_then(Value::as_u64) {
            Some(next) if next > start => start = next,
            _ => return Err(format!("{url}: the page has no later `nextPageStart`")),
        }
    }
}

/// `GET /_apis/git/repositories` as repos of `org`. No default branch means an empty repo; a
/// disabled repo cannot be cloned, so it counts as archived.
pub(crate) fn parse_azure(org: &str, body: &Value) -> Vec<Listed> {
    let items = body
        .get("value")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    items
        .iter()
        .filter_map(|r| {
            let branch = text(r, "defaultBranch")?;
            let project = text(r.get("project")?, "name")?;
            let name = text(r, "name")?;
            let clone_url = text(r, "remoteUrl")?;
            Some(Listed {
                id: format!("{}/{}/{}", id_part(org), id_part(&project), id_part(&name)),
                clone_url: strip_userinfo(&clone_url),
                default_branch: Some(
                    branch
                        .strip_prefix("refs/heads/")
                        .unwrap_or(&branch)
                        .to_string(),
                ),
                archived: flag(r, "isDisabled"),
                fork: flag(r, "isFork"),
                topics: Vec::new(),
                key: stable_key(r, "id"),
            })
        })
        .collect()
}

/// Every repo of an organization, or of one project with `org/project`. The API does not page.
/// A missing or unreadable target is a redirect to a sign-in page (or a 203 carrying one), so
/// anything else than a 200 with the promised `count` stops the listing.
pub fn azure(api: &str, target: &str, fetch: &mut Fetch) -> Result<Vec<Listed>, String> {
    let (org, project) = match target.split_once('/') {
        Some((org, project)) => (org, Some(project)),
        None => (target, None),
    };
    let scope = match project {
        Some(p) => format!("{}/{}", encode_segment(org), encode_segment(p)),
        None => encode_segment(org),
    };
    let url = format!("{api}/{scope}/_apis/git/repositories?api-version=6.0");
    let reply = fetch(&url)?;
    let hint = " (Azure DevOps asks for sign-in: the organization or project does not exist, \
                or set AZURE_DEVOPS_TOKEN to a token with Code read scope; public projects \
                can only be listed as `org/project`)";
    match reply.status {
        200 => {}
        203 | 300..=399 => return Err(format!("GET {url}: HTTP {}{hint}", reply.status)),
        404 => return Err(format!("Azure DevOps has no organization `{org}`")),
        status => return Err(http_error(&url, status, hint)),
    }
    let body = json(&url, &reply.body)?;
    let items = body
        .get("value")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{url}: no `value` list"))?;
    if let Some(count) = body.get("count").and_then(Value::as_u64) {
        if count != items.len() as u64 {
            return Err(format!("{url}: says {count} repos, lists {}", items.len()));
        }
    }
    let all = parse_azure(org, &body);
    let mut ids = BTreeSet::new();
    match all.iter().find(|r| !ids.insert(r.id.as_str())) {
        Some(r) => Err(format!(
            "two Azure DevOps repos have the id `{}` once spaces and punctuation are replaced",
            r.id
        )),
        None => Ok(all),
    }
}

/// An agent for forge listings: https only, and `SSL_CERT_FILE` as the trusted roots when set,
/// for a forge behind a private CA.
#[cfg(feature = "network")]
pub fn agent(follow_redirects: bool) -> Result<ureq::Agent, String> {
    use std::time::Duration;
    use ureq::tls::{parse_pem, PemItem, RootCerts, TlsConfig};

    let mut config = ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)));
    if !follow_redirects {
        config = config.max_redirects(0);
    }
    if let Some(path) = std::env::var_os("SSL_CERT_FILE").filter(|p| !p.is_empty()) {
        let shown = std::path::Path::new(&path).display().to_string();
        let pem = std::fs::read(&path).map_err(|e| format!("SSL_CERT_FILE {shown}: {e}"))?;
        let mut certs = Vec::new();
        for item in parse_pem(&pem) {
            if let PemItem::Certificate(cert) =
                item.map_err(|e| format!("SSL_CERT_FILE {shown}: {e}"))?
            {
                certs.push(cert);
            }
        }
        if certs.is_empty() {
            return Err(format!("SSL_CERT_FILE {shown}: no certificates"));
        }
        config = config.tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(&certs))
                .build(),
        );
    }
    Ok(config.build().into())
}

/// A GET with `auth` as the `Authorization` header. Redirects are not followed.
#[cfg(feature = "network")]
pub fn http_fetch(
    auth: Option<String>,
) -> Result<impl FnMut(&str) -> Result<Reply, String>, String> {
    let agent = agent(false)?;
    Ok(move |url: &str| {
        let mut req = agent.get(url).header("Accept", "application/json").header(
            "User-Agent",
            concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(value) = &auth {
            req = req.header("Authorization", value);
        }
        let mut resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(64 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| format!("reading {url}: {e}"))?;
        Ok(Reply { status, body })
    })
}

/// Refuses without the network feature.
#[cfg(not(feature = "network"))]
pub fn http_fetch(
    _auth: Option<String>,
) -> Result<impl FnMut(&str) -> Result<Reply, String>, String> {
    Err::<fn(&str) -> Result<Reply, String>, String>(
        "listing this source needs a network build (`--features network`)".to_string(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// Answers from a url -> (status, body) table and fails on anything else.
    fn server(pages: &[(&str, u16, &str)]) -> impl FnMut(&str) -> Result<Reply, String> {
        let table: BTreeMap<String, (u16, String)> = pages
            .iter()
            .map(|(u, s, b)| (u.to_string(), (*s, b.to_string())))
            .collect();
        move |url: &str| {
            table
                .get(url)
                .map(|(status, body)| Reply {
                    status: *status,
                    body: body.clone(),
                })
                .ok_or_else(|| format!("unexpected request {url}"))
        }
    }

    fn ids(repos: &[Listed]) -> Vec<&str> {
        repos.iter().map(|r| r.id.as_str()).collect()
    }

    const API: &str = "https://forge.test/api";

    #[test]
    fn gitea_reads_every_page_and_skips_empty_repos() {
        let one = r#"[{"id":1,"full_name":"acme/api","clone_url":"https://forge.test/acme/api.git",
            "default_branch":"main","archived":true,"fork":true,"topics":["prod"]},
            {"id":2,"full_name":"acme/void","clone_url":"https://forge.test/acme/void.git","empty":true}]"#;
        let two =
            r#"[{"id":3,"full_name":"acme/web","clone_url":"https://forge.test/acme/web.git"}]"#;
        let mut fetch = server(&[
            (
                "https://forge.test/api/orgs/acme/repos?limit=50&page=1",
                200,
                one,
            ),
            (
                "https://forge.test/api/orgs/acme/repos?limit=50&page=2",
                200,
                two,
            ),
            (
                "https://forge.test/api/orgs/acme/repos?limit=50&page=3",
                200,
                "[]",
            ),
        ]);
        let repos = gitea(API, "acme", &mut fetch).unwrap();
        assert_eq!(ids(&repos), vec!["acme/api", "acme/web"]);
        assert!(repos[0].archived && repos[0].fork);
        assert_eq!(repos[0].topics, vec!["prod"]);
        assert_eq!(repos[0].key.as_deref(), Some("1"));
    }

    #[test]
    fn gitea_falls_back_to_a_user_and_fails_on_neither() {
        let mut fetch = server(&[
            (
                "https://forge.test/api/orgs/me/repos?limit=50&page=1",
                404,
                "",
            ),
            (
                "https://forge.test/api/users/me/repos?limit=50&page=1",
                200,
                "[]",
            ),
        ]);
        assert!(gitea(API, "me", &mut fetch).unwrap().is_empty());
        let mut fetch = server(&[
            (
                "https://forge.test/api/orgs/me/repos?limit=50&page=1",
                404,
                "",
            ),
            (
                "https://forge.test/api/users/me/repos?limit=50&page=1",
                404,
                "",
            ),
        ]);
        assert!(gitea(API, "me", &mut fetch).is_err());
    }

    #[test]
    fn a_failed_later_page_fails_the_listing() {
        let one = r#"[{"id":1,"full_name":"a/b","clone_url":"https://forge.test/a/b.git"}]"#;
        let mut fetch = server(&[
            (
                "https://forge.test/api/orgs/a/repos?limit=50&page=1",
                200,
                one,
            ),
            (
                "https://forge.test/api/orgs/a/repos?limit=50&page=2",
                500,
                "boom",
            ),
        ]);
        assert!(gitea(API, "a", &mut fetch).unwrap_err().contains("500"));
    }

    #[test]
    fn a_server_that_ignores_the_page_number_is_refused() {
        let same = r#"[{"id":1,"full_name":"a/b","clone_url":"https://forge.test/a/b.git"}]"#;
        let mut fetch = |_: &str| {
            Ok(Reply {
                status: 200,
                body: same.to_string(),
            })
        };
        assert!(gitea(API, "a", &mut fetch)
            .unwrap_err()
            .contains("repeated"));
    }

    const BB: &str = r#"{"type":"repository","full_name":"ws/api","uuid":"{u1}","scm":"git",
        "mainbranch":{"name":"trunk"},"parent":{"full_name":"x/y"},
        "links":{"clone":[{"name":"https","href":"https://me@bitbucket.test/ws/api.git"},
                          {"name":"ssh","href":"git@bitbucket.test:ws/api.git"}]}}"#;

    #[test]
    fn bitbucket_follows_next_and_strips_the_caller_from_clone_urls() {
        let one = format!(
            r#"{{"values":[{BB}],"next":"https://forge.test/api/repositories/ws?pagelen=100&page=2"}}"#
        );
        let two = r#"{"values":[{"full_name":"ws/void","links":{"clone":[{"name":"https","href":"https://bitbucket.test/ws/void.git"}]},"mainbranch":null}]}"#;
        let mut fetch = server(&[
            (
                "https://forge.test/api/repositories/ws?pagelen=100",
                200,
                &one,
            ),
            (
                "https://forge.test/api/repositories/ws?pagelen=100&page=2",
                200,
                two,
            ),
        ]);
        let repos = bitbucket(API, "ws", &mut fetch).unwrap();
        assert_eq!(ids(&repos), vec!["ws/api"]);
        assert_eq!(repos[0].clone_url, "https://bitbucket.test/ws/api.git");
        assert_eq!(repos[0].default_branch.as_deref(), Some("trunk"));
        assert!(repos[0].fork);
    }

    #[test]
    fn a_next_link_off_the_api_never_receives_the_token() {
        let body = r#"{"values":[],"next":"https://evil.test/steal"}"#;
        let mut fetch = server(&[(
            "https://forge.test/api/repositories/ws?pagelen=100",
            200,
            body,
        )]);
        assert!(bitbucket(API, "ws", &mut fetch)
            .unwrap_err()
            .contains("left the API"));
    }

    #[test]
    fn bitbucket_server_pages_by_next_start() {
        let repo = |slug: &str, extra: &str| {
            format!(
                r#"{{"id":7,"slug":"{slug}","scmId":"git","project":{{"key":"CAT"}},{extra}
                "links":{{"clone":[{{"name":"ssh","href":"ssh://git@bb.test:7999/cat/{slug}.git"}},
                {{"name":"http","href":"https://admin@bb.test/scm/cat/{slug}.git"}}]}}}}"#
            )
        };
        let one = format!(
            r#"{{"values":[{}],"isLastPage":false,"nextPageStart":12}}"#,
            repo("a", r#""archived":true,"origin":{"slug":"up"},"#)
        );
        let two = format!(r#"{{"values":[{}],"isLastPage":true}}"#, repo("b", ""));
        let mut fetch = server(&[
            (
                "https://forge.test/api/projects/CAT/repos?limit=100&start=0",
                200,
                &one,
            ),
            (
                "https://forge.test/api/projects/CAT/repos?limit=100&start=12",
                200,
                &two,
            ),
        ]);
        let repos = bitbucket_server(API, "CAT", &mut fetch).unwrap();
        assert_eq!(ids(&repos), vec!["CAT/a", "CAT/b"]);
        assert_eq!(repos[0].clone_url, "https://bb.test/scm/cat/a.git");
        assert!(repos[0].archived && repos[0].fork && !repos[1].fork);
    }

    #[test]
    fn bitbucket_server_refuses_a_pager_that_does_not_advance() {
        let body = r#"{"values":[],"isLastPage":false,"nextPageStart":0}"#;
        let mut fetch = server(&[(
            "https://forge.test/api/projects/CAT/repos?limit=100&start=0",
            200,
            body,
        )]);
        assert!(bitbucket_server(API, "CAT", &mut fetch).is_err());
    }

    fn azure_repo(project: &str, name: &str, extra: &str) -> String {
        format!(
            r#"{{"id":"g-{name}","name":"{name}","project":{{"name":"{project}"}},{extra}
            "remoteUrl":"https://org@dev.azure.test/org/{project}/_git/{name}"}}"#
        )
    }

    #[test]
    fn azure_names_repos_by_org_project_and_repo() {
        let body = format!(
            r#"{{"count":3,"value":[{},{},{}]}}"#,
            azure_repo(
                "My Project",
                "api",
                r#""defaultBranch":"refs/heads/main","isFork":true,"#
            ),
            azure_repo("p", "void", ""),
            azure_repo(
                "p",
                "old",
                r#""defaultBranch":"refs/heads/dev","isDisabled":true,"#
            ),
        );
        let url = "https://forge.test/api/org/_apis/git/repositories?api-version=6.0";
        let mut fetch = server(&[(url, 200, &body)]);
        let repos = azure(API, "org", &mut fetch).unwrap();
        assert_eq!(ids(&repos), vec!["org/My-Project/api", "org/p/old"]);
        assert_eq!(repos[0].default_branch.as_deref(), Some("main"));
        assert!(repos[0].clone_url.starts_with("https://dev.azure.test/"));
        assert!(repos[0].fork && repos[1].archived);
    }

    #[test]
    fn azure_scopes_to_a_project_and_treats_sign_in_as_failure() {
        let url = "https://forge.test/api/org/My%20Project/_apis/git/repositories?api-version=6.0";
        for status in [203, 302] {
            let mut fetch = server(&[(url, status, "<html>sign in</html>")]);
            let error = azure(API, "org/My Project", &mut fetch).unwrap_err();
            assert!(error.contains("sign-in"), "{error}");
        }
        let mut fetch = server(&[(url, 200, "<html>sign in</html>")]);
        assert!(azure(API, "org/My Project", &mut fetch).is_err());
    }

    #[test]
    fn azure_refuses_a_short_list_and_a_shared_id() {
        let url = "https://forge.test/api/org/_apis/git/repositories?api-version=6.0";
        let mut fetch = server(&[(url, 200, r#"{"count":2,"value":[]}"#)]);
        assert!(azure(API, "org", &mut fetch).is_err());
        let extra = r#""defaultBranch":"refs/heads/main","#;
        let body = format!(
            r#"{{"count":2,"value":[{},{}]}}"#,
            azure_repo("a b", "r", extra),
            azure_repo("a-b", "r", extra),
        );
        let mut fetch = server(&[(url, 200, &body)]);
        assert!(azure(API, "org", &mut fetch).unwrap_err().contains("a-b/r"));
    }
}
