//! `[settings.fix]`: when `fix apply` may publish, how edits share a branch, whether verified
//! requests merge themselves, and how fast a campaign spreads across the fleet (spec 16,
//! row 5, phase B).
//!
//! ```toml
//! [settings.fix]
//! schedule = ["mon-fri 09:00-17:00"]   # when --push and --open-pr may publish
//! timezone = "Europe/Paris"            # IANA name; UTC by default
//! group = "package"                    # or "repo", or "ssvc"
//! automerge = "verified"               # or "off" (default)
//! merge_method = "squash"              # or "merge", "rebase"
//! rollout = [1, 5]                     # repos per wave; the rest after the last wave
//! ```

use jiff::civil::{Time, Weekday};
use jiff::tz::TimeZone;
use jiff::{ToSpan, Zoned};
use serde::Deserialize;

/// The raw `[settings.fix]` block.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFix {
    #[serde(default)]
    schedule: Vec<String>,
    timezone: Option<String>,
    group: Option<String>,
    automerge: Option<String>,
    merge_method: Option<String>,
    #[serde(default)]
    rollout: Vec<usize>,
}

/// How a repo's edits are split into branches and requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Group {
    /// One request per package bump (the default).
    #[default]
    Package,
    /// One request per repo with every bump in it.
    Repo,
    /// One request per repo and SSVC outcome, so an `immediate` fix never waits on a
    /// `defer` one.
    Ssvc,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MergeMethod {
    #[default]
    Squash,
    Merge,
    Rebase,
}

impl MergeMethod {
    /// The flag `gh pr merge` and `glab mr merge` take for it.
    pub fn flag(self) -> &'static str {
        match self {
            MergeMethod::Squash => "--squash",
            MergeMethod::Merge => "--merge",
            MergeMethod::Rebase => "--rebase",
        }
    }
}

/// A weekly window: the days it opens on and the minutes of the day, `end` exclusive. An
/// `end` at or before `start` runs past midnight into the next day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    days: [bool; 7],
    start: u16,
    end: u16,
}

#[derive(Debug, Clone)]
pub struct FixSettings {
    pub schedule: Vec<Window>,
    pub timezone: TimeZone,
    pub timezone_name: String,
    pub group: Group,
    pub automerge: bool,
    pub merge_method: MergeMethod,
    pub rollout: Vec<usize>,
}

impl Default for FixSettings {
    fn default() -> Self {
        FixSettings {
            schedule: Vec::new(),
            timezone: TimeZone::UTC,
            timezone_name: "UTC".to_string(),
            group: Group::Package,
            automerge: false,
            merge_method: MergeMethod::Squash,
            rollout: Vec::new(),
        }
    }
}

impl RawFix {
    pub(crate) fn parse(self) -> Result<FixSettings, String> {
        let schedule = self
            .schedule
            .iter()
            .map(|w| parse_window(w).map_err(|e| format!("schedule `{w}`: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let timezone_name = self.timezone.unwrap_or_else(|| "UTC".to_string());
        let timezone = TimeZone::get(&timezone_name)
            .map_err(|_| format!("timezone `{timezone_name}` is not an IANA time zone name"))?;
        let group = match self.group.as_deref() {
            None | Some("package") => Group::Package,
            Some("repo") => Group::Repo,
            Some("ssvc") => Group::Ssvc,
            Some(other) => {
                return Err(format!(
                    "group `{other}` is not `package`, `repo` or `ssvc`"
                ))
            }
        };
        let automerge = match self.automerge.as_deref() {
            None | Some("off") => false,
            Some("verified") => true,
            Some(other) => return Err(format!("automerge `{other}` is not `off` or `verified`")),
        };
        let merge_method = match self.merge_method.as_deref() {
            None | Some("squash") => MergeMethod::Squash,
            Some("merge") => MergeMethod::Merge,
            Some("rebase") => MergeMethod::Rebase,
            Some(other) => {
                return Err(format!(
                    "merge_method `{other}` is not `squash`, `merge` or `rebase`"
                ))
            }
        };
        if self.rollout.contains(&0) {
            return Err("rollout waves must each have at least one repo".to_string());
        }
        // A grouped branch carries several campaigns, so no one campaign's wave can gate it.
        if !self.rollout.is_empty() && group != Group::Package {
            return Err(
                "rollout needs group = \"package\": a grouped request spans \
                        several campaigns"
                    .to_string(),
            );
        }
        Ok(FixSettings {
            schedule,
            timezone,
            timezone_name,
            group,
            automerge,
            merge_method,
            rollout: self.rollout,
        })
    }
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// `mon-fri 09:00-17:00`, `sat,sun 00:00-24:00`, `22:00-06:00` (every day, past midnight).
fn parse_window(text: &str) -> Result<Window, String> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let (days_text, hours) = match parts.as_slice() {
        [hours] => ("*", *hours),
        [days, hours] => (*days, *hours),
        _ => return Err("expected `[days] HH:MM-HH:MM`".to_string()),
    };
    let mut days = [false; 7];
    if days_text == "*" {
        days = [true; 7];
    } else {
        for item in days_text.to_ascii_lowercase().split(',') {
            let index = |d: &str| {
                DAYS.iter()
                    .position(|n| *n == d)
                    .ok_or_else(|| format!("`{d}` is not a day (mon to sun)"))
            };
            match item.split_once('-') {
                Some((a, b)) => {
                    let (a, b) = (index(a)?, index(b)?);
                    let mut i = a;
                    loop {
                        days[i] = true;
                        if i == b {
                            break;
                        }
                        i = (i + 1) % 7;
                    }
                }
                None => days[index(item)?] = true,
            }
        }
    }
    let (start, end) = hours
        .split_once('-')
        .ok_or_else(|| "expected hours as HH:MM-HH:MM".to_string())?;
    let (start, end) = (minutes(start)?, minutes(end)?);
    if start == end {
        return Err("the window is empty".to_string());
    }
    Ok(Window { days, start, end })
}

/// `HH:MM` as minutes since midnight; `24:00` is the end of the day.
fn minutes(text: &str) -> Result<u16, String> {
    let bad = || format!("`{text}` is not HH:MM");
    let (h, m) = text.split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let (h, m): (u16, u16) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if m > 59 || h > 24 || (h == 24 && m != 0) {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

fn day_index(day: Weekday) -> usize {
    usize::from(day.to_monday_zero_offset().unsigned_abs())
}

impl Window {
    /// Whether the window is open at this weekday and minute of the day.
    fn contains(&self, day: usize, minute: u16) -> bool {
        if self.start < self.end {
            self.days[day] && (self.start..self.end).contains(&minute)
        } else {
            // Past midnight: the evening of an open day, or the morning after one.
            (self.days[day] && minute >= self.start)
                || (self.days[(day + 6) % 7] && minute < self.end)
        }
    }
}

impl FixSettings {
    /// Whether the schedule lets a run publish now. No schedule means always.
    pub fn open_at(&self, now: &Zoned) -> bool {
        if self.schedule.is_empty() {
            return true;
        }
        let local = now.with_time_zone(self.timezone.clone());
        let minute = u16::try_from(local.hour()).unwrap_or(0) * 60
            + u16::try_from(local.minute()).unwrap_or(0);
        let day = day_index(local.weekday());
        self.schedule.iter().any(|w| w.contains(day, minute))
    }

    /// When the schedule next opens after `now`, in its own time zone.
    pub fn next_open(&self, now: &Zoned) -> Option<Zoned> {
        let local = now.with_time_zone(self.timezone.clone());
        let mut best: Option<Zoned> = None;
        for offset in 0..8i64 {
            let date = local.date().checked_add(offset.days()).ok()?;
            for w in &self.schedule {
                if !w.days[day_index(date.weekday())] || w.start >= 24 * 60 {
                    continue;
                }
                let start = Time::new(
                    i8::try_from(w.start / 60).ok()?,
                    i8::try_from(w.start % 60).ok()?,
                    0,
                    0,
                )
                .ok()?;
                let Ok(at) = date.to_datetime(start).to_zoned(self.timezone.clone()) else {
                    continue;
                };
                if at > local && best.as_ref().is_none_or(|b| at < *b) {
                    best = Some(at);
                }
            }
        }
        best
    }

    /// How many new requests a campaign may open now, given how many of its requests are
    /// merged, open, and closed unmerged. `None` is no limit.
    pub fn rollout_allowance(&self, merged: usize, open: usize, closed: usize) -> RolloutGate {
        if self.rollout.is_empty() {
            return RolloutGate::Open(None);
        }
        if closed > 0 {
            return RolloutGate::Stopped;
        }
        if open > 0 {
            return RolloutGate::Waiting;
        }
        let mut boundary = 0usize;
        for wave in &self.rollout {
            boundary += wave;
            if merged < boundary {
                return RolloutGate::Open(Some(boundary - merged));
            }
        }
        RolloutGate::Open(None)
    }
}

/// What the rollout lets a campaign do this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolloutGate {
    /// Open this many new requests (`None`: any number).
    Open(Option<usize>),
    /// The current wave's requests are still open.
    Waiting,
    /// A request of this campaign was closed without merging: no more waves.
    Stopped,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn settings(toml_text: &str) -> Result<FixSettings, String> {
        toml::from_str::<RawFix>(toml_text)
            .map_err(|e| e.to_string())?
            .parse()
    }

    fn at(text: &str) -> Zoned {
        text.parse().unwrap()
    }

    #[test]
    fn defaults_change_nothing() {
        let s = settings("").unwrap();
        assert_eq!(s.group, Group::Package);
        assert!(!s.automerge);
        assert!(s.open_at(&at("2026-11-14T03:00:00+00:00[UTC]")));
        assert_eq!(s.rollout_allowance(0, 0, 0), RolloutGate::Open(None));
    }

    #[test]
    fn weekday_window_in_its_own_time_zone() {
        let s = settings(
            r#"schedule = ["mon-fri 09:00-17:00"]
               timezone = "Europe/Paris""#,
        )
        .unwrap();
        // Thursday 2026-11-12, 08:30 UTC is 09:30 in Paris (UTC+1 in November).
        assert!(s.open_at(&at("2026-11-12T08:30:00+00:00[UTC]")));
        // 07:30 UTC is 08:30 in Paris: not yet.
        assert!(!s.open_at(&at("2026-11-12T07:30:00+00:00[UTC]")));
        // 16:00 UTC is 17:00 in Paris: the end is exclusive.
        assert!(!s.open_at(&at("2026-11-12T16:00:00+00:00[UTC]")));
        // Saturday.
        assert!(!s.open_at(&at("2026-11-14T10:00:00+00:00[UTC]")));
        // Summer time: 07:30 UTC on Thursday 2026-07-02 is 09:30 in Paris (UTC+2).
        assert!(s.open_at(&at("2026-07-02T07:30:00+00:00[UTC]")));
        let next = s.next_open(&at("2026-11-13T17:00:00+00:00[UTC]")).unwrap();
        assert_eq!(next.to_string(), "2026-11-16T09:00:00+01:00[Europe/Paris]");
    }

    #[test]
    fn overnight_window_runs_into_the_next_day() {
        let s = settings(r#"schedule = ["fri 22:00-06:00"]"#).unwrap();
        assert!(s.open_at(&at("2026-11-13T23:00:00+00:00[UTC]"))); // Friday night
        assert!(s.open_at(&at("2026-11-14T05:59:00+00:00[UTC]"))); // Saturday morning
        assert!(!s.open_at(&at("2026-11-14T06:00:00+00:00[UTC]")));
        assert!(!s.open_at(&at("2026-11-13T05:00:00+00:00[UTC]"))); // Friday morning
        let s = settings(r#"schedule = ["sat,sun 00:00-24:00", "22:00-06:00"]"#).unwrap();
        assert!(s.open_at(&at("2026-11-15T12:00:00+00:00[UTC]")));
        assert!(s.open_at(&at("2026-11-12T03:00:00+00:00[UTC]")));
        assert!(!s.open_at(&at("2026-11-12T12:00:00+00:00[UTC]")));
        // A range that wraps the week.
        let s = settings(r#"schedule = ["sat-mon 10:00-11:00"]"#).unwrap();
        assert!(s.open_at(&at("2026-11-16T10:30:00+00:00[UTC]"))); // Monday
        assert!(!s.open_at(&at("2026-11-17T10:30:00+00:00[UTC]"))); // Tuesday
    }

    #[test]
    fn bad_settings_are_refused() {
        for (text, says) in [
            (r#"schedule = ["mon-fri 9-17"]"#, "is not HH:MM"),
            (r#"schedule = ["funday 09:00-10:00"]"#, "is not a day"),
            (r#"schedule = ["09:00-09:00"]"#, "empty"),
            (r#"schedule = ["24:30-01:00"]"#, "is not HH:MM"),
            (r#"timezone = "Mars/Olympus""#, "IANA"),
            (r#"group = "owner""#, "is not `package`"),
            (r#"automerge = "always""#, "is not `off`"),
            (r#"merge_method = "ff""#, "merge_method"),
            ("rollout = [1, 0]", "at least one"),
            ("rollout = [1]\ngroup = \"repo\"", "rollout needs group"),
            ("shedule = []", "unknown field"),
        ] {
            let err = settings(text).unwrap_err();
            assert!(err.contains(says), "{text}: {err}");
        }
    }

    #[test]
    fn rollout_opens_one_wave_at_a_time() {
        let s = settings("rollout = [1, 5]").unwrap();
        assert_eq!(s.rollout_allowance(0, 0, 0), RolloutGate::Open(Some(1)));
        assert_eq!(s.rollout_allowance(0, 1, 0), RolloutGate::Waiting);
        assert_eq!(s.rollout_allowance(1, 0, 0), RolloutGate::Open(Some(5)));
        assert_eq!(s.rollout_allowance(3, 2, 0), RolloutGate::Waiting);
        assert_eq!(s.rollout_allowance(6, 0, 0), RolloutGate::Open(None));
        assert_eq!(s.rollout_allowance(1, 0, 1), RolloutGate::Stopped);
    }
}
