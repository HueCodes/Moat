//! Minimal ANSI styling helpers. No dependency; respects `NO_COLOR`.
//!
//! Terminals that don't understand the escapes will see the raw bytes, but in
//! 2026 that's essentially none of them; we honor the de facto `NO_COLOR`
//! convention for users who opt out.

use std::io::IsTerminal;
use std::sync::OnceLock;

static COLOR_ENABLED: OnceLock<bool> = OnceLock::new();

fn colors_on() -> bool {
    *COLOR_ENABLED.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        std::io::stdout().is_terminal()
    })
}

/// Force color output off for the remainder of the process (used by `--json`).
pub fn disable_colors() {
    let _ = COLOR_ENABLED.set(false);
}

fn wrap(code: &str, s: &str) -> String {
    if colors_on() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    wrap("1", s)
}
pub fn dim(s: &str) -> String {
    wrap("2", s)
}
pub fn green(s: &str) -> String {
    wrap("32", s)
}
pub fn red(s: &str) -> String {
    wrap("31", s)
}
pub fn yellow(s: &str) -> String {
    wrap("33", s)
}
pub fn cyan(s: &str) -> String {
    wrap("36", s)
}
pub fn magenta(s: &str) -> String {
    wrap("35", s)
}

pub fn check() -> String {
    green("✓")
}
pub fn cross() -> String {
    red("✗")
}
pub fn arrow() -> String {
    cyan("→")
}
