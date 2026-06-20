//! A user-configured Sign-in browser (ADR 0033): spawn `command` with `{url}`
//! substituted. Lets the user route Sign-in through a private/incognito window
//! (e.g. `firefox -private-window {url}`, `chrome --incognito {url}`) so the
//! Identity Center portal cookie is isolated from other browser-based AWS tools
//! like the CLI.
//!
//! The command is parsed **shell-free**: whitespace-split, `{url}` substituted as a
//! standalone argument (never interpolated into a shell line), so the authorize
//! URL — which carries `&`, `?`, `=` — can't be reinterpreted. The parse
//! ([`build_browser_command`]) is pure and unit-tested; only the spawn is shell.

use std::process::Command;

use crate::browser::BrowserOpener;
use crate::error::SignInError;

/// Opens Sign-in by spawning a configured command. See module docs.
pub struct CommandBrowser {
    command: String,
}

impl CommandBrowser {
    pub fn new(command: String) -> Self {
        CommandBrowser { command }
    }
}

impl BrowserOpener for CommandBrowser {
    fn open(&self, url: &str) -> Result<(), SignInError> {
        let (program, args) =
            build_browser_command(&self.command, url).ok_or(SignInError::BrowserLaunch)?;
        tracing::info!(target: "janitor::aws", surface = "command", %program, "Opening Sign-in browser");
        Command::new(program)
            .args(args)
            .spawn()
            .map(|_child| ())
            .map_err(|_| SignInError::BrowserLaunch)
    }
}

/// Parse a `browser_command` into `(program, args)` with `{url}` substituted.
///
/// - Whitespace-split (shell-free). `{url}` is replaced wherever it appears.
/// - If no token contains `{url}`, the URL is appended as a trailing argument, so
///   `chrome --incognito` works as well as `chrome --incognito {url}`.
/// - Returns `None` for a blank/whitespace-only command.
///
/// ponytail: whitespace split — the program path can't contain spaces. Upgrade to
///           `shell-words` only if a real command needs quoted/spaced args.
fn build_browser_command(command: &str, url: &str) -> Option<(String, Vec<String>)> {
    let mut tokens = command.split_whitespace();
    let program = tokens.next()?; // None → blank command
    let mut had_placeholder = program.contains("{url}");
    let program = program.replace("{url}", url);
    let mut args: Vec<String> = tokens
        .map(|t| {
            had_placeholder |= t.contains("{url}");
            t.replace("{url}", url)
        })
        .collect();
    if !had_placeholder {
        args.push(url.to_string());
    }
    Some((program, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://oidc.example/authorize?client_id=abc&state=xyz";

    #[test]
    fn substitutes_url_placeholder_as_one_standalone_arg() {
        let (program, args) = build_browser_command("firefox -private-window {url}", URL).unwrap();
        assert_eq!(program, "firefox");
        // The URL stays ONE arg — its `&`/`?`/`=` are never split or shell-parsed.
        assert_eq!(args, vec!["-private-window".to_string(), URL.to_string()]);
    }

    #[test]
    fn appends_url_when_no_placeholder() {
        let (program, args) = build_browser_command("chrome --incognito", URL).unwrap();
        assert_eq!(program, "chrome");
        assert_eq!(args, vec!["--incognito".to_string(), URL.to_string()]);
    }

    #[test]
    fn placeholder_present_is_not_also_appended() {
        let (program, args) = build_browser_command("open -a Safari {url}", URL).unwrap();
        assert_eq!(program, "open");
        assert_eq!(
            args,
            vec!["-a".to_string(), "Safari".to_string(), URL.to_string()]
        );
    }

    #[test]
    fn blank_command_is_none() {
        assert!(build_browser_command("   ", URL).is_none());
        assert!(build_browser_command("", URL).is_none());
    }
}
