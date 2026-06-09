//! A thin **stdin presenter** for the shared [`Discovery`] step-machine
//! (ADR 0013, issue #11): it drives `start()`/`advance()` to a terminal `Step`,
//! rendering each `Ask` as a numbered menu read from stdin. This is the CLI
//! consumer of the same engine the GUI drives, proving it is genuinely generic.
//!
//! The interactive loop and the menu render/parse (the old `live-verify`
//! `StdinChooser`) live here, behind `Read`/`Write` seams, so they are tested
//! against `wire::fakes` rather than real stdin (ADR 0003).

use std::io::{self, BufRead, Write};

use async_trait::async_trait;

use crate::discovery::Discovery;
use janitor_core::provider::{FetchFailReason, Step, What};

/// The minimal step-machine seam [`drive_discovery`] drives (ADR 0013): begin the
/// walk, feed back a picked index for an `Ask`, or feed back typed text for an
/// `Input` (ADR 0025). [`Discovery`] is the production implementor; gating the
/// presenter on this seam (rather than the concrete `Discovery`) lets a test fake
/// emit a `Step::Input` the Secrets Manager walk never produces, so the new
/// `Input` arm is exercised without a Provider that poses one. Local to
/// `janitor-aws` — this is a presenter seam, not the `core` Discovery orchestrator
/// (#33 / ADR 0026).
#[async_trait]
pub trait Walk {
    async fn start(&mut self) -> Step;
    async fn advance(&mut self, choice: usize) -> Step;
    async fn provide_input(&mut self, text: String) -> Step;
}

#[async_trait]
impl Walk for Discovery {
    async fn start(&mut self) -> Step {
        Discovery::start(self).await
    }
    async fn advance(&mut self, choice: usize) -> Step {
        Discovery::advance(self, choice).await
    }
    async fn provide_input(&mut self, _text: String) -> Step {
        // The Secrets Manager walk only ever poses account/role/secret `Ask`s, so
        // this is reachable only through a presenter bug. Fail closed rather than
        // pretend to advance — `Discovery` never emits `Step::Input` (ADR 0025).
        Step::Failed(FetchFailReason::Other)
    }
}

/// Drive `walk` to a terminal `Step`, presenting each `Ask` as a numbered menu and
/// each `Input` as a free-text prompt, written to `output` and resolved by a line
/// read from `input`. Returns the terminal `Step` (`Done`/`Empty`/`Failed`/`Reauth`)
/// for the caller to act on (fetch, or report). Auto-picked (singleton) steps
/// consume no input. The match is exhaustive over every `Step` variant so a new
/// one can never be silently treated as terminal (ADR 0025).
pub async fn drive_discovery<M: Walk, R: BufRead, W: Write>(
    walk: &mut M,
    input: &mut R,
    output: &mut W,
) -> io::Result<Step> {
    let mut step = walk.start().await;
    loop {
        match step {
            Step::Ask {
                what,
                choices,
                default,
            } => {
                let choice = prompt_choice(input, output, what, &choices, default)?;
                step = walk.advance(choice).await;
            }
            Step::Input {
                prompt, default, ..
            } => {
                let text = prompt_input(input, output, &prompt, default.as_deref())?;
                step = walk.provide_input(text).await;
            }
            Step::Done(_) | Step::Empty(_) | Step::Failed(_) | Step::Reauth => return Ok(step),
        }
    }
}

/// Title line for an `Ask`, named by `what` (matches the GUI picker's prompts).
fn what_title(what: What) -> &'static str {
    match what {
        What::Accounts => "Choose an account:",
        What::Roles => "Choose a role:",
        What::Secrets => "Choose a secret:",
        What::Instances => "Choose an instance:",
        What::FilePath => "Enter a path:",
    }
}

/// Render an `Input` prompt and read one line of free text (ADR 0025). Empty input
/// (Enter or EOF) accepts the `default` if any, else yields an empty string —
/// mirroring `prompt_choice`'s Enter-accepts-default behavior. The typed text is a
/// location (e.g. a `.env` path), never a Value.
fn prompt_input<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    prompt: &str,
    default: Option<&str>,
) -> io::Result<String> {
    writeln!(output)?;
    match default {
        Some(d) => write!(output, "{prompt} [default {d}]: ")?,
        None => write!(output, "{prompt}: ")?,
    }
    output.flush()?;

    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        // EOF: accept the default if any, else empty.
        return Ok(default.unwrap_or("").to_string());
    }
    let typed = line.trim();
    if typed.is_empty() {
        return Ok(default.unwrap_or("").to_string());
    }
    Ok(typed.to_string())
}

/// Render the numbered menu and read a valid 1-based choice, re-prompting on
/// invalid input. Returns the chosen 0-based index.
fn prompt_choice<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    what: What,
    choices: &[String],
    default: Option<usize>,
) -> io::Result<usize> {
    loop {
        writeln!(output)?;
        writeln!(output, "{}", what_title(what))?;
        for (i, label) in choices.iter().enumerate() {
            let marker = if Some(i) == default { " (default)" } else { "" };
            writeln!(output, "  [{}] {label}{marker}", i + 1)?;
        }
        match default {
            Some(i) => write!(output, "choose 1-{} [default {}]: ", choices.len(), i + 1)?,
            None => write!(output, "choose 1-{}: ", choices.len())?,
        }
        output.flush()?;

        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            // EOF: accept the default if any, else the first item.
            return Ok(default.unwrap_or(0));
        }
        if let Some(i) = parse_choice(&line, choices.len(), default) {
            return Ok(i);
        }
        writeln!(output, "  invalid choice, try again")?;
    }
}

/// Interpret a typed line against `n` choices and an optional default. `Some(i)`
/// is the chosen 0-based index; `None` means re-prompt (invalid, or empty with
/// no default). Empty input accepts the default (Enter).
fn parse_choice(line: &str, n: usize, default: Option<usize>) -> Option<usize> {
    let s = line.trim();
    if s.is_empty() {
        return default;
    }
    match s.parse::<usize>() {
        Ok(k) if (1..=n).contains(&k) => Some(k - 1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::FakeSecretsApi;
    use crate::wire::SecretSummary;
    use janitor_aws_auth::types::SsoToken;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
    use janitor_aws_auth::wire::{AccountSummary, RoleSummary};
    use janitor_core::config::Mapping;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    fn token() -> Arc<SsoToken> {
        Arc::new(SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ))
    }
    fn account(id: &str, name: &str) -> AccountSummary {
        AccountSummary {
            id: id.into(),
            name: name.into(),
        }
    }
    fn role(name: &str) -> RoleSummary {
        RoleSummary { name: name.into() }
    }
    fn secret(name: &str, arn: &str) -> SecretSummary {
        SecretSummary {
            name: name.into(),
            arn: arn.into(),
        }
    }
    fn cred_ok() -> Result<CredSpec, janitor_aws_auth::error::SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }

    /// Build a single-choice walk that should auto-pick straight to Done.
    fn singleton_discovery() -> Discovery {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111111111111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "myapp/prod",
            "arn:aws:secretsmanager:us-west-2:111111111111:secret:myapp/prod",
        )])]));
        Discovery::new(
            "prod".into(),
            "us-west-2".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        )
    }

    /// Two accounts → an Ask; the rest of the walk is singletons.
    fn two_account_discovery(remembered: Option<Mapping>) -> Discovery {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "myapp/s",
            "arn:secret:myapp/s",
        )])]));
        Discovery::new(
            "env".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            remembered,
        )
    }

    #[tokio::test]
    async fn many_choices_render_a_numbered_menu_and_a_typed_pick_advances() {
        let mut d = two_account_discovery(None);
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::<u8>::new();

        let step = drive_discovery(&mut d, &mut input, &mut output)
            .await
            .expect("drive");

        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.account_id, "222", "typed '2' chose the second account");

        let rendered = String::from_utf8(output).unwrap();
        assert!(
            rendered.contains("[1] Prod (111)"),
            "menu line 1: {rendered}"
        );
        assert!(
            rendered.contains("[2] Staging (222)"),
            "menu line 2: {rendered}"
        );
    }

    #[tokio::test]
    async fn empty_line_accepts_the_remembered_default() {
        // A prior pick chose account 222 → it pre-selects (index 1) and the menu
        // marks it; pressing Enter (empty line) accepts it.
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "222".into(),
            region: "us-east-1".into(),
            secret_id: "arn:old".into(),
            permission_set: "ReadOnly".into(),
            method: janitor_core::config::Method::SecretsManager,
        };
        let mut d = two_account_discovery(Some(remembered));
        let mut input = Cursor::new(b"\n".to_vec());
        let mut output = Vec::<u8>::new();

        let Step::Done(m) = drive_discovery(&mut d, &mut input, &mut output)
            .await
            .expect("drive")
        else {
            panic!("expected Done");
        };
        assert_eq!(m.account_id, "222", "Enter accepted the remembered default");

        let rendered = String::from_utf8(output).unwrap();
        assert!(
            rendered.contains("[2] Staging (222) (default)"),
            "default is marked: {rendered}"
        );
        assert!(
            rendered.contains("[default 2]"),
            "hint names the default: {rendered}"
        );
    }

    #[tokio::test]
    async fn invalid_input_reprompts_then_accepts_a_valid_choice() {
        let mut d = two_account_discovery(None);
        // out-of-range, then non-numeric, then a valid pick.
        let mut input = Cursor::new(b"9\nabc\n1\n".to_vec());
        let mut output = Vec::<u8>::new();

        let Step::Done(m) = drive_discovery(&mut d, &mut input, &mut output)
            .await
            .expect("drive")
        else {
            panic!("expected Done");
        };
        assert_eq!(m.account_id, "111", "the valid '1' was accepted");

        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(
            rendered.matches("invalid choice, try again").count(),
            2,
            "two invalid lines were rejected: {rendered}"
        );
    }

    #[tokio::test]
    async fn empty_and_failed_walks_pass_their_terminal_step_through() {
        use janitor_core::provider::FetchFailReason;
        // No accounts → Empty(Accounts), surfaced for the caller to message.
        let mut empty = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            Arc::new(FakeAccountCatalog::new(vec![Ok(vec![])], vec![])),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeSecretsApi::with_lists(vec![])),
            None,
        );
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::<u8>::new();
        let step = drive_discovery(&mut empty, &mut input, &mut output)
            .await
            .expect("drive");
        assert!(matches!(step, Step::Empty(What::Accounts)), "got {step:?}");
        assert!(output.is_empty(), "no menu for an empty walk");

        // An access-denied listing → Failed(reason), not a panic or a menu.
        let mut failed = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![account("111", "Prod")])],
                vec![Err(janitor_aws_auth::error::SessionError::AccessDenied)],
            )),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeSecretsApi::with_lists(vec![])),
            None,
        );
        let mut input2 = Cursor::new(Vec::<u8>::new());
        let mut output2 = Vec::<u8>::new();
        let Step::Failed(reason) = drive_discovery(&mut failed, &mut input2, &mut output2)
            .await
            .expect("drive")
        else {
            panic!("expected Failed");
        };
        assert_eq!(reason, FetchFailReason::AccessDenied);
    }

    #[tokio::test]
    async fn singleton_walk_auto_picks_to_done_without_reading_input() {
        let mut d = singleton_discovery();
        let mut input = Cursor::new(Vec::<u8>::new()); // empty: no prompt expected
        let mut output = Vec::<u8>::new();

        let step = drive_discovery(&mut d, &mut input, &mut output)
            .await
            .expect("drive");

        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.account_id, "111111111111");
        assert_eq!(m.permission_set, "ReadOnly");
        assert!(
            output.is_empty(),
            "no menu should be rendered for an all-singleton walk"
        );
    }

    /// A scripted [`Walk`] that poses a free-text `Input` and completes on the
    /// typed text. The Secrets Manager `Discovery` never emits `Step::Input`, so
    /// this fake is how the new `Input` arm is exercised (ADR 0025).
    struct FakeWalk {
        last_input: Option<String>,
    }

    #[async_trait::async_trait]
    impl Walk for FakeWalk {
        async fn start(&mut self) -> Step {
            Step::Input {
                what: What::FilePath,
                prompt: "Path to the remote .env".into(),
                default: Some("/app/.env".into()),
            }
        }
        async fn advance(&mut self, _choice: usize) -> Step {
            unreachable!("the fake walk poses no Ask")
        }
        async fn provide_input(&mut self, text: String) -> Step {
            self.last_input = Some(text.clone());
            Step::Done(Mapping {
                environment: "prod".into(),
                account_id: "111111111111".into(),
                region: "us-east-1".into(),
                secret_id: format!("i-0abc:{text}"),
                permission_set: "ReadOnly".into(),
                method: janitor_core::config::Method::SecretsManager,
            })
        }
    }

    #[tokio::test]
    async fn input_step_reads_a_typed_line_and_feeds_it_back() {
        // The free-text counterpart of the Ask menu: an `Input` step renders its
        // prompt, reads a line, and feeds the typed path back via `provide_input`.
        let mut walk = FakeWalk { last_input: None };
        let mut input = Cursor::new(b"/custom/path/.env\n".to_vec());
        let mut output = Vec::<u8>::new();

        let step = drive_discovery(&mut walk, &mut input, &mut output)
            .await
            .expect("drive");

        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(
            m.secret_id, "i-0abc:/custom/path/.env",
            "the typed path was fed back into the walk"
        );
        assert_eq!(walk.last_input.as_deref(), Some("/custom/path/.env"));

        let rendered = String::from_utf8(output).unwrap();
        assert!(
            rendered.contains("Path to the remote .env"),
            "the Input prompt is rendered: {rendered}"
        );
        assert!(
            rendered.contains("[default /app/.env]"),
            "the remembered default is offered: {rendered}"
        );
    }

    #[tokio::test]
    async fn input_step_empty_line_accepts_the_remembered_default() {
        // Pressing Enter on an `Input` accepts the remembered default (mirrors the
        // Ask menu's Enter-accepts-default behavior).
        let mut walk = FakeWalk { last_input: None };
        let mut input = Cursor::new(b"\n".to_vec());
        let mut output = Vec::<u8>::new();

        let Step::Done(m) = drive_discovery(&mut walk, &mut input, &mut output)
            .await
            .expect("drive")
        else {
            panic!("expected Done");
        };
        assert_eq!(
            m.secret_id, "i-0abc:/app/.env",
            "Enter accepted the remembered default path"
        );
        assert_eq!(walk.last_input.as_deref(), Some("/app/.env"));
    }
}
