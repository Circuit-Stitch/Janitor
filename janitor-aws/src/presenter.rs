//! A thin **stdin presenter** for the shared [`Discovery`] step-machine
//! (ADR 0013, issue #11): it drives `start()`/`advance()` to a terminal `Step`,
//! rendering each `Ask` as a numbered menu read from stdin. This is the CLI
//! consumer of the same engine the GUI drives, proving it is genuinely generic.
//!
//! The interactive loop and the menu render/parse (the old `live-verify`
//! `StdinChooser`) live here, behind `Read`/`Write` seams, so they are tested
//! against `wire::fakes` rather than real stdin (ADR 0003).

use std::io::{self, BufRead, Write};

use crate::discovery::Discovery;
use janitor_core::provider::{Step, What};

/// Drive `discovery` to a terminal `Step`, presenting each `Ask` as a numbered
/// menu written to `output` and resolved by a line read from `input`. Returns
/// the terminal `Step` (`Done`/`Empty`/`Failed`/`Reauth`) for the caller to act
/// on (fetch, or report). Auto-picked (singleton) steps consume no input.
pub async fn drive_discovery<R: BufRead, W: Write>(
    discovery: &mut Discovery,
    input: &mut R,
    output: &mut W,
) -> io::Result<Step> {
    let mut step = discovery.start().await;
    loop {
        match step {
            Step::Ask {
                what,
                choices,
                default,
            } => {
                let choice = prompt_choice(input, output, what, &choices, default)?;
                step = discovery.advance(choice).await;
            }
            terminal => return Ok(terminal),
        }
    }
}

/// Title line for an `Ask`, named by `what` (matches the GUI picker's prompts).
fn what_title(what: What) -> &'static str {
    match what {
        What::Accounts => "Choose an account:",
        What::Roles => "Choose a role:",
        What::Secrets => "Choose a secret:",
    }
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
}
