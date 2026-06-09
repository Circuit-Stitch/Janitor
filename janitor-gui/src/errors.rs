//! The error banner string, kept in a pure seam so its error-safety — it surfaces
//! only the `environment` + the already-scrubbed `detail`, never a Value /
//! Credential / token — is unit-testable (ADR 0003 / ADR 0017; THREAT-MODEL). The
//! `MainWindow`-coupled `apply_event` glue calls this and pushes the result; it has
//! no formatting logic of its own.

use janitor_core::provider::AppError;

/// `"<env>: <real AWS detail>; …"` — one `environment: detail` clause per failed
/// Environment, joined by `; `. ADR 0017: the banner shows the real, error-safe
/// `detail` (the same scrubbed text the Diagnostic Log carries), so an operator
/// sees *why* a load failed — never a Value/Credential/token, which `Failure`
/// already excludes by construction.
pub fn banner(err: &AppError) -> String {
    err.failures
        .iter()
        .map(|f| format!("{}: {}", f.environment, f.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use janitor_core::provider::{Failure, FetchFailReason};

    fn failure(environment: &str, detail: &str) -> Failure {
        Failure {
            environment: environment.into(),
            reason: FetchFailReason::Other,
            detail: detail.into(),
        }
    }

    #[test]
    fn one_failure_is_environment_then_detail() {
        let err = AppError {
            failures: vec![failure("prod", "secret not found")],
        };
        assert_eq!(banner(&err), "prod: secret not found");
    }

    #[test]
    fn multiple_failures_join_with_semicolons() {
        let err = AppError {
            failures: vec![
                failure("prod", "access denied"),
                failure("staging", "throttled, try again"),
            ],
        };
        assert_eq!(
            banner(&err),
            "prod: access denied; staging: throttled, try again"
        );
    }

    #[test]
    fn no_failures_is_empty() {
        let err = AppError {
            failures: Vec::new(),
        };
        assert_eq!(banner(&err), "");
    }

    #[test]
    fn surfaces_only_the_environment_and_scrubbed_detail() {
        // Error-safety property (THREAT-MODEL / ADR 0017): the banner is built from
        // exactly two fields — the Environment name and the scrubbed `detail`. The
        // classified `reason` and anything secret-shaped never appear. Here `detail`
        // is the safe text the Provider produced; assert nothing else leaks in.
        let err = AppError {
            failures: vec![failure("prod", "secret not found")],
        };
        let line = banner(&err);
        assert!(line.contains("prod") && line.contains("secret not found"));
        // The banner is purely `"{environment}: {detail}"` — no extra fields.
        assert_eq!(line, "prod: secret not found");
    }
}
