//! Session-manager **logging detection** (ADR 0025, B4): a remote read over
//! Session Manager can be archived to S3/CloudWatch if the org enabled
//! session logging — config Janitor cannot disable (THREAT-MODEL accepted
//! residual risk). Before a read, Janitor detects the org's preference and warns
//! when logging is (or might be) on.
//!
//! The org's preference lives in the `SSM-SessionManagerRunShell` SSM **document**
//! (read with `ssm:GetDocument`); its `inputs.s3BucketName` /
//! `cloudWatchLogGroupName` say where sessions are logged, and `kmsKeyId` says
//! whether the data channel is KMS-encrypted. (ADR 0025 recalled this as
//! `GetServiceSetting`; the live spike corrected it to `GetDocument` — there is no
//! service setting for session logging.)
//!
//! Everything here is **pure, tested logic** except the one real `GetDocument`
//! call (the untested shell, in [`crate::transport`]): the document-body parse
//! ([`parse_logging`]) and the warn decision ([`session_logging_advisory`]) are
//! unit-tested against the [`fakes`]. The advisory string is a policy note — never
//! a Value, Credential, or any file content.

use async_trait::async_trait;

use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;

/// The org's Session Manager logging/encryption preferences, distilled from the
/// `SSM-SessionManagerRunShell` document to the three booleans that matter for a
/// remote read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoggingState {
    /// `inputs.s3BucketName` is set — sessions are archived to S3.
    pub s3: bool,
    /// `inputs.cloudWatchLogGroupName` is set — sessions stream to CloudWatch.
    pub cloudwatch: bool,
    /// `inputs.kmsKeyId` is set — the data channel is KMS-encrypted (which the
    /// pure-Rust transport does not support; a read will fail fast).
    pub kms: bool,
}

impl LoggingState {
    /// Whether a read's contents would be written to a logging destination.
    pub fn logs(&self) -> bool {
        self.s3 || self.cloudwatch
    }
}

/// Reads the org's Session Manager logging preference for a region. The real impl
/// ([`crate::transport::AwsLoggingPreference`]) calls `GetDocument`; the
/// orchestration is tested against [`fakes::FakeLoggingPreference`].
#[async_trait]
pub trait LoggingPreference: Send + Sync {
    /// `GetDocument(SSM-SessionManagerRunShell)` in `region`, authorized by `cred`,
    /// distilled to a [`LoggingState`]. A missing document (SSM returns the
    /// `InvalidDocument` code, mapped to `SessionError::NotFound`) — the decision
    /// below reads that as "no custom prefs ⇒ Session Manager default ⇒ no logging."
    async fn session_logging(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<LoggingState, SessionError>;
}

/// Parse the `SSM-SessionManagerRunShell` document body into a [`LoggingState`].
/// Unknown/empty fields are `false`; a malformed body yields the all-`false`
/// default (the caller still gets a defined answer). Pure + tested.
pub fn parse_logging(document_content: &str) -> LoggingState {
    let v: serde_json::Value = match serde_json::from_str(document_content) {
        Ok(v) => v,
        Err(_) => return LoggingState::default(),
    };
    let inputs = &v["inputs"];
    let nonempty = |key: &str| -> bool {
        inputs
            .get(key)
            .and_then(|x| x.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    };
    LoggingState {
        s3: nonempty("s3BucketName"),
        cloudwatch: nonempty("cloudWatchLogGroupName"),
        kms: nonempty("kmsKeyId"),
    }
}

/// Decide the operator advisory from a logging probe (ADR 0025 / THREAT-MODEL):
///
/// - logging on → name the destination(s);
/// - logging off → no advisory;
/// - no prefs document (`NotFound`, incl. SSM's `InvalidDocument`) → no advisory
///   (Session Manager defaults to no logging when the org never customized it);
/// - any other failure (can't read the doc — e.g. denied) → an always-on
///   fallback advisory (we cannot rule logging out).
///
/// The returned string is a fixed policy note — never any secret or document text.
pub fn session_logging_advisory(probe: &Result<LoggingState, SessionError>) -> Option<String> {
    match probe {
        Ok(state) if state.logs() => Some(format!(
            "this org logs Session Manager sessions to {} — the remote file's contents will be written there (config Janitor cannot disable)",
            destinations(state)
        )),
        Ok(_) => None,
        Err(SessionError::NotFound) => None,
        Err(_) => Some(
            "could not determine this org's Session Manager logging policy; if logging is enabled the remote file's contents will be written to S3/CloudWatch"
                .to_string(),
        ),
    }
}

/// Human phrase for which destination(s) are configured (only called when at least
/// one is).
fn destinations(state: &LoggingState) -> &'static str {
    match (state.s3, state.cloudwatch) {
        (true, true) => "S3 and CloudWatch",
        (true, false) => "S3",
        (false, true) => "CloudWatch",
        (false, false) => "a logging destination",
    }
}

// ----------------------------------------------------------------------------
// Fakes for unit tests (and dependent crates' tests via `test-support`).
// ----------------------------------------------------------------------------
#[cfg(any(test, feature = "test-support"))]
pub mod fakes {
    use super::*;
    use std::sync::Mutex;

    /// A scripted logging probe: each call pops the next outcome.
    pub struct FakeLoggingPreference {
        pub outcomes: Mutex<Vec<Result<LoggingState, SessionError>>>,
        pub calls: Mutex<u32>,
    }
    impl FakeLoggingPreference {
        pub fn new(outcomes: Vec<Result<LoggingState, SessionError>>) -> Self {
            FakeLoggingPreference {
                outcomes: Mutex::new(outcomes),
                calls: Mutex::new(0),
            }
        }
        /// A probe that always reports the given state.
        pub fn always(state: LoggingState) -> Self {
            FakeLoggingPreference::new(vec![Ok(state)])
        }
        /// A probe that always reports "no logging configured."
        pub fn off() -> Self {
            FakeLoggingPreference::new(vec![Ok(LoggingState::default())])
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl LoggingPreference for FakeLoggingPreference {
        async fn session_logging(
            &self,
            _cred: &Credential,
            _region: &str,
        ) -> Result<LoggingState, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.outcomes.lock().unwrap();
            if v.is_empty() {
                // Default to "no logging" once scripted outcomes run out, so a probe
                // on every read in a multi-env walk does not need N scripted entries.
                return Ok(LoggingState::default());
            }
            v.remove(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_s3_and_cloudwatch_and_kms() {
        let doc = r#"{
            "schemaVersion": "1.0",
            "sessionType": "Standard_Stream",
            "inputs": {
                "s3BucketName": "logs-bucket",
                "cloudWatchLogGroupName": "/ssm/sessions",
                "kmsKeyId": "arn:aws:kms:...:key/abc",
                "s3KeyPrefix": ""
            }
        }"#;
        assert_eq!(
            parse_logging(doc),
            LoggingState {
                s3: true,
                cloudwatch: true,
                kms: true
            }
        );
    }

    #[test]
    fn empty_strings_count_as_unconfigured() {
        let doc = r#"{"inputs":{"s3BucketName":"","cloudWatchLogGroupName":"","kmsKeyId":""}}"#;
        assert_eq!(parse_logging(doc), LoggingState::default());
        assert!(!parse_logging(doc).logs());
    }

    #[test]
    fn missing_inputs_or_malformed_is_all_false() {
        assert_eq!(parse_logging("{}"), LoggingState::default());
        assert_eq!(parse_logging("not json"), LoggingState::default());
    }

    #[test]
    fn advisory_names_the_destinations_when_logging_is_on() {
        let s3 = session_logging_advisory(&Ok(LoggingState {
            s3: true,
            ..Default::default()
        }))
        .unwrap();
        assert!(s3.contains("S3"));
        assert!(!s3.contains("CloudWatch"));
        let both = session_logging_advisory(&Ok(LoggingState {
            s3: true,
            cloudwatch: true,
            kms: false,
        }))
        .unwrap();
        assert!(both.contains("S3 and CloudWatch"));
    }

    #[test]
    fn no_advisory_when_logging_is_off_or_doc_absent() {
        assert!(session_logging_advisory(&Ok(LoggingState::default())).is_none());
        // A missing prefs document = Session Manager default = no logging.
        assert!(session_logging_advisory(&Err(SessionError::NotFound)).is_none());
    }

    #[test]
    fn unreachable_probe_falls_back_to_an_always_on_advisory() {
        // Can't read the doc (e.g. denied / throttled / SDK) → warn anyway.
        let w = session_logging_advisory(&Err(SessionError::AccessDenied)).unwrap();
        assert!(w.contains("could not determine"));
        assert!(session_logging_advisory(&Err(SessionError::Sdk {
            context: "boom".into()
        }))
        .is_some());
    }

    #[test]
    fn kms_only_does_not_trigger_a_logging_advisory() {
        // KMS encryption is a transport concern, not a logging side effect; the
        // logging advisory stays silent (the transport fails fast on KMS).
        let kms_only = LoggingState {
            kms: true,
            ..Default::default()
        };
        assert!(!kms_only.logs());
        assert!(session_logging_advisory(&Ok(kms_only)).is_none());
    }

    #[tokio::test]
    async fn fake_scripts_then_defaults_to_off() {
        use fakes::FakeLoggingPreference;
        let cred = Credential::new(
            "a".into(),
            "b".into(),
            "c".into(),
            std::time::SystemTime::UNIX_EPOCH,
        );
        let f = FakeLoggingPreference::new(vec![Ok(LoggingState {
            s3: true,
            ..Default::default()
        })]);
        assert!(f.session_logging(&cred, "us-east-1").await.unwrap().s3);
        // Subsequent calls default to off rather than panicking.
        assert_eq!(
            f.session_logging(&cred, "us-east-1").await.unwrap(),
            LoggingState::default()
        );
        assert_eq!(f.call_count(), 2);
    }
}
