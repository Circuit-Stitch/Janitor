# Setting up IAM Identity Center for Janitor

Janitor authenticates **only** through AWS IAM Identity Center, in memory, with a
fresh browser sign-in each launch — no static keys, no stored tokens
([ADR 0002](adr/0002-identity-center-only-memory-only-auth.md)). To run it
against real AWS (today: the `live-verify` harness,
[ADR 0010](adr/0010-aws-adapter-crate-and-auth-object-model.md) Milestone B), you
need an Identity Center org that grants your user a **permission set** with read
access to Secrets Manager. This guide sets that up starting from a standalone AWS
account.

> **Cost & footprint:** IAM Identity Center and AWS Organizations are free. The
> only charge is AWS Secrets Manager (~$0.40 per secret per month, plus
> negligible per-call cost). Delete the test secret afterward if you don't want
> it.

> **Verified:** this whole flow was run end-to-end against a real org
> (Milestone B, 2026-05-31) — browser sign-in → discovery → masked matrix. The
> two things that bit during that run, now baked into this guide, were (1) the
> `kms:Decrypt` permission and (2) entering the **Issuer URL** (not the portal
> URL). Both are called out below.

## The one critical choice: organization instance, not account instance

When you enable Identity Center on a standalone account, AWS offers two instance
types and nudges new/standalone accounts toward an **account instance**. **Do not
pick the account instance.**

- **Account instance** — supports *application* assignments only. It does **not**
  support permission sets and does **not** grant access to AWS accounts.
- **Organization instance** — supports **permission sets** and **AWS-account
  access**. This is what Janitor needs: the flow is browser sign-in →
  `GetRoleCredentials(account, role)` → Secrets Manager, where the "role" *is* a
  permission set. With an account instance, `ListAccounts` / `ListAccountRoles`
  return nothing and `GetRoleCredentials` has nothing to mint.

On a standalone account, enabling the organization instance auto-creates an AWS
Organization with your account as the management account (free).

## Setup checklist (~15–20 min)

### 1. Enable Identity Center (organization instance)

Console → **IAM Identity Center**
(`https://console.aws.amazon.com/singlesignon/`) → **Enable**. Choose the full
organization enablement (let it create the Organization) — **not** "account
instance."

Pick the region deliberately: this becomes Janitor's **SSO region**, and moving
it later means deleting and recreating the instance. `us-east-1` is a safe
default.

### 2. Create and activate your user

Identity Center → **Users** → **Add user** (use your email). You'll receive an
invitation email — **accept it, set a password, register MFA, and sign in to the
access portal once in a browser.** Confirm the user works *before* running
Janitor; an unactivated user makes sign-in fail for an unrelated reason.

### 3. Create a permission set (this becomes the "role")

Identity Center → **Permission sets** → **Create** → **Custom permission set** →
attach this **inline policy**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*" },
    { "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], "Resource": "*" },
    { "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*" }
  ]
}
```

Name it e.g. `JanitorSecretsRead`. The **permission set name is what Janitor
shows as the "role."**

> **Why `kms:Decrypt` is in the policy (verified, Milestone B):** any secret
> encrypted with a **customer-managed KMS key** (the common case for real
> secrets — e.g. the `deferno/*` secrets this was tested against) needs
> `kms:Decrypt`. Without it, `ListSecrets` still works and the secret is
> reachable, but `GetSecretValue` fails with
> `AccessDeniedException: "Access to KMS is not allowed"`. Secrets on the
> default `aws/secretsmanager` key don't strictly need it, so granting
> `kms:Decrypt` unconditionally is the safe default. Scope `Resource` to the
> specific key ARN(s) once you know them; `"*"` is fine to start.
>
> **Trap:** the AWS managed `ReadOnlyAccess` job-function policy lets you *list*
> secrets but **denies `GetSecretValue`** — sign-in would succeed and then the
> fetch would fail. Use the inline policy above (or the broader managed
> `SecretsManagerReadWrite`; Janitor is read-only by default —
> [ADR 0004](adr/0004-read-only-v1-scope-and-secret-shapes.md) — so it won't
> issue writes).
>
> **KMS key-policy fallback:** if `kms:Decrypt` in the permission set still
> isn't enough, the CMK's own **key policy** must also permit it. A key with the
> standard `"Enable IAM User Permissions"` (account-root) statement delegates to
> IAM, so the permission-set grant suffices. A key locked to specific principals
> needs the provisioned SSO role
> (`arn:aws:iam::<account-id>:role/aws-reserved/sso.amazonaws.com/.../AWSReservedSSO_JanitorSecretsRead_*`,
> findable in IAM → Roles) added with `kms:Decrypt`.

### 4. Assign your user to your account

Identity Center → **AWS accounts** → check your account → **Assign users or
groups** → select your user → select `JanitorSecretsRead` → **Submit**. (The
management account is fine for a test.) Assignments can take a minute to
propagate to the portal.

### 5. Create a test secret

AWS Secrets Manager — in whatever region you want Janitor to browse (the
**Secrets Manager region**, which may differ from the SSO region) → **Store a new
secret** → key/value, e.g. `{"FOO":"bar"}`. This gives the tool something to list
and read.

The **Encryption key** you pick here matters: the default `aws/secretsmanager`
key works with the policy above as-is, while a **customer-managed key** also
requires the `kms:Decrypt` grant from step 3 (and possibly a key-policy entry).
The policy above already includes `kms:Decrypt`, so either kind works.

### 6. Note your URLs

Identity Center → **Dashboard** → *Settings summary*. Record:

- the **Issuer URL** — `https://identitycenter.amazonaws.com/ssoins-xxxxxxxxxxxx`
  — **this is the value Janitor wants** (see [the `issuerUrl` note](#issuerurl--use-the-issuer-url-resolved))
- the **AWS access portal URL** — `https://d-xxxxxxxxxx.awsapps.com/start` (or
  your custom subdomain) — note it too; it's what you sign in to in a browser

## The values Janitor asks for

On first run, `live-verify` prompts once for these and saves them to Config
(locations only — never a secret;
[ADR 0011](adr/0011-guided-sign-in-and-discovery.md)). Config lives in your OS
config dir — on Windows, `%APPDATA%\Janitor\Janitor\config\config.toml`.

| Prompt | Value |
| --- | --- |
| `IAM Identity Center start URL` | the **Issuer URL** — `https://identitycenter.amazonaws.com/ssoins-…` (step 6) |
| `SSO region` | the region you enabled Identity Center in (step 1) |
| `Secrets Manager region to browse` | where your test secret lives (step 5) |

> Despite the prompt saying "start URL," enter the **Issuer URL**, not the
> portal `…/start` URL — see the resolved note below.

## Running it

```bash
cargo run -p janitor-aws --bin live-verify
```

The browser opens; after sign-in the tool auto-discovers your account, role, and
secret (auto-picking when there's only one, offering a menu otherwise), then
prints a **masked** single-environment matrix — presence, value length, and
hash-equality group, never a plaintext value
([ADR 0011](adr/0011-guided-sign-in-and-discovery.md), output discipline). It
remembers your pick for next time.

Flags skip any discovered step: `--start-url`, `--sso-region`, `--secret-region`,
`--account-id`, `--role`, `--secret-id`.

### `issuerUrl` — use the Issuer URL (resolved)

Janitor passes the value you enter to `RegisterClient` as `issuerUrl`. **Use the
Issuer URL** (`https://identitycenter.amazonaws.com/ssoins-…`), not the portal
`…/start` URL — verified end-to-end against a live org under Milestone B
([ADR 0011](adr/0011-guided-sign-in-and-discovery.md)). The portal URL was
observed to fail with `InvalidRequestException: "Invalid start url provided"`.

If you already saved the wrong value, reset and re-enter:

```bash
cargo run -p janitor-aws --bin live-verify -- --reset-config
# or override without wiping the rest:
cargo run -p janitor-aws --bin live-verify -- --start-url <ISSUER_URL>
```

Related Milestone B finding: AWS returns a **null `authorizationEndpoint`** from
`RegisterClient` for this instance, so Janitor derives the browser endpoint as
`https://oidc.<sso-region>.amazonaws.com/authorize` (the loopback redirect path
must be exactly `/oauth/callback`). These are handled in code; nothing for you to
configure.

### Cleanup

The test secret is the only ongoing cost — delete it from Secrets Manager when
done (note: deletion runs on a recovery window, not immediate). Identity Center,
the user, the permission set, and the Organization are free to leave in place.

## The remote-`.env`-over-SSM Provider (ADR 0025, B4)

Janitor's second Provider reads a `.env` file off a remote **EC2 instance** over AWS
Systems Manager (SSM) Session Manager, instead of from Secrets Manager. To verify it
(`cargo run -p janitor-ssm --bin live-verify-ssm`, or the GUI with `--ssm`) you need,
in addition to the Identity Center setup above:

### A target EC2 instance managed by SSM

- The instance must run the **SSM agent** (preinstalled on Amazon Linux / recent
  Ubuntu AMIs) and have an **instance profile** with the AWS managed policy
  `AmazonSSMManagedInstanceCore` (so it registers with Systems Manager).
- It must reach the SSM endpoints (a public subnet + IGW, a NAT, or SSM VPC
  endpoints). Confirm it shows up under **Systems Manager → Fleet Manager** /
  `aws ssm describe-instance-information` before running Janitor.
- Put a `.env` (flat `KEY=VALUE`) somewhere readable by the session's user, e.g.
  `/app/.env` (the conventional default Janitor pre-fills).

### The permission set's SSM read policy

Add these to the permission set's inline policy (alongside the Identity Center +
`GetRoleCredentials` the sign-in already needs). Janitor is read-only by default
(ADR 0004) — it runs `cat`-class reads via the `AWS-StartNonInteractiveCommand`
document. The **read-only** policy is the first block below; the **read-write**
addition (the `AWS-StartInteractiveCommand` document, ADR 0029) is the second.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ssm:DescribeInstanceInformation", "Resource": "*" },
    {
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": [
        "arn:aws:ec2:*:*:instance/*",
        "arn:aws:ssm:*::document/AWS-StartNonInteractiveCommand"
      ]
    },
    { "Effect": "Allow", "Action": ["ssm:TerminateSession", "ssm:ResumeSession"], "Resource": "arn:aws:ssm:*:*:session/*" },
    { "Effect": "Allow", "Action": "ssm:GetDocument", "Resource": "arn:aws:ssm:*::document/SSM-SessionManagerRunShell" }
  ]
}
```

- `ssm:DescribeInstanceInformation` — list the managed instances to pick from.
- `ssm:StartSession` scoped to the target instance(s) **and** the
  `AWS-StartNonInteractiveCommand` document — open the data channel that streams the
  `cat`. Scope `arn:aws:ec2:*:*:instance/*` to specific instance IDs in production.
- `ssm:TerminateSession`/`ssm:ResumeSession` — session lifecycle.
- `ssm:GetDocument` on `SSM-SessionManagerRunShell` — read the org's **session-logging
  preference** so Janitor can warn when a read would be archived to S3/CloudWatch (it
  cannot disable that; see [THREAT-MODEL.md](THREAT-MODEL.md)). If this is denied,
  Janitor falls back to an always-on warning rather than assuming logging is off.

#### Read-write mode (the `.env` write path, ADR 0029)

Writing an Entry back to a remote `.env` (read-write mode, gated; v1 ships read-only)
needs the **interactive** document, because only a pty-backed session lets the agent
deliver the streamed content to the command's stdin (the non-interactive document
discards it — ADR 0029). Add it to the `ssm:StartSession` document list:

```json
"arn:aws:ssm:*::document/AWS-StartInteractiveCommand"
```

- The new file content streams over the encrypted data channel — never on argv or in
  the CloudTrail-logged `StartSession` `Parameters` (THREAT-MODEL / ADR 0029). The
  same session-logging advisory applies (S3/CloudWatch archival captures it if on).
- The write runs the atomic replace under **passwordless `sudo`** (root-owned `600`
  files), so the instance's SSM agent must grant `ssm-user` `NOPASSWD` sudo (the
  default). There is no non-sudo fallback on the write (stdin is consumed once).

> **Editing the policy is not enough — assign the permission set to your user.** The
> policy above says what the *minted* role may do; it does not grant your user the
> right to mint it. You must **assign** the permission set to your user on the target
> account (Identity Center → **AWS accounts** → select the account → **Assign users or
> groups** → your user → the permission set → **Submit**), exactly as in step 4 above.
> Without the assignment, Janitor fails at **`GetRoleCredentials`** with
> `ForbiddenException: No access` / "not entitled to this role" — **before** any SSM
> call, so the SSM policy is never even reached. (If you renamed or replaced an
> earlier permission set, a saved Application's mapping may still name the old role;
> reset and re-discover — see below.) Assignments take a minute to propagate.

> **Use a fresh SSM Application, not a Secrets Manager one.** The remote-`.env`
> Provider's locations are `<instance-id>:<path>`, not Secrets Manager ARNs. Reusing
> an Application discovered against the Secrets Manager Provider will not work even
> once `GetRoleCredentials` succeeds (its `secret_id`s are the wrong shape, and may
> name a role without the SSM policy). Either run `live-verify-ssm` (it walks its own
> account → role → instance → path) or, in the GUI, create a **new** Application via
> Manage → discovery while running with `--ssm`.

> **No `session-manager-plugin` needed.** Unlike the AWS CLI's `aws ssm start-session`,
> Janitor speaks the Session Manager data-channel protocol in pure Rust (ADR 0025 §3,
> transport b), so there is **no** local plugin binary to install.

> **KMS-encrypted sessions are not supported (v1).** If the org's
> `SSM-SessionManagerRunShell` sets a `kmsKeyId` (session-data encryption), the read
> fails masked rather than hanging — leave session encryption off on the test box.

## See also

- [ADR 0002](adr/0002-identity-center-only-memory-only-auth.md) — Identity-Center-only, memory-only auth
- [ADR 0025](adr/0025-remote-dotenv-over-ssm-provider.md) — the remote-`.env`-over-SSM Provider
- [ADR 0010](adr/0010-aws-adapter-crate-and-auth-object-model.md) — `janitor-aws` adapter + auth object model (Milestone B)
- [ADR 0011](adr/0011-guided-sign-in-and-discovery.md) — guided sign-in, discovery, remembered picks
- [THREAT-MODEL.md](THREAT-MODEL.md) — why nothing secret touches disk

**External references** (AWS docs):

- [Enable IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/enable-identity-center.html)
- [Account instances of IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/account-instances-identity-center.html) — the "no permission sets / no account access" limitation
- [Create a permission set](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtocreatepermissionset.html)
- [Assign user or group access to AWS accounts](https://docs.aws.amazon.com/singlesignon/latest/userguide/assignusers.html)
- [Customizing the AWS access portal URL](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtochangeURL.html) — where the portal + Issuer URL appear on the Dashboard
