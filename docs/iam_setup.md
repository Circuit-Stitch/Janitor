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
    { "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], "Resource": "*" }
  ]
}
```

Name it e.g. `JanitorSecretsRead`. The **permission set name is what Janitor
shows as the "role."**

> **Trap:** the AWS managed `ReadOnlyAccess` job-function policy lets you *list*
> secrets but **denies `GetSecretValue`** — sign-in would succeed and then the
> fetch would fail. Use the inline policy above (or the broader managed
> `SecretsManagerReadWrite`; Janitor is read-only by default —
> [ADR 0004](adr/0004-read-only-v1-scope-and-secret-shapes.md) — so it won't
> issue writes).
>
> If your test secret uses a **customer-managed KMS key**, also grant
> `kms:Decrypt` on that key. The default `aws/secretsmanager` key needs nothing
> extra.

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

### 6. Note your URLs

Identity Center → **Dashboard** → *Settings summary*. Record:

- the **AWS access portal URL** — `https://d-xxxxxxxxxx.awsapps.com/start` (or
  your custom subdomain)
- the **Issuer URL** (shown separately) — keep it handy as a fallback (see
  [the `issuerUrl` note](#issuerurl--the-open-verification-item))

## The values Janitor asks for

On first run, `live-verify` prompts once for these and saves them to Config
(locations only — never a secret;
[ADR 0011](adr/0011-guided-sign-in-and-discovery.md)). Config lives in your OS
config dir — on Windows, `%APPDATA%\Janitor\Janitor\config\config.toml`.

| Prompt | Value |
| --- | --- |
| `IAM Identity Center start URL` | the **AWS access portal URL** (step 6) |
| `SSO region` | the region you enabled Identity Center in (step 1) |
| `Secrets Manager region to browse` | where your test secret lives (step 5) |

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

### `issuerUrl` — the open verification item

Janitor passes your **start URL** to `RegisterClient` as `issuerUrl` (reference
clients such as AWS CLI v2 do the same — see
[ADR 0011](adr/0011-guided-sign-in-and-discovery.md)). Confirming that AWS
accepts it is a Milestone B verify item
([ADR 0010](adr/0010-aws-adapter-crate-and-auth-object-model.md) §2a). Enter the
**access portal URL** at the prompt first. If sign-in fails immediately at
`RegisterClient`, re-run with the console's **Issuer URL** instead:

```bash
cargo run -p janitor-aws --bin live-verify -- --start-url <ISSUER_URL>
```

Either outcome resolves the ADR checklist item.

### Cleanup

The test secret is the only ongoing cost — delete it from Secrets Manager when
done (note: deletion runs on a recovery window, not immediate). Identity Center,
the user, the permission set, and the Organization are free to leave in place.

## See also

- [ADR 0002](adr/0002-identity-center-only-memory-only-auth.md) — Identity-Center-only, memory-only auth
- [ADR 0010](adr/0010-aws-adapter-crate-and-auth-object-model.md) — `janitor-aws` adapter + auth object model (Milestone B)
- [ADR 0011](adr/0011-guided-sign-in-and-discovery.md) — guided sign-in, discovery, remembered picks
- [THREAT-MODEL.md](THREAT-MODEL.md) — why nothing secret touches disk

**External references** (AWS docs):

- [Enable IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/enable-identity-center.html)
- [Account instances of IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/account-instances-identity-center.html) — the "no permission sets / no account access" limitation
- [Create a permission set](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtocreatepermissionset.html)
- [Assign user or group access to AWS accounts](https://docs.aws.amazon.com/singlesignon/latest/userguide/assignusers.html)
- [Customizing the AWS access portal URL](https://docs.aws.amazon.com/singlesignon/latest/userguide/howtochangeURL.html) — where the portal + Issuer URL appear on the Dashboard
