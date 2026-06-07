//! `janitor-ssm` — Janitor's remote-`.env`-over-SSM [Provider](../../CONTEXT.md)
//! (ADR 0025), the second real Provider.
//!
//! **Skeleton slice (#63):** this crate currently holds only the one pure,
//! offline piece the remote-`.env` Provider needs before any AWS or transport
//! code — [`parse_dotenv`], which turns a `.env` file's text into the same flat
//! [`SecretShape`](janitor_core::secret::SecretShape) a flat JSON Secret Set
//! produces. **No** Discovery, **no** `Provider` impl, **no** SSM transport,
//! **no** binaries — those are later slices (B3/B4). It depends on
//! **`janitor-core` only**; the `janitor-aws-auth` dependency arrives with the
//! SSM tail (B3).

mod dotenv;

pub use dotenv::{parse_dotenv, DotenvError};
