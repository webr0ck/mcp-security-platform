//! `CredentialBroker` ← `mcphub-creds::Broker`, with a Postgres-backed
//! `CredentialSource`.
//!
//! FLAGGED SCHEMA MISMATCH (report this, do not silently paper over it):
//! `mcphub-store`'s `credentials` table was designed with three separate
//! columns (`nonce`, `ciphertext`, `aad`) for a generic sealed-blob shape.
//! `mcphub-creds::store::CredentialStore` was independently built with its
//! own self-contained blob format — `salt(32B) || nonce(12B) ||
//! ciphertext+tag` as ONE opaque `Vec<u8>`, with AAD derived internally
//! from `(identity, server, credential_name)` rather than stored at all.
//! The two shapes don't line up: the DB has no `salt` column, and its
//! separate `nonce`/`aad` columns have no counterpart in the blob
//! `CredentialStore` produces. Reconciled here by treating the DB's
//! `ciphertext` column as the single opaque `mcphub-creds` blob and simply
//! not using the `nonce`/`aad` columns for this pairing (written empty on
//! seed). This works correctly but the schema is misleading as written —
//! flagged for the architect/db-engineer to either drop the two unused
//! columns or give `mcphub-creds` a componentized blob to fill them with.

use async_trait::async_trait;
use mcphub_creds::broker::{CredentialRecord, CredentialSource};
use mcphub_creds::adapters::InjectionKind;
use mcphub_types::{Identity, ToolRef};
use sqlx::PgPool;

pub struct StoreCredentialSource {
    pool: PgPool,
}

impl StoreCredentialSource {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialSource for StoreCredentialSource {
    async fn lookup(&self, identity: &Identity, tool: &ToolRef) -> Option<CredentialRecord> {
        // NOTE: `lookup` returns `Option`, not `Result` — a Postgres outage
        // here degrades to "no credential" (empty injection headers, not a
        // deny) rather than a hard fail-closed deny. In practice this does
        // not weaken the invariant: `tool_meta`/`list_visible` (the
        // `EntitlementStore` adapter) both hit Postgres earlier in the
        // enforcement chain and already deny on the same outage before
        // credential injection is ever reached. Flagged as a
        // `mcphub-creds` trait-shape gap regardless — see handoff report.
        let row = mcphub_store::repo::credentials::get_active_credential(
            &self.pool,
            &identity.sub,
            tool.server.0,
            &tool.tool,
        )
        .await
        .ok()
        .flatten()?;

        Some(CredentialRecord {
            blob: row.ciphertext,
            server: tool.server.0.to_string(),
            credential_name: tool.tool.clone(),
            // TODO: confirm with architect — the `credentials` table has no
            // injection-kind column, so every stored credential is injected
            // as a bearer header today.
            kind: InjectionKind::BearerHeader,
            basic_username: None,
        })
    }
}
