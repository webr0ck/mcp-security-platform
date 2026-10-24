//! Wires [`crate::store::CredentialStore`] + [`crate::adapters`] together
//! behind `mcphub_gateway::traits::CredentialBroker`.
//!
//! Where the encrypted blob and injection kind for a given (identity, tool)
//! come from is a storage concern — `mcphub-store`'s (component 4) job once
//! that crate exists. This module defines the [`CredentialSource`] trait
//! boundary it must implement and an in-memory test double
//! ([`InMemoryCredentialSource`]) so this crate is fully testable without a
//! database.

use crate::adapters::{inject, CredentialMaterial, InjectionKind};
use crate::error::CredsError;
use crate::store::CredentialStore;
use crate::vault::KekSource;
use mcphub_gateway::traits::CredentialBroker as CredentialBrokerTrait;
use mcphub_types::{GateError, Identity, ToolRef};
use std::collections::HashMap;

/// What to decrypt and how to inject it for a given tool call.
pub struct CredentialRecord {
    pub blob: Vec<u8>,
    pub server: String,
    pub credential_name: String,
    pub kind: InjectionKind,
    /// Only meaningful for `InjectionKind::BasicAuth`, where the username
    /// half is not secret and is stored alongside (not inside) the
    /// encrypted blob.
    pub basic_username: Option<String>,
}

#[async_trait::async_trait]
pub trait CredentialSource: Send + Sync {
    async fn lookup(&self, identity: &Identity, tool: &ToolRef) -> Option<CredentialRecord>;
}

pub struct Broker<K: KekSource, S: CredentialSource> {
    store: CredentialStore<K>,
    source: S,
}

impl<K: KekSource, S: CredentialSource> Broker<K, S> {
    pub fn new(store: CredentialStore<K>, source: S) -> Self {
        Self { store, source }
    }
}

#[async_trait::async_trait]
impl<K: KekSource, S: CredentialSource> CredentialBrokerTrait for Broker<K, S> {
    async fn inject(&self, identity: &Identity, tool: &ToolRef) -> Result<HashMap<String, String>, GateError> {
        let record = self
            .source
            .lookup(identity, tool)
            .await
            .ok_or(CredsError::NotFound)
            .map_err(|e| e.to_gate_error())?;

        let plaintext = self
            .store
            .decrypt(&record.blob, &identity.sub, &record.server, &record.credential_name)
            .await
            .map_err(|e| e.to_gate_error())?;

        let material = match (&record.kind, record.basic_username) {
            (InjectionKind::BasicAuth, Some(username)) => CredentialMaterial::Basic {
                username,
                password: plaintext,
            },
            (InjectionKind::BasicAuth, None) => {
                return Err(CredsError::AdapterMismatch.to_gate_error())
            }
            (_, _) => CredentialMaterial::Simple(plaintext),
        };

        let out = inject(&material, &record.kind).map_err(|e| e.to_gate_error())?;
        Ok(out.headers)
    }
}

/// In-memory test double.
#[derive(Default)]
pub struct InMemoryCredentialSource(pub HashMap<String, CredentialRecord>);

#[async_trait::async_trait]
impl CredentialSource for InMemoryCredentialSource {
    async fn lookup(&self, identity: &Identity, tool: &ToolRef) -> Option<CredentialRecord> {
        let key = format!("{}:{}", identity.sub, tool.tool);
        self.0.get(&key).map(|r| CredentialRecord {
            blob: r.blob.clone(),
            server: r.server.clone(),
            credential_name: r.credential_name.clone(),
            kind: r.kind.clone(),
            basic_username: r.basic_username.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::StaticKekSource;
    use mcphub_types::{GrantedRole, IssuerId, Role, ServerId, TokenRef};
    use uuid::Uuid;

    fn identity(sub: &str) -> Identity {
        Identity {
            sub: sub.into(),
            issuer: IssuerId::new("platform"),
            email: None,
            roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
            groups: vec![],
            token_ref: TokenRef::none(),
        }
    }

    fn tool(name: &str) -> ToolRef {
        ToolRef {
            server: ServerId::new(Uuid::nil()),
            tool: name.into(),
        }
    }

    #[tokio::test]
    async fn end_to_end_bearer_injection() {
        let kek = StaticKekSource(vec![0x22u8; 32]);
        let store = CredentialStore::new(kek);
        let blob = store.encrypt("real-token", "alice", "jira", "api_token").await.unwrap();

        let mut records = HashMap::new();
        records.insert(
            "alice:jira_search".to_string(),
            CredentialRecord {
                blob,
                server: "jira".to_string(),
                credential_name: "api_token".to_string(),
                kind: InjectionKind::BearerHeader,
                basic_username: None,
            },
        );

        let store2 = CredentialStore::new(StaticKekSource(vec![0x22u8; 32]));
        let broker = Broker::new(store2, InMemoryCredentialSource(records));

        let headers = CredentialBrokerTrait::inject(&broker, &identity("alice"), &tool("jira_search"))
            .await
            .unwrap();
        assert_eq!(headers.get("Authorization").unwrap(), "Bearer real-token");
    }

    #[tokio::test]
    async fn missing_credential_denies_not_panics() {
        let store = CredentialStore::new(StaticKekSource(vec![0x33u8; 32]));
        let broker = Broker::new(store, InMemoryCredentialSource::default());
        let err = CredentialBrokerTrait::inject(&broker, &identity("bob"), &tool("nope"))
            .await
            .unwrap_err();
        // Must be a GateError (which maps only to Deny) — never a successful
        // header map for a credential that doesn't exist.
        let _ = err.to_deny_reason();
    }
}
