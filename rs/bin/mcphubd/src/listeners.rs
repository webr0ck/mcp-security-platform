//! Per-server dedicated listeners (`auth_mode = dedicated_port`). Each one
//! gets its own TCP port serving its own RFC 9728 protected-resource
//! document and RFC 8414 AS metadata pointing at *that server's* IDP — the
//! isolation valve described in ARCHITECTURE.md's multi-IDP section. Every
//! dedicated port mounts the exact same router the shared port does
//! (`mcphub_gateway::build`), so `/mcp` and the REST invoke route on a
//! dedicated port funnel into the identical `invoke()` choke point as the
//! shared port — there is no second copy of the enforcement chain.

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use mcphub_gateway::AppState;
use mcphub_identity::config::IdpConfig;
use mcphub_identity::discovery::DiscoveryDocument;
use mcphub_identity::ports::{as_metadata, protected_resource_metadata, IssuerEndpoints};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
struct MetaState {
    idp: Arc<IdpConfig>,
    endpoints: Arc<IssuerEndpoints>,
    resource: String,
}

async fn protected_resource(State(state): State<MetaState>) -> Json<serde_json::Value> {
    Json(protected_resource_metadata(&state.resource, &state.idp.issuer))
}

async fn as_meta(State(state): State<MetaState>) -> Json<serde_json::Value> {
    Json(as_metadata(&state.idp, &state.endpoints))
}

/// Mounts RFC 9728 / RFC 8414 discovery on the SHARED listener, using the
/// platform IDP.
///
/// Dedicated-port listeners already publish their own documents (each pointing
/// at that server's own IDP — that is the whole isolation valve). The shared
/// port needs them too, and for the more common reason: an MCP client
/// (Claude Code, Claude Desktop, Codex, the ChatGPT app) discovers how to
/// authenticate by fetching `/.well-known/oauth-protected-resource` from the
/// MCP server URL it was given. Without these routes on the shared port, every
/// such client fails at discovery and the platform looks broken rather than
/// unconfigured — the single most likely first experience for an employee.
///
/// The `resource` identifier must be the `/mcp` URL the client was pointed at,
/// per RFC 9728: it is what the authorization server audience-binds the issued
/// token to.
pub fn shared_oauth_metadata_router(
    idp: &IdpConfig,
    doc: &mcphub_identity::discovery::DiscoveryDocument,
    public_base: &str,
) -> Router {
    let endpoints = IssuerEndpoints {
        authorization_endpoint: doc.authorization_endpoint.clone().unwrap_or_default(),
        token_endpoint: doc.token_endpoint.clone().unwrap_or_default(),
        registration_endpoint: doc.registration_endpoint.clone(),
    };
    let meta_state = MetaState {
        idp: Arc::new(idp.clone()),
        endpoints: Arc::new(endpoints),
        resource: format!("{public_base}/mcp"),
    };
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(as_meta))
        .with_state(meta_state)
}

/// Spawns one listener per dedicated-port server row. Best-effort per
/// listener: a single misconfigured dedicated server (bad port, IDP with
/// no discovery doc cached) logs an error and is skipped rather than
/// aborting the whole process — the shared port and every other dedicated
/// port must keep serving.
pub async fn spawn_dedicated_listeners(
    gw_state: AppState,
    servers: &[mcphub_store::repo::servers::ServerRow],
    idps_by_id: &HashMap<uuid::Uuid, IdpConfig>,
    discovery_by_issuer: &HashMap<String, DiscoveryDocument>,
    public_host: &str,
) {
    for server in servers {
        let (Some(port), Some(idp_id)) = (server.dedicated_port, server.idp_id) else {
            continue;
        };
        let Some(idp) = idps_by_id.get(&idp_id) else {
            tracing::error!(server = %server.name, "dedicated_port server references an unknown idp_id — skipping listener");
            continue;
        };
        let Some(doc) = discovery_by_issuer.get(&idp.issuer) else {
            tracing::error!(server = %server.name, issuer = %idp.issuer, "no cached discovery document for dedicated IDP — skipping listener");
            continue;
        };
        let endpoints = IssuerEndpoints {
            authorization_endpoint: doc.authorization_endpoint.clone().unwrap_or_default(),
            token_endpoint: doc.token_endpoint.clone().unwrap_or_default(),
            registration_endpoint: doc.registration_endpoint.clone(),
        };
        let meta_state = MetaState {
            idp: Arc::new(idp.clone()),
            endpoints: Arc::new(endpoints),
            resource: format!("https://{public_host}:{port}/mcp"),
        };

        let router = mcphub_gateway::build(gw_state.clone())
            .merge(
                Router::new()
                    .route("/.well-known/oauth-protected-resource", get(protected_resource))
                    .route("/.well-known/oauth-authorization-server", get(as_meta))
                    .with_state(meta_state),
            );

        let addr = format!("0.0.0.0:{port}");
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                tracing::info!(%addr, server = %server.name, issuer = %idp.issuer, "dedicated listener up");
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
                        tracing::error!(error = %e, %addr, "dedicated listener exited");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, %addr, server = %server.name, "failed to bind dedicated listener — skipping");
            }
        }
    }
}
