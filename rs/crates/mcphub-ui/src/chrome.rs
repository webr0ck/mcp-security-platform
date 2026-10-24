use mcphub_types::Identity;

use crate::csp::CspNonce;
use crate::domain::{role_label, NAV_ITEMS};
use crate::state::AppState;
use crate::templates::{Chrome, NavItemView};

pub fn build(state: &AppState, user: &Identity, session_id: &str, active_href: &str, nonce: CspNonce, flash: Option<String>) -> Chrome {
    let nav: Vec<NavItemView> = NAV_ITEMS
        .iter()
        .filter(|item| item.roles.iter().any(|r| user.has_role(*r)))
        .map(|item| NavItemView { href: item.href, label: item.label, active: item.href == active_href })
        .collect();

    let role_names = user.roles.iter().map(|g| role_label(g.role)).collect::<Vec<_>>().join(", ");

    Chrome {
        user_email: user.email.clone().unwrap_or_else(|| user.sub.clone()),
        user_role: role_names,
        nav,
        csp_nonce: nonce.as_b64(),
        mcp_url: state.mcp_url.clone(),
        csrf_token: state.csrf.token_for(session_id),
        flash,
    }
}
