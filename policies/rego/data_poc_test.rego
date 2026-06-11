package mcp.authz_test

import rego.v1
import data.mcp.authz.allow

# alice (viewer → "user" role) can invoke echo tools
test_alice_can_echo if {
    allow with input as {
        "client_id": "alice",
        "client_roles": ["user"],
        "tool_id": "poc-echo-ping",
        "tool_name": "ping",
        "tool_status": "active",
        "tool_risk_level": "low",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "alice": {
            "allowed_tools": ["ping", "echo_args", "whoami"],
            "allowed_tags": [],
            "max_risk_level": "low"
        }
    } with data.mcp.tools as {
        "ping": {"tags": ["echo", "read-only"]}
    }
}

# alice (viewer → "user" role) cannot invoke notes tools (not in grant)
test_alice_cannot_notes if {
    not allow with input as {
        "client_id": "alice",
        "client_roles": ["user"],
        "tool_id": "poc-notes-write",
        "tool_name": "notes_write",
        "tool_status": "active",
        "tool_risk_level": "medium",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "alice": {
            "allowed_tools": ["ping", "echo_args", "whoami"],
            "allowed_tags": [],
            "max_risk_level": "low"
        }
    } with data.mcp.tools as {
        "notes_write": {"tags": ["notes", "write"]}
    }
}

# alice (viewer → "user" role) cannot invoke medium-risk tools (max_risk_level=low)
test_alice_blocked_by_risk_level if {
    not allow with input as {
        "client_id": "alice",
        "client_roles": ["user"],
        "tool_id": "poc-notes-write",
        "tool_name": "notes_write",
        "tool_status": "active",
        "tool_risk_level": "medium",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "alice": {
            "allowed_tools": ["ping", "echo_args", "whoami", "notes_write"],
            "allowed_tags": [],
            "max_risk_level": "low"
        }
    } with data.mcp.tools as {
        "notes_write": {"tags": ["notes", "write"]}
    }
}

# bob (editor → "user" role) can invoke notes tools
test_bob_can_notes if {
    allow with input as {
        "client_id": "bob",
        "client_roles": ["user"],
        "tool_id": "poc-notes-write",
        "tool_name": "notes_write",
        "tool_status": "active",
        "tool_risk_level": "medium",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "bob": {
            "allowed_tools": ["ping", "echo_args", "whoami", "notes_read", "notes_write", "notes_delete"],
            "allowed_tags": [],
            "max_risk_level": "medium"
        }
    } with data.mcp.tools as {
        "notes_write": {"tags": ["notes", "write"]}
    }
}

# carol (analyst) can invoke search tools
test_carol_can_search if {
    allow with input as {
        "client_id": "carol",
        "client_roles": ["analyst"],
        "tool_id": "poc-search-query",
        "tool_name": "search",
        "tool_status": "active",
        "tool_risk_level": "low",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "carol": {
            "allowed_tools": ["ping", "echo_args", "whoami", "notes_read", "notes_write", "notes_delete", "search", "fetch_url", "summarize"],
            "allowed_tags": [],
            "max_risk_level": "medium"
        }
    } with data.mcp.tools as {
        "search": {"tags": ["search", "read-only"]}
    }
}

# quarantined tool is denied regardless of grant
test_quarantined_tool_denied if {
    not allow with input as {
        "client_id": "carol",
        "client_roles": ["analyst"],
        "tool_id": "poc-bad-tool",
        "tool_name": "search",
        "tool_status": "quarantined",
        "tool_risk_level": "low",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": false,
    } with data.mcp_grants as {
        "carol": {
            "allowed_tools": ["search"],
            "allowed_tags": [],
            "max_risk_level": "medium"
        }
    } with data.mcp.tools as {
        "search": {"tags": ["search", "read-only"]}
    }
}
