# The proxy reads and writes only its own KV paths: the broker master secret,
# platform secrets (LLM API token) and the credential store.
path "secret/data/mcp/*"                { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/mcp/*"            { capabilities = ["read", "list", "delete"] }
path "secret/data/credential-broker*"   { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/credential-broker*" { capabilities = ["read", "list", "delete"] }
