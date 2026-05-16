output "tenant_id" {
  description = "Entra tenant ID"
  value       = var.tenant_id
}

output "client_id" {
  description = "Application (client) ID — set as ENTRA_CLIENT_ID in .env.lab"
  value       = azuread_application.mcp_lab.client_id
}

output "client_secret" {
  description = "Client secret value — set as ENTRA_CLIENT_SECRET in .env.lab"
  value       = azuread_application_password.mcp_lab.value
  sensitive   = true
}

output "object_id" {
  description = "Service principal object ID"
  value       = azuread_service_principal.mcp_lab.object_id
}

output "env_lab_snippet" {
  description = "Paste this into .env.lab"
  value       = <<-EOT
    ENTRA_TENANT_ID=${var.tenant_id}
    ENTRA_CLIENT_ID=${azuread_application.mcp_lab.client_id}
    ENTRA_CLIENT_SECRET=<run: terraform output -raw client_secret>
  EOT
  sensitive   = false
}
