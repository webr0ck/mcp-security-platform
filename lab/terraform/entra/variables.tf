variable "tenant_id" {
  description = "Azure AD / Entra tenant ID"
  type        = string
}

variable "subscription_id" {
  description = "Azure subscription ID (needed for provider auth)"
  type        = string
  default     = ""
}

variable "app_display_name" {
  description = "Display name for the Entra app registration"
  type        = string
  default     = "mcp-security-lab"
}

variable "graph_permissions" {
  description = "Microsoft Graph API permissions to assign (application type)"
  type        = list(string)
  default     = ["User.Read.All", "Mail.Read", "Calendars.Read", "offline_access"]
}

variable "client_secret_expiry_years" {
  description = "Client secret validity in years"
  type        = number
  default     = 1
}
