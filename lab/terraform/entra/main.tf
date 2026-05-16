terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.53"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
  required_version = ">= 1.6"
}

provider "azuread" {
  tenant_id = var.tenant_id
}

# ── Locals ─────────────────────────────────────────────────────────────────────

locals {
  # Microsoft Graph application permission (Role) UUIDs.
  # These IDs are stable across all tenants — they are defined by Microsoft.
  # offline_access is a delegated scope only; it has no Role UUID and must be
  # excluded from azuread_app_role_assignment (which handles application perms).
  graph_permission_ids = {
    "User.Read.All"    = "df021288-bdef-4463-88db-98f22de89214"
    "Mail.Read"        = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
    "Calendars.Read"   = "798ee544-9d2d-430c-a058-570e29e34338"
    # offline_access is delegated-only — omitted intentionally
  }

  # Filter var.graph_permissions to only those with known Role UUIDs.
  # This safely ignores delegated-only scopes like offline_access.
  assignable_permissions = {
    for perm in var.graph_permissions :
    perm => local.graph_permission_ids[perm]
    if contains(keys(local.graph_permission_ids), perm)
  }

  # Terraform does not support arithmetic in string interpolations directly;
  # compute the secret duration in hours as a local.
  secret_expiry_hours = "${var.client_secret_expiry_years * 8760}h"
}

# ── Data Sources ───────────────────────────────────────────────────────────────

# Look up the Microsoft Graph service principal in the tenant.
# Its client_id is fixed across all tenants (00000003-0000-0000-c000-000000000000).
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

# ── App Registration ───────────────────────────────────────────────────────────

resource "azuread_application" "mcp_lab" {
  display_name     = var.app_display_name
  sign_in_audience = "AzureADMyOrg" # single-tenant

  # No redirect URIs — this app uses client_credentials flow only.
  # Adding web {} or spa {} blocks with redirect URIs would enable auth code
  # flow, which is not required here and would broaden the attack surface.

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    dynamic "resource_access" {
      for_each = local.assignable_permissions
      content {
        id   = resource_access.value # permission UUID
        type = "Role"                # "Role" = application permission; "Scope" = delegated
      }
    }
  }
}

# ── Service Principal ──────────────────────────────────────────────────────────

resource "azuread_service_principal" "mcp_lab" {
  client_id                    = azuread_application.mcp_lab.client_id
  app_role_assignment_required = false
}

# ── Client Secret ──────────────────────────────────────────────────────────────

resource "azuread_application_password" "mcp_lab" {
  application_id    = azuread_application.mcp_lab.id
  display_name      = "mcp-lab-secret"
  end_date_relative = local.secret_expiry_hours
}

# ── Admin Consent (App Role Assignments) ──────────────────────────────────────
# For application permissions (Role type), admin consent is granted by creating
# an azuread_app_role_assignment on the service principal.
# One resource per permission — for_each over the filtered assignable map.

resource "azuread_app_role_assignment" "mcp_lab_graph" {
  for_each = local.assignable_permissions

  principal_object_id = azuread_service_principal.mcp_lab.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
  app_role_id         = each.value # permission UUID
}
