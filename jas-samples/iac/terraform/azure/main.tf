# JAS IaC-scan demo fixture (Azure/Terraform). Not applied by any pipeline.
#
# Findings demonstrated (JFrog Misconfiguration Scans -> IaC):
#  - Overly-public access: storage account allowing public blob access.
#  - Overly-public access: NSG rule allowing inbound traffic from any source.
#  - Weak cipher suite: storage account permitting TLS 1.0.
#  - Disabled logging: no diagnostic settings / monitoring configured.

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "jas_demo" {
  name     = "jas-demo-rg"
  location = "East US"
}

# Vulnerable: public blob access enabled, minimum TLS pinned to an old version.
resource "azurerm_storage_account" "reports" {
  name                     = "jasdemostorage"
  resource_group_name      = azurerm_resource_group.jas_demo.name
  location                 = azurerm_resource_group.jas_demo.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true     # Vulnerable: public blob access allowed
  min_tls_version                 = "TLS1_0" # Vulnerable: weak/legacy TLS
}

resource "azurerm_network_security_group" "wide_open" {
  name                = "jas-demo-nsg"
  location            = azurerm_resource_group.jas_demo.location
  resource_group_name = azurerm_resource_group.jas_demo.name

  # Vulnerable: allows inbound traffic from any source on any port.
  security_rule {
    name                       = "AllowAnyInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
