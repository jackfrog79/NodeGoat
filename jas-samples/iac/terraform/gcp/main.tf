# JAS IaC-scan demo fixture (GCP/Terraform). Not applied by any pipeline.
#
# Findings demonstrated (JFrog Misconfiguration Scans -> IaC):
#  - Overly-public access: GCS bucket granted allUsers read access.
#  - Overly-public access: firewall rule allowing ingress from 0.0.0.0/0
#    on all ports.
#  - Admin-role overuse: primitive "roles/owner" bound to a service account
#    instead of a least-privilege custom/predefined role.

provider "google" {
  project = "jas-demo-project"
  region  = "us-central1"
}

resource "google_storage_bucket" "reports" {
  name     = "jas-demo-reports-bucket"
  location = "US"
}

# Vulnerable: bucket readable by anyone on the internet.
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# Vulnerable: ingress open to the entire internet on every port.
resource "google_compute_firewall" "wide_open" {
  name    = "jas-demo-wide-open"
  network = "default"

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# Vulnerable: primitive "owner" role grants full project control, far
# beyond what an application service account should hold.
resource "google_project_iam_member" "app_sa_owner" {
  project = "jas-demo-project"
  role    = "roles/owner"
  member  = "serviceAccount:jas-demo-app@jas-demo-project.iam.gserviceaccount.com"
}
