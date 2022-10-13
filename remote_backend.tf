terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "hybytes"
    workspaces {
      name = "hashicat-aws"
    }
  }
}
