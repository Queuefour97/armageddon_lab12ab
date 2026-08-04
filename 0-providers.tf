##############################################################
# 0-providers.tf
#
# Declares the AWS provider and Terraform version constraints.
# This is always the first file Terraform reads.
#
# No S3 backend — state is stored locally in this folder.
# CloudWatch is used for all logging (no S3 log buckets).
##############################################################

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project   = "armageddon-12ab"
      Managedby = "Terraform"
      Lab       = "12ab"
    }
  }
}

##############################################################
# Data sources — used throughout all other files
##############################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}
