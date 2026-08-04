##############################################################
# 7-variables.tf
#
# Input variable declarations.
# Actual values are stored in terraform.tfvars (gitignored).
# terraform.tfvars is never committed to version control.
##############################################################

variable "alert_email" {
  description = "Email address for critical security alert SNS notifications"
  type        = string
  sensitive   = true
}