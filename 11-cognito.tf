



####### Cognito Resource Server #########
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_resource_server

resource "aws_cognito_resource_server" "cognito_pool_server" {
  identifier = "api_rest"
  name       = "rbac_rest_api"

  scope {
    scope_name        = "admin-scope"
    scope_description = "Admin Scope Description"
  }

  scope {
    scope_name        = "user-scope"
    scope_description = "User Scope Description"
  }

  user_pool_id = aws_cognito_user_pool.cognito_pool.id
}


#######Cognito User Pool #########
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool

resource "aws_cognito_user_pool" "cognito_pool" {
  name                     = "cognito_pool"
  mfa_configuration        = "ON"
  auto_verified_attributes = ["email"]

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }

    recovery_mechanism {
      name     = "verified_phone_number"
      priority = 2
    }

  }
  # attributes add for the console's sign-up page need more detail to spell out the required attributes
  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = true
    required            = true
  }

  alias_attributes = ["email"]

}

######## Cognito User Pool Client #########
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client

resource "aws_cognito_user_pool_client" "cognito_pool_client" {

  name                                 = "cognito_pool_client"
  user_pool_id                         = aws_cognito_user_pool.cognito_pool.id
  generate_secret                      = false
  callback_urls                        = ["https://localhost/callback"]
  logout_urls                          = ["https://localhost/logout"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  # auth_session_validity              = "15"

  supported_identity_providers = ["COGNITO"]

  allowed_oauth_scopes = [
    "openid",
    "email",
    "profile",
    "${aws_cognito_resource_server.cognito_pool_server.identifier}/admin-scope",
    "${aws_cognito_resource_server.cognito_pool_server.identifier}/user-scope"
  ]

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]
  # Above: Why is this one not inclued in the explicit_auth_flows? "ALLOW_CUSTOM_AUTH"

  # supported_identity_providers = ["COGNITO"]

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "hours"
  }
  access_token_validity  = 15
  id_token_validity      = 15
  refresh_token_validity = 1

  #  supported_identity_providers         = ["COGNITO"]
}

# Mr. Brown says get rid of this: 07/09/02026
# resource "aws_cognito_user_pool" "pool" {
#   name = "pool"
# }


# COGNITO User 1
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user

resource "aws_cognito_user" "user_cognito_1" {
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
  username     = "cognitouser1"
  password     = "BongoBeats1*"

  message_action = "SUPPRESS"

  attributes = {
    email          = "jorune.simpkins@gmail.com" #trusted email confirmation status
    email_verified = true
  }
}

#COGNITO

####### Cognito User Pool Groups 1 #########
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_group
# https://docs.aws.amazon.com/cognito/latest/developersguide/cognito-user-pools-user-groups.html

resource "aws_cognito_user_group" "user_group" {
  name         = "students"
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
  description  = "Cognito User Group"
  precedence   = 43
}

#COGNITO User In Group 1
resource "aws_cognito_user_in_group" "cognito_user_in_group_student" {
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
  group_name   = aws_cognito_user_group.user_group.name
  username     = aws_cognito_user.user_cognito_1.username
}


####### Cognito User Pool Groups 2 #########
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_group
# https://docs.aws.amazon.com/cognito/latest/developersguide/cognito-user-pools-user-groups.html

resource "aws_cognito_user_group" "admin_group" {
  name         = "admins"
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
  description  = "Cognito Admin Group"
  precedence   = 42
}

#COGNITO User In Group 2
resource "aws_cognito_user_in_group" "cognito_user_in_group_admin" {
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
  group_name   = aws_cognito_user_group.admin_group.name
  username     = aws_cognito_user.user_cognito_1.username
}

# COGNITO Domain


resource "aws_cognito_user_pool_domain" "cognito_pool_login_domain" {
  # this 'domain' will be the prefix for the FQDN, it must be unique
  domain       = "jorun-armageddon9499"
  user_pool_id = aws_cognito_user_pool.cognito_pool.id
}