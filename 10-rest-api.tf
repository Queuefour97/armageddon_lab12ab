resource "aws_api_gateway_rest_api" "lambda_rest_api" {
  name = "lambda-rest-api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

###### PYTHON #########

resource "aws_api_gateway_resource" "api_rest_python" {
  parent_id   = aws_api_gateway_rest_api.lambda_rest_api.root_resource_id
  path_part   = "python"
  rest_api_id = aws_api_gateway_rest_api.lambda_rest_api.id
}

resource "aws_api_gateway_method" "api_rest_python" {
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito_api_authorizer.id
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.api_rest_python.id
  rest_api_id   = aws_api_gateway_rest_api.lambda_rest_api.id
}

resource "aws_api_gateway_integration" "api_rest_python" {
  http_method             = aws_api_gateway_method.api_rest_python.http_method
  resource_id             = aws_api_gateway_resource.api_rest_python.id
  rest_api_id             = aws_api_gateway_rest_api.lambda_rest_api.id
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda_python.invoke_arn
}


###### node ##########

resource "aws_api_gateway_resource" "api_rest_node" {
  parent_id   = aws_api_gateway_rest_api.lambda_rest_api.root_resource_id
  path_part   = "node"
  rest_api_id = aws_api_gateway_rest_api.lambda_rest_api.id
}

resource "aws_api_gateway_method" "api_rest_node" {
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito_api_authorizer.id
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.api_rest_node.id
  rest_api_id   = aws_api_gateway_rest_api.lambda_rest_api.id
}

resource "aws_api_gateway_integration" "api_rest_node" {
  http_method             = aws_api_gateway_method.api_rest_node.http_method
  resource_id             = aws_api_gateway_resource.api_rest_node.id
  rest_api_id             = aws_api_gateway_rest_api.lambda_rest_api.id
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_lambda_node.invoke_arn
}


resource "aws_api_gateway_deployment" "rest_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.lambda_rest_api.id

  triggers = {
    # NOTE: The configuration below will satisfy ordering considerations,
    #       but not pick up all future REST API changes. More advanced patterns
    #       are possible, such as using the filesha1() function against the
    #       Terraform configuration file(s) or removing the .id references to
    #       calculate a hash against whole resources. Be aware that using whole
    #       resources will show a difference after the initial implementation.
    #       It will stabilize to only change when resources change afterwards.
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.api_rest_python.id,
      aws_api_gateway_method.api_rest_python.id,
      aws_api_gateway_integration.api_rest_python.id,
      aws_api_gateway_resource.api_rest_node.id,
      aws_api_gateway_method.api_rest_node.id,
      aws_api_gateway_integration.api_rest_node.id,
      aws_api_gateway_authorizer.cognito_api_authorizer.id
    ]))

  }

  lifecycle {
    create_before_destroy = true
  }
}

####### premissions ##########
resource "aws_lambda_permission" "node_lambda_permission" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_lambda_node.function_name
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.lambda_rest_api.id}/*/*"
}

resource "aws_lambda_permission" "python_lambda_permission" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_lambda_python.function_name
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.lambda_rest_api.id}/*/*"
}

###### stages ##########
resource "aws_api_gateway_stage" "rest_api_stage" {
  deployment_id = aws_api_gateway_deployment.rest_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.lambda_rest_api.id
  stage_name    = "prod"
}

# data "aws_caller_identity" "current" {}
# data "aws_region" "current" {}
# data "aws_partition" "current" {}

resource "aws_api_gateway_authorizer" "cognito_api_authorizer" {
  name          = "cognito_api_authorizer"
  rest_api_id   = aws_api_gateway_rest_api.lambda_rest_api.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = [aws_cognito_user_pool.cognito_pool.arn]
}
