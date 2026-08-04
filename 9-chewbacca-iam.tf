resource "aws_iam_role" "lambda_role" {
  name = "chewbacca_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
  # NOTE:For a given role, this resource is incompatible with using the aws_iam_role resource inline_policy argument. When using that argument and this resource, both will attempt to manage the role's inline policies and Terraform will show a permanent difference.
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy

  # dynamoDB
  inline_policy {
    name   = "access-DynamoDB"
    policy = file("${path.module}/policies/access-DynamoDB.json")
  }

  # bedrock
  inline_policy {
    name   = "bedrock"
    policy = file("${path.module}/policies/bedrock.json")
  }

  # waf bedrock
  inline_policy {
    name   = "waf-role"
    policy = file("${path.module}/policies/waf_role.json")
  }

}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}