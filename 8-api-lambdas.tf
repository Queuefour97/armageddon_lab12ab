# 
# node.js Lambda
# 

resource "aws_lambda_function" "api_lambda_node" {
  filename      = data.archive_file.node_example.output_path
  function_name = "api_lambda_node"
  role          = aws_iam_role.lambda_role.arn
  handler       = "chewbacca-node-lambda.handler"
# The code_sha256 argument is not valid in this provider version.sersion 
# code_sha256   = data.archive_file.node_example.output_base64sha256

# The runtimes have to be downgraded to match the provider version.  The latest runtimes are not supported in this provider version.
  runtime = "nodejs22.x"
}

data "archive_file" "node_example" {
  type        = "zip"
  source_file = "./src/chewbacca-node-lambda.js"
  output_path = "./build/node.zip"
}

# Python Lambda
resource "aws_lambda_function" "api_lambda_python" {
  filename      = data.archive_file.example_python.output_path
  function_name = "api_lambda_python"
  role          = aws_iam_role.lambda_role.arn
  handler       = "chewbacca-python-lambda.lambda_handler"
# The code_sha256 argument is not valid in this provider version.sersion  
# code_sha256   = data.archive_file.example_python.output_base64sha256

# The runtimes have to be downgraded to match the provider version.  The latest runtimes are not supported in this provider version.
  runtime = "python3.13"
}

data "archive_file" "example_python" {
  type        = "zip"
  source_file = "./src/chewbacca-python-lambda.py"
  output_path = "./build/python.zip"
}