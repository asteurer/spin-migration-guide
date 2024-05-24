terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-west-2"
}

/*
################################################
S3
################################################
*/
resource "aws_s3_bucket" "lambda_test" {
  bucket = "asteurer-fermyon-lambda-test"

  tags = {
    Name        = "asteurer-fermyon-lambda-test"
  }
}

resource "aws_s3_bucket_ownership_controls" "lambda_test" {
  bucket = aws_s3_bucket.lambda_test.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "lambda_test" {
  bucket = aws_s3_bucket.lambda_test.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "lambda_test" {
  depends_on = [
    aws_s3_bucket_ownership_controls.lambda_test,
    aws_s3_bucket_public_access_block.lambda_test,
  ]

  bucket = aws_s3_bucket.lambda_test.id
  acl    = "public-read"
}


/*
################################################
Lambda
################################################
*/

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = "iam_for_asteurer_test_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

locals {
  binary_path  = "../cmd/bootstrap"
  src_path     = "../cmd/main.go"
  archive_path = "../cmd/bootstrap.zip"
  binary_name  = "bootstrap"
  project_root = "${path.module}"  # Adjust the path to point to your project root
}

resource "null_resource" "function_binary" {
  provisioner "local-exec" {
    command = "GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-trimpath go build -mod=readonly -ldflags='-s -w' -o ${local.binary_path} ${local.src_path}"
    working_dir = local.project_root  # Set the working directory to the project root
  }
}

data "archive_file" "function_archive" {
  depends_on = [null_resource.function_binary]

  type        = "zip"
  source_file = local.binary_path
  output_path = local.archive_path
}

// create the lambda function from zip file
resource "aws_lambda_function" "function" {
  function_name = "hello-world"
  description   = "My first hello world function"
  role          = aws_iam_role.lambda.arn
  handler       = local.binary_name
  memory_size   = 128

  filename         = local.archive_path
  source_code_hash = data.archive_file.function_archive.output_base64sha256
  architectures = ["x86_64"]
  runtime = "provided.al2023"
}