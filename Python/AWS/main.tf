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
  region = var.region
}


/*
################################################
S3
################################################
*/
resource "aws_s3_bucket" "test_bucket" {
  bucket = var.bucket_name
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
  name               = "iam_for_${var.function_name}"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}


data "aws_iam_policy_document" "lambda_s3_read_access" {
  statement {
    effect = "Allow"

    actions = [
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.test_bucket.arn,
      "${aws_s3_bucket.test_bucket.arn}/*"
    ]
  }
}


resource "aws_iam_policy" "lambda_s3_policy" {
  name   = "lambda_s3_policy_${var.function_name}"
  policy = data.aws_iam_policy_document.lambda_s3_read_access.json
}


resource "aws_iam_role_policy_attachment" "lambda_s3_attach" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}


data "archive_file" "function_archive" {
  type        = "zip"
  source_dir  = "${path.module}/"
  output_path = var.archive_path
}


resource "aws_lambda_function" "function" {
  function_name = var.function_name
  description   = "Testing terraform and python"
  role          = aws_iam_role.lambda.arn
  handler       = var.handler_name
  memory_size   = 128

  filename         = var.archive_path
  source_code_hash = data.archive_file.function_archive.output_base64sha256
  runtime = var.runtime

  environment {
    variables = {
      bucket_name = var.bucket_name
    }
  }
}