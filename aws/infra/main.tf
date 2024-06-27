terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

// Creating the S3 bucket
resource "aws_s3_bucket" "s3_bucket" {
  bucket = var.bucket_name
}

resource "aws_sqs_queue" "queue" {
  name = var.queue_name
}

# // Creating the IAM service account
# resource "aws_iam_policy" "s3_policy" {
#   name        = "${var.bucket_name}_policy"
#   description = "Policy to allow access to the S3 bucket ${var.bucket_name}"
#   policy      = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect   = "Allow"
#         Action   = [
#           "s3:ListBucket",
#           "s3:ListObjects",
#           "s3:GetObject",
#           "s3:PutObject",
#           "s3:DeleteObject"
#         ]
#         Resource = [
#           "arn:aws:s3:::${var.bucket_name}",
#           "arn:aws:s3:::${var.bucket_name}/*"
#         ]
#       }
#     ]
#   })
# }

# resource "aws_iam_user" "service_user" {
#   name = "s3_service_user"
# }

# resource "aws_iam_user_policy_attachment" "s3_user_policy_attachment" {
#   user       = aws_iam_user.service_user.name
#   policy_arn = aws_iam_policy.s3_policy.arn
# }

# resource "aws_iam_access_key" "service_user_access_key" {
#   user = aws_iam_user.service_user.name
# }