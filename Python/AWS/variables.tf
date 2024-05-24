variable "handler_name" {
    type = string
    default = "main.lambda_handler"
}

variable "function_name" {
  type = string
  default = "test-python"
}

variable "region" {
  type = string
  default = "us-west-2"
}

variable "runtime" {
    type = string
}

variable "bucket_name" {
  type = string
}

variable "archive_path" {
  type = string
  default = "/."
}