output "service_user_access_key_id" {
  value       = aws_iam_access_key.service_user_access_key.id
  description = "The access key ID for the service user"
}

output "service_user_secret_access_key" {
  value       = aws_iam_access_key.service_user_access_key.secret
  description = "The secret access key for the service user"
  sensitive   = true
}