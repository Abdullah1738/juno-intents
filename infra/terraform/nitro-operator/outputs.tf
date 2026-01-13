output "kms_key_arn" {
  value = aws_kms_key.nitro_operator.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.nitro_operator.name
}

output "iam_role_arn" {
  value = aws_iam_role.nitro_operator.arn
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.nitro_operator.name
}

