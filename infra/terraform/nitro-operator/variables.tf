variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS shared config profile"
  default     = "juno"
}

variable "name_prefix" {
  type        = string
  description = "Resource name prefix"
  default     = "juno-intents"
}

variable "allowed_pcr0" {
  type        = list(string)
  description = "Allowed Nitro Enclaves PCR0 measurements (hex, 96 chars each)"

  validation {
    condition = (
      length(var.allowed_pcr0) > 0 &&
      alltrue([for v in var.allowed_pcr0 : can(regex("^[0-9a-f]{96}$", lower(trimspace(v))))])
    )
    error_message = "allowed_pcr0 must be a non-empty list of 96-char lowercase hex strings (PCR0 values)."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional AWS tags"
  default     = {}
}

