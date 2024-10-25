package main

# Deny any rule that allows unrestricted SSH access
deny[msg] {
  security_group := input.resource.aws_security_group[_]

  ingress := security_group.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"

  # Check if "0.0.0.0/0" exists in cidr_blocks
  cidr := ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [security_group.name])
}
