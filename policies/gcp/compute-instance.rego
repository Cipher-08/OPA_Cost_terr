package main

# Deny any rule that allows unrestricted SSH access
deny[msg] {
  security_group := input.resource.aws_security_group[_]

  ingress := security_group.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"
  "0.0.0.0/0" in ingress.cidr_blocks

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [security_group.name])
}
