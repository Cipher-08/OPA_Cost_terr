package main

# Deny any rule that allows unrestricted SSH access
deny[msg] {
  security_group := input.resource.aws_security_group[_]  # Iterate over each security group

  # Check each ingress rule within the security group
  ingress := security_group.ingress[_]
  ingress.from_port == 22                      # Port 22 for SSH
  ingress.to_port == 22                        # Port 22 for SSH
  ingress.protocol == "tcp"                    # TCP protocol
  "0.0.0.0/0" in ingress.cidr_blocks           # Unrestricted access

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [security_group.name])
}
