package main

# Deny any security group ingress rule that allows unrestricted SSH access (port 22 open to 0.0.0.0/0)
deny[msg] {
  # Check the planned_values section for security groups
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.name == "terrateam_security_group"

  # Look for ingress rules that allow unrestricted access on port 22
  some ingress
  ingress = resource.values.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"

  # Iterate through each CIDR block to check for unrestricted access
  some cidr
  cidr = ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [resource.name])
}

# Check the resource_changes section for any modifications allowing unrestricted SSH access on port 22
deny[msg] {
  # Check the resource_changes section for security groups
  change := input.resource_changes[_]
  change.type == "aws_security_group"
  change.name == "terrateam_security_group"

  # Look for ingress rules in the 'after' state that allow unrestricted access on port 22
  some ingress
  ingress = change.change.after.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"

  # Iterate through each CIDR block to check for unrestricted access
  some cidr
  cidr = ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg = sprintf("Security Group %v in resource_changes has an ingress rule allowing unrestricted SSH access on port 22.", [change.name])
}
