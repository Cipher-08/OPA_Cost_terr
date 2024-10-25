package main

# Deny any security group ingress rule that allows unrestricted SSH access (port 22 open to 0.0.0.0/0)
deny[msg] {
  # Check in the planned_values section for the security group resource
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.name == "terrateam_security_group"

  # Check each ingress rule
  ingress := resource.values.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"

  # Iterate over cidr_blocks to find unrestricted access
  cidr := ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [resource.name])
}

# Check the resource_changes section for any changes that allow unrestricted SSH access on port 22
deny[msg] {
  # Look for security group changes in the resource_changes section
  change := input.resource_changes[_]
  change.type == "aws_security_group"
  change.name == "terrateam_security_group"

  # Check each ingress rule in the 'after' state of the change
  ingress := change.change.after.ingress[_]
  ingress.from_port == 22
  ingress.to_port == 22
  ingress.protocol == "tcp"

  # Iterate over cidr_blocks to find unrestricted access
  cidr := ingress.cidr_blocks[_]
  cidr == "0.0.0.0/0"

  msg = sprintf("Security Group %v in resource_changes has an ingress rule allowing unrestricted SSH access on port 22.", [change.name])
}

