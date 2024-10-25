package main

# Deny any rule that allows unrestricted SSH access
deny[msg] {
  # Check the planned values section for security groups
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_security_group"
  resource.values.ingress[_].from_port == 22
  resource.values.ingress[_].to_port == 22
  resource.values.ingress[_].protocol == "tcp"
  "0.0.0.0/0" in resource.values.ingress[_].cidr_blocks

  msg = sprintf("Security Group %v has an ingress rule allowing unrestricted SSH access on port 22.", [resource.name])
}

# Additional check on resource_changes to cover any changes
deny[msg] {
  # Check the resource changes section
  change := input.resource_changes[_]
  change.type == "aws_security_group"
  change.change.after.ingress[_].from_port == 22
  change.change.after.ingress[_].to_port == 22
  change.change.after.ingress[_].protocol == "tcp"
  "0.0.0.0/0" in change.change.after.ingress[_].cidr_blocks

  msg = sprintf("Security Group %v in resource_changes has an ingress rule allowing unrestricted SSH access on port 22.", [change.name])
}
