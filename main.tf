resource "aws_security_group" "terrateam_security_group" {
  name        = "terrateam-security-group"
  description = "Security group with unrestricted SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This allows unrestricted SSH access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terrateam-security-group"
  }
}
