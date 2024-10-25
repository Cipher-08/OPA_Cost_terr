
resource "aws_instance" "terrateam-in" {
  ami = "ami-0e86e20dae9224db8"
  instance_type = "u-24tb1.metal" # Maximum instance type
  subnet_id = "subnet-02efa144df0a77c13"
  tags = {
    Name = "TerraTeamInstance"
  }
}
