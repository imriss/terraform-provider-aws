#
# VPC Resources
#  * VPC
#  * Subnets
#  * Internet Gateway
#  * Route Table
#

resource "aws_vpc" "rfarrahi01mysqltest" {
  cidr_block = "10.0.0.0/16"

  tags = "${
    map(
     "Name", "terraform-eks-rfarrahi01mysqltest-node",
     "kubernetes.io/cluster/${var.cluster-name}", "shared",
    )
  }"
}

resource "aws_subnet" "rfarrahi01mysqltest" {
  count = 2

  availability_zone = "${data.aws_availability_zones.available.names[count.index]}"
  cidr_block        = "10.0.${count.index}.0/24"
  vpc_id            = "${aws_vpc.rfarrahi01mysqltest.id}"

  tags = "${
    map(
     "Name", "terraform-eks-rfarrahi01mysqltest-node",
     "kubernetes.io/cluster/${var.cluster-name}", "shared",
    )
  }"
}

resource "aws_internet_gateway" "rfarrahi01mysqltest" {
  vpc_id = "${aws_vpc.rfarrahi01mysqltest.id}"

  tags {
    Name = "terraform-eks-rfarrahi01mysqltest"
  }
}

resource "aws_route_table" "rfarrahi01mysqltest" {
  vpc_id = "${aws_vpc.rfarrahi01mysqltest.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.rfarrahi01mysqltest.id}"
  }
}

resource "aws_route_table_association" "rfarrahi01mysqltest" {
  count = 2

  subnet_id      = "${aws_subnet.rfarrahi01mysqltest.*.id[count.index]}"
  route_table_id = "${aws_route_table.rfarrahi01mysqltest.id}"
}
