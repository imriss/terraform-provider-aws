#
# EKS Worker Nodes Resources
#  * IAM role allowing Kubernetes actions to access other AWS services
#  * EC2 Security Group to allow networking traffic
#  * Data source to fetch latest EKS worker AMI: ami-0a2abab4107669c1b (us-west-2)
#  * AutoScaling Launch Configuration to configure worker instances
#  * AutoScaling Group to launch worker instances
#

resource "aws_iam_role" "rfarrahi01mysqltest-node" {
  name = "terraform-eks-rfarrahi01mysqltest-node"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "rfarrahi01mysqltest-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = "${aws_iam_role.rfarrahi01mysqltest-node.name}"
}

resource "aws_iam_role_policy_attachment" "rfarrahi01mysqltest-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = "${aws_iam_role.rfarrahi01mysqltest-node.name}"
}

resource "aws_iam_role_policy_attachment" "rfarrahi01mysqltest-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = "${aws_iam_role.rfarrahi01mysqltest-node.name}"
}

resource "aws_iam_instance_profile" "rfarrahi01mysqltest-node" {
  name = "terraform-eks-rfarrahi01mysqltest"
  role = "${aws_iam_role.rfarrahi01mysqltest-node.name}"
}

resource "aws_security_group" "rfarrahi01mysqltest-node" {
  name        = "terraform-eks-rfarrahi01mysqltest-node"
  description = "Security group for all nodes in the cluster"
  vpc_id      = "${aws_vpc.rfarrahi01mysqltest.id}"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = "${
    map(
     "Name", "terraform-eks-rfarrahi01mysqltest-node",
     "stack_name_for_billing", "terraform-eks-rfarrahi01mysqltest",
     "cost_center", "4444444",
     "kubernetes.io/cluster/${var.cluster-name}", "owned",
    )
  }"
}

resource "aws_security_group_rule" "rfarrahi01mysqltest-node-ingress-self" {
  description              = "Allow node to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = "${aws_security_group.rfarrahi01mysqltest-node.id}"
  source_security_group_id = "${aws_security_group.rfarrahi01mysqltest-node.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "rfarrahi01mysqltest-node-ingress-cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.rfarrahi01mysqltest-node.id}"
  source_security_group_id = "${aws_security_group.rfarrahi01mysqltest-cluster.id}"
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "rfarrahi01mysqltest-node-ingress-cluster443" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane (443)"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.rfarrahi01mysqltest-node.id}"
  source_security_group_id = "${aws_security_group.rfarrahi01mysqltest-cluster.id}"
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "rfarrahi01mysqltest-node-ingress-ssh" {
  description              = "Allow Nakisa to communicate with the nodes"
  from_port                = 22
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.rfarrahi01mysqltest-node.id}"
  cidr_blocks              = ["216.46.4.18/32"]
  to_port                  = 22
  type                     = "ingress"
}

data "aws_ami" "eks-worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-1.11-v2019*"]
  }

  most_recent = true
  owners      = ["602401143452"] # Amazon EKS AMI Account ID
}
# values = amazon-eks-node-1.10-v2019* for eks.3

# EKS currently documents this required userdata for EKS worker nodes to
# properly configure Kubernetes applications on the EC2 instance.
# We utilize a Terraform local here to simplify Base64 encoding this
# information into the AutoScaling Launch Configuration.
# More information: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
locals {
  rfarrahi01mysqltest-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.rfarrahi01mysqltest.endpoint}' --b64-cluster-ca '${aws_eks_cluster.rfarrahi01mysqltest.certificate_authority.0.data}' '${var.cluster-name}'
USERDATA
}

resource "aws_launch_configuration" "rfarrahi01mysqltest" {
  associate_public_ip_address = true
  iam_instance_profile        = "${aws_iam_instance_profile.rfarrahi01mysqltest-node.name}"
  image_id                    = "${data.aws_ami.eks-worker.id}"
  instance_type               = "m5.large"
  key_name                    = "nakisa-rd-rfarrahi-terraform-oregon"
  name_prefix                 = "terraform-eks-rfarrahi01mysqltest"
  security_groups             = ["${aws_security_group.rfarrahi01mysqltest-node.id}"]
  user_data_base64            = "${base64encode(local.rfarrahi01mysqltest-node-userdata)}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "rfarrahi01mysqltest" {
  desired_capacity     = 2
  launch_configuration = "${aws_launch_configuration.rfarrahi01mysqltest.id}"
  max_size             = 4
  min_size             = 1
  name                 = "terraform-eks-rfarrahi01mysqltest"
  vpc_zone_identifier  = ["${aws_subnet.rfarrahi01mysqltest.*.id}"]

  tag {
    key                 = "Name"
    value               = "terraform-eks-rfarrahi01mysqltest"
    propagate_at_launch = true
  }

  tag {
    key                 = "stack_name_for_billing"
    value               = "terraform-eks-rfarrahi01mysqltest"
    propagate_at_launch = true
  }

  tag {
    key                 = "cost_center"
    value               = "4444444"
    propagate_at_launch = true
  }

  tag {
    key                 = "kubernetes.io/cluster/${var.cluster-name}"
    value               = "owned"
    propagate_at_launch = true
  }
}
