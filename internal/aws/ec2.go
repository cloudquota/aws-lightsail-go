package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2InstanceView struct {
	ID          string
	Name        string
	State       string
	InstanceTyp string
	PublicIPv4  string
	PublicIPv6  string
	PrivateIPv4 string
	Zone        string
	LaunchedAt  string
}

type EC2AMIOption struct {
	Key     string
	Name    string
	Owner   string
	Pattern string
	Arch    string
}

var defaultEC2AMIOptions = []EC2AMIOption{
	{
		Key:     "ubuntu-24.04",
		Name:    "Ubuntu 24.04 LTS",
		Owner:   "099720109477",
		Pattern: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-*",
		Arch:    "x86_64",
	},
	{
		Key:     "ubuntu-22.04",
		Name:    "Ubuntu 22.04 LTS",
		Owner:   "099720109477",
		Pattern: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*",
		Arch:    "x86_64",
	},
	{
		Key:     "debian-12",
		Name:    "Debian 12",
		Owner:   "136693071363",
		Pattern: "debian-12-*",
		Arch:    "x86_64",
	},
	{
		Key:     "amzn-2023",
		Name:    "Amazon Linux 2023",
		Owner:   "137112412989",
		Pattern: "al2023-ami-2023.*",
		Arch:    "x86_64",
	},
}

type CreateEC2InstanceInput struct {
	Name         string
	AMI          string
	InstanceType string
	Count        int32
	UserData     string
}

func ResolveEC2AMI(ctx context.Context, cli *ec2.Client, key, custom string) (string, error) {
	if strings.TrimSpace(custom) != "" {
		return strings.TrimSpace(custom), nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "ubuntu-22.04"
	}
	for _, opt := range defaultEC2AMIOptions {
		if opt.Key == key {
			amiID, err := latestAMI(ctx, cli, opt.Owner, opt.Pattern, opt.Arch)
			if err != nil {
				return "", err
			}
			if amiID == "" {
				return "", fmt.Errorf("未找到 AMI：%s", opt.Name)
			}
			return amiID, nil
		}
	}
	return "", fmt.Errorf("未知 AMI 选项：%s", key)
}

func latestAMI(ctx context.Context, cli *ec2.Client, owner, pattern, arch string) (string, error) {
	out, err := cli.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{owner},
		Filters: []ec2types.Filter{
			{Name: aws.String("name"), Values: []string{pattern}},
			{Name: aws.String("architecture"), Values: []string{arch}},
			{Name: aws.String("virtualization-type"), Values: []string{"hvm"}},
		},
	})
	if err != nil {
		return "", err
	}
	if len(out.Images) == 0 {
		return "", nil
	}
	sort.Slice(out.Images, func(i, j int) bool {
		return aws.ToString(out.Images[i].CreationDate) > aws.ToString(out.Images[j].CreationDate)
	})
	return aws.ToString(out.Images[0].ImageId), nil
}

func ListEC2Instances(ctx context.Context, cli *ec2.Client) ([]EC2InstanceView, error) {
	out, err := cli.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("拉取 EC2 实例失败：%v", err)
	}
	var list []EC2InstanceView
	for _, res := range out.Reservations {
		for _, ins := range res.Instances {
			if ins.State != nil && ins.State.Name == ec2types.InstanceStateNameTerminated {
				continue
			}
			name := ""
			for _, tag := range ins.Tags {
				if aws.ToString(tag.Key) == "Name" {
					name = aws.ToString(tag.Value)
					break
				}
			}
			public4 := aws.ToString(ins.PublicIpAddress)
			private4 := aws.ToString(ins.PrivateIpAddress)
			public6 := ""
			if len(ins.NetworkInterfaces) > 0 && len(ins.NetworkInterfaces[0].Ipv6Addresses) > 0 {
				public6 = aws.ToString(ins.NetworkInterfaces[0].Ipv6Addresses[0].Ipv6Address)
			}
			zone := aws.ToString(ins.Placement.AvailabilityZone)
			launched := ""
			if ins.LaunchTime != nil {
				launched = ins.LaunchTime.Local().Format("2006-01-02 15:04:05")
			}
			state := ""
			if ins.State != nil {
				state = string(ins.State.Name)
			}
			list = append(list, EC2InstanceView{
				ID:          aws.ToString(ins.InstanceId),
				Name:        name,
				State:       state,
				InstanceTyp: string(ins.InstanceType),
				PublicIPv4:  public4,
				PublicIPv6:  public6,
				PrivateIPv4: private4,
				Zone:        zone,
				LaunchedAt:  launched,
			})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Zone < list[j].Zone
	})
	return list, nil
}

func CreateEC2Instance(ctx context.Context, cli *ec2.Client, in CreateEC2InstanceInput) error {
	if in.Count <= 0 {
		in.Count = 1
	}
	if strings.TrimSpace(in.InstanceType) == "" {
		in.InstanceType = "t3.micro"
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = fmt.Sprintf("ec2-%d", time.Now().Unix())
	}
	runIn := &ec2.RunInstancesInput{
		ImageId:      aws.String(in.AMI),
		InstanceType: ec2types.InstanceType(in.InstanceType),
		MinCount:     aws.Int32(in.Count),
		MaxCount:     aws.Int32(in.Count),
	}
	if strings.TrimSpace(in.UserData) != "" {
		runIn.UserData = aws.String(base64.StdEncoding.EncodeToString([]byte(in.UserData)))
	}
	runIn.TagSpecifications = []ec2types.TagSpecification{
		{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags: []ec2types.Tag{
				{Key: aws.String("Name"), Value: aws.String(in.Name)},
			},
		},
	}
	_, err := cli.RunInstances(ctx, runIn)
	if err != nil {
		return fmt.Errorf("创建 EC2 实例失败：%v", err)
	}
	return nil
}

func StartEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("启动失败：%v", err)
	}
	return nil
}

func StopEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("停止失败：%v", err)
	}
	return nil
}

func RebootEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.RebootInstances(ctx, &ec2.RebootInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("重启失败：%v", err)
	}
	return nil
}

func TerminateEC2Instance(ctx context.Context, cli *ec2.Client, id string) error {
	_, err := cli.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	if err != nil {
		return fmt.Errorf("终止失败：%v", err)
	}
	return nil
}
