package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const awsprofiletype = "aws"

func init() {
	RegisterProfileType(awsprofiletype, NewAWSProfile)
}

type AWSProfile struct {
	Profile            string `json:"profile"`
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
}

func NewAWSProfile() Profile {
	return &AWSProfile{}
}

func (p *AWSProfile) Describe() string {
	return `This profile handles your AWS Access Keys. For details about AWS Access Keys see: 
(see https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys)
`
}

func (p *AWSProfile) Capabilities() ProfileCapabilities {
	return ProfileCapabilities{
		Mount: true,
	}
}

func (p *AWSProfile) Type() string {
	return awsprofiletype
}

func (p *AWSProfile) Prompt() error {
	var err error

	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "Profile Name: ")
	p.Profile, err = reader.ReadString('\n')
	if err != nil {
		return nil
	}
	p.Profile = strings.TrimSpace(p.Profile)

	fmt.Fprintf(os.Stderr, "AWSAccessKeyID: ")
	p.AWSAccessKeyID, err = reader.ReadString('\n')
	if err != nil {
		return nil
	}
	p.AWSAccessKeyID = strings.TrimSpace(p.AWSAccessKeyID)

	fmt.Fprintf(os.Stderr, "AWSSecretAccessKey: ")
	p.AWSSecretAccessKey, err = reader.ReadString('\n')
	if err != nil {
		return nil
	}
	p.AWSSecretAccessKey = strings.TrimSpace(p.AWSSecretAccessKey)

	return nil
}

func (p *AWSProfile) Serialize() ([]byte, error) {
	return json.Marshal(p)
}

func (p *AWSProfile) Deserialize(in []byte) error {
	return json.Unmarshal(in, p)
}

func (p *AWSProfile) String() string {
	return fmt.Sprintf("[%s]\naws_access_key_id=%s\naws_secret_access_key=%s\n\n", p.Profile, p.AWSAccessKeyID, p.AWSSecretAccessKey)
}

func (p *AWSProfile) SetName(name string) {
	p.Profile = name
}

func (p *AWSProfile) Name() string {
	return p.Profile
}

func (p *AWSProfile) MountSnippet() (string, string) {
	return ".awscredentials", p.String()
}
