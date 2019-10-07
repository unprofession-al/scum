package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
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
		Mount:  true,
		Rotate: true,
		Verify: true,
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

func (p *AWSProfile) RotateCredentials() ([]byte, error) {
	sess, _, err := p.getSession()

	iamClient := iam.New(sess)
	respListAccessKeys, err := iamClient.ListAccessKeys(&iam.ListAccessKeysInput{})
	if err != nil {
		return []byte{}, err
	}

	// Delete Old Access Key
	if len(respListAccessKeys.AccessKeyMetadata) == 2 {
		keyIndex := 0
		if *respListAccessKeys.AccessKeyMetadata[0].AccessKeyId == p.AWSAccessKeyID {
			keyIndex = 1
		}

		// fmt.Println("You have two access keys, which is the max number of access keys.")
		_, err := iamClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: respListAccessKeys.AccessKeyMetadata[keyIndex].AccessKeyId,
		})
		if err != nil {
			return []byte{}, err
		}
		// fmt.Printf("Deleted access key %s.\n", *respListAccessKeys.AccessKeyMetadata[keyIndex].AccessKeyId)
	}

	// Create the new access key
	respCreateAccessKey, err := iamClient.CreateAccessKey(&iam.CreateAccessKeyInput{})
	if err != nil {
		return []byte{}, err
	}
	// fmt.Printf("Created access key %s.\n", *respCreateAccessKey.AccessKey.AccessKeyId)

	// Todo: Verify

	// delete old access key
	_, err = iamClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
		AccessKeyId: &p.AWSAccessKeyID,
	})
	if err != nil {
		return []byte{}, err
	}

	// Update data in memory
	p.AWSAccessKeyID = *respCreateAccessKey.AccessKey.AccessKeyId
	p.AWSSecretAccessKey = *respCreateAccessKey.AccessKey.SecretAccessKey

	return p.Serialize()
}

func (p *AWSProfile) VerifyCredentials() (string, bool) {
	_, info, err := p.getSession()
	if err != nil {
		return err.Error(), false
	}

	return info, true
}

func (p *AWSProfile) getSession() (*session.Session, string, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", p.AWSAccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", p.AWSSecretAccessKey)
	sess := session.Must(session.NewSessionWithOptions(session.Options{}))

	// sts get-caller-identity
	stsClient := sts.New(sess)
	respGetCallerIdentity, err := stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return sess, "", fmt.Errorf("Error getting caller identity: %s. Is the key disabled?", err.Error())
	}
	return sess, fmt.Sprintf("Your user ARN is: %s", *respGetCallerIdentity.Arn), nil
}
