package oktaaws

import "encoding/base64"
import "strings"
import "github.com/aws/aws-sdk-go/service/sts"
import "github.com/aws/aws-sdk-go/aws"
import "github.com/aws/aws-sdk-go/aws/session"
import "github.com/go-ini/ini"

const configPath = ".aws/credentials"

type ProfileSettings struct {
	ProfileName string
	AccessKeyId string
	SecretAccessKey string
	SessionToken string
	Region string
	Output string
}

func samlAssertionToArns(samlAssertion string) (string, string, error) {
	decodedBytes, _ := base64.StdEncoding.DecodeString(samlAssertion)
	decoded := string(decodedBytes)
	start := strings.Index(decoded, "arn:aws")
	sub := decoded[start:]
	end := strings.Index(sub, "</saml2:")
	sub = sub[:end]
	arns := strings.Split(sub, ",")
	return arns[0], arns[1], nil
}

func assumeRole(samlAssertion string, principalArn string, roleArn string) (sts.Credentials, error) {
	req := sts.AssumeRoleWithSAMLInput{
		PrincipalArn: &principalArn,
		RoleArn: &roleArn,
		SAMLAssertion: &samlAssertion,
	}
	client := sts.New(session.New(&aws.Config{Region: aws.String("us-west-2")}))
	out, error := client.AssumeRoleWithSAML(&req)
	if error == nil {
		return *out.Credentials, nil
	} else {
		return sts.Credentials{}, error
	}
}

func SAMLAssertionToCredentials(samlAssertion string) (sts.Credentials, error) {
	principalArn, roleArn, err := samlAssertionToArns(samlAssertion)
	if err != nil {
		return sts.Credentials{}, err
	} else {
		creds, err := assumeRole(samlAssertion, principalArn, roleArn)
		if err != nil {
			return sts.Credentials{}, err
		} else {
			return creds, nil
		}
	}
}

func SaveConfig(userDir string, profile ProfileSettings) error {
	filePath := userDir + "/" + configPath
	config, err := ini.Load(filePath)
	if err != nil {
		return err
	} else {
		section := config.Section(profile.ProfileName)
		section.NewKey("aws_access_key_id", profile.AccessKeyId)
		section.NewKey("aws_secret_access_key", profile.SecretAccessKey)
		section.NewKey("aws_session_token", profile.SessionToken)
		section.NewKey("region", profile.Region)
		section.NewKey("output", profile.Output)
		saveErr := config.SaveTo(filePath)
		if saveErr != nil {
			return saveErr
		} else {
			return nil
		}
	}
}
