package main

import "fmt"
import "flag"
import "os/user"
import "errors"
import "os"
import "log"
import "io/ioutil"
import "bufio"
import "net/url"
import "strings"
import "github.com/marshallbrekka/okta-aws-login/okta"
import "github.com/marshallbrekka/okta-aws-login/oktaaws"
import "github.com/go-ini/ini"
import "github.com/howeyc/gopass"

const SessionFile = ".okta-aws-login-sid"
const ConfigFile = ".okta-aws-login"

type Config struct {
	IdpAwsUrl string
	Region    string
}

func homeDir() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
		panic("User not found")
	}
	return usr.HomeDir
}

func sessionId() (string, error) {
	filePath := homeDir() + "/" + SessionFile
	if _, err := os.Stat(filePath); err == nil {
		contents, err := ioutil.ReadFile(filePath)
		if err != nil {
			return "", err
		} else {
			return string(contents), nil
		}
	} else {
		return "", errors.New("Session id file doesn't exist")
	}
}

func saveSessionId(sessionId string) error {
	return ioutil.WriteFile(homeDir()+"/"+SessionFile, []byte(sessionId), 0644)
}

func normalizeUrl(appUrl string) string {
	url, _ := url.Parse(appUrl)
	url.RawQuery = ""
	url.Fragment = ""
	return url.String()
}

func readConfig() *Config {
	filePath := homeDir() + "/" + ConfigFile
	if _, err := os.Stat(filePath); err == nil {
		config, err := ini.Load(filePath)
		if err != nil {
			panic(err)
		} else {
			section := config.Section("default")
			return &Config{
				IdpAwsUrl: section.Key("idp_aws_url").Value(),
				Region:    section.Key("region").Value(),
			}
		}
	} else {
		return nil
	}
}

func saveConfig(settings *Config) error {
	config := ini.Empty()
	section := config.Section("default")
	section.NewKey("idp_aws_url", settings.IdpAwsUrl)
	section.NewKey("region", settings.Region)
	return config.SaveTo(homeDir() + "/" + ConfigFile)
}

func promptUrl(reader *bufio.Reader, originalUrl string) string {
	for true {
		prompt := ""
		if originalUrl == "" {
			prompt = "AWS IDP URL: "
		} else {
			prompt = "AWS IDP URL [default " + originalUrl + "]: "
		}
		fmt.Print(prompt)
		url, _ := reader.ReadString('\n')
		url = url[:len(url)-1]
		if url != "" {
			return url
		} else if originalUrl != "" {
			return originalUrl
		}
	}
	// make the compiler happy
	return ""
}

func promptRegion(reader *bufio.Reader, originalRegion string) string {
	if originalRegion == "" {
		originalRegion = "us-east-1"
	}

	fmt.Print("AWS Region [default " + originalRegion + "]: ")
	region, _ := reader.ReadString('\n')
	region = region[:len(region)-1]
	if region != "" {
		return region
	} else {
		return originalRegion
	}
}

func setupConfig(settings *Config) *Config {
	reader := bufio.NewReader(os.Stdin)
	settings.IdpAwsUrl = normalizeUrl(promptUrl(reader, settings.IdpAwsUrl))
	settings.Region = promptRegion(reader, settings.Region)
	return settings
}

func idpUrlToOrg(appUrl string) string {
	parsed, _ := url.Parse(appUrl)
	return strings.Split(parsed.Host, ".")[0]
}

func getUserCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Password: ")
	password, _ := gopass.GetPasswd()
	fmt.Println("")
	// strip new lines from the end of username and password
	return username[:len(username)-1], string(password)
}

func getSAMLAssertionFromAuth(appUrl string) string {
	for true {
		username, password := getUserCredentials()
		sessionToken, err := okta.AuthUser(idpUrlToOrg(appUrl), username, password)
		if err == nil {
			samlResponse, err := okta.SessionTokenToSAMLAssertion(appUrl, sessionToken)
			if err != nil {
				fmt.Println(err)
				break
			} else {
				saveSessionId(samlResponse.SessionId)
				return samlResponse.SAMLAssertion
			}
		} else {
			fmt.Println("Auth failed, please try again.")
		}
	}
	panic("Something went wrong getting the SAML assertion")
}

func getSAMLAssertion(appUrl string) string {
	sessionId, err := sessionId()
	if err != nil {
		return getSAMLAssertionFromAuth(appUrl)
	} else {
		samlResponse, err := okta.SessionIdToSAMLAssertion(appUrl, sessionId)
		if err != nil {
			return getSAMLAssertionFromAuth(appUrl)
		} else {
			saveSessionId(samlResponse.SessionId)
			return samlResponse.SAMLAssertion
		}
	}
}

func main() {
	configFlag := flag.Bool("configure", false, "Configure the tool")
	flag.Parse()

	conf := readConfig()
	if conf == nil {
		conf = setupConfig(&Config{})
		saveConfig(conf)
	} else if *configFlag {
		conf = setupConfig(conf)
		saveConfig(conf)
	}

	if *configFlag == false {
		samlAssertion := getSAMLAssertion(conf.IdpAwsUrl)
		creds, err := oktaaws.SAMLAssertionToCredentials(samlAssertion)
		if err != nil {
			panic(err)
		} else {
			pref := oktaaws.ProfileSettings{
				ProfileName:     "default",
				AccessKeyId:     *creds.AccessKeyId,
				SecretAccessKey: *creds.SecretAccessKey,
				SessionToken:    *creds.SessionToken,
				Region:          conf.Region,
				Output:          "json",
			}
			err := oktaaws.SaveConfig(homeDir(), pref)
			if err != nil {
				panic(err)
			} else {
				fmt.Println("success!")
			}
		}
	}
}
