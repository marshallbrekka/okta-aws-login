package okta

import "errors"
import "bufio"
import "bytes"
import "encoding/json"
import "net/http"
import "net/url"
import "io"
import "net/http/cookiejar"
import "io/ioutil"
import "strings"

type sessionResponse struct {
	Status       string `json:status`
	SessionToken string `json:sessionToken`
}

type SAMLResponse struct {
	SessionId     string
	SAMLAssertion string
}

func samlResponseToSAMLAssertion(body io.ReadCloser) (string, error) {
	reader := bufio.NewReader(body)

	for true {
		line, err := reader.ReadString('\n')
		if strings.Contains(line, "SAMLResponse") {
			startIndex := strings.Index(line, "value=") + 7
			endIndex := strings.Index(line, "/>") - 1
			saml := line[startIndex:endIndex]
			saml = strings.Replace(saml, "&#x2b;", "+", -1)
			saml = strings.Replace(saml, "&#x3d;", "=", -1)
			return saml, nil
		} else if err != nil {
			return "", errors.New("SAML not found")
		}
	}
	// this case should really never happen, just making the compiler happy
	return "", nil
}

func jarToSessionId(urlString string, jar *cookiejar.Jar) (string, error) {
	url, _ := url.Parse(urlString)
	cookies := jar.Cookies(url)

	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			return cookie.Value, nil
		}
	}
	return "", errors.New("Session ID cookie not found")
}

func getSAMLAssertion(url string, jar *cookiejar.Jar) (SAMLResponse, error) {
	client := http.Client{Jar: jar}
	response, _ := client.Get(url)

	defer response.Body.Close()
	assertion, err := samlResponseToSAMLAssertion(response.Body)
	if err != nil {
		return SAMLResponse{}, err
	} else {
		sessionId, _ := jarToSessionId(url, jar)
		return SAMLResponse{SAMLAssertion: assertion, SessionId: sessionId}, nil
	}
}

func SessionIdToSAMLAssertion(appUrl string, sessionId string) (SAMLResponse, error) {
	jar, _ := cookiejar.New(nil)
	url, _ := url.Parse(appUrl)
	cookies := []*http.Cookie{&http.Cookie{Name: "sid", Value: sessionId}}
	jar.SetCookies(url, cookies)
	return getSAMLAssertion(appUrl, jar)
}

func SessionTokenToSAMLAssertion(appUrl string, sessionToken string) (SAMLResponse, error) {
	jar, _ := cookiejar.New(nil)
	return getSAMLAssertion(appUrl+"?onetimetoken="+sessionToken, jar)
}

// Given the organization name ({org}.okta.com), a username and password,
// returns a session token or an error.
func AuthUser(orgname string, username string, password string) (string, error) {
	url := "https://" + orgname + ".okta.com/api/v1/authn"
	bodyRequest := map[string]string{"username": username, "password": password}
	client := &http.Client{}
	requestBytes, _ := json.Marshal(&bodyRequest)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(requestBytes))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)

	if err != nil {
		return "", err
	} else {
		defer response.Body.Close()
		body, _ := ioutil.ReadAll(response.Body)
		res := sessionResponse{}
		json.Unmarshal(body, &res)
		if res.Status == "SUCCESS" {
			return res.SessionToken, nil
		} else {
			return "", errors.New(res.Status)
		}
	}
}
