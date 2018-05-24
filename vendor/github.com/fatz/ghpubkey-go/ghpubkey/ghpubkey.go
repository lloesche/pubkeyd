package ghpubkey

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GithubURL
const GithubURL = "https://github.com"
const GithubKeysEnding = "keys"
const UsernameRegex = `^[a-zA-Z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$`

type GHPubKey struct {
	Client  *http.Client
	BaseUrl string
	Ending  string
}

// NewGHPubKey creates a default Github public key client
func NewGHPubKey() (g *GHPubKey) {
	g = &GHPubKey{}
	g.Client = &http.Client{}
	g.BaseUrl = GithubURL
	g.Ending = GithubKeysEnding

	return
}

// NewGHPubKeyWithClient creates a default Github public key client with a *http.Client
func NewGHPubKeyWithClient(client *http.Client) (g *GHPubKey) {
	g = &GHPubKey{}
	g.Client = client
	g.BaseUrl = GithubURL
	g.Ending = GithubKeysEnding

	return
}

type AuthorizedKeys struct {
	PublicKeys []ssh.PublicKey
}

// GenAuthFIle joins the keys so the string could be used as authorized_keys
func (a *AuthorizedKeys) GenAuthFIle() (f string) {
	for _, k := range a.PublicKeys {
		f += fmt.Sprintf("%s", ssh.MarshalAuthorizedKey(k))
	}
	return f
}

// ParseAuthorizedKeysEntry tryies to parse the entry string and returns ssh.PublicKey
func ParseAuthorizedKeysEntry(entry string) (key ssh.PublicKey, err error) {
	key, _, _, _, err = ssh.ParseAuthorizedKey([]byte(entry))
	if err != nil {
		return nil, fmt.Errorf("ERROR: parsing entry - %v", err)
	}
	return
}

// ParseAuthorizedKeys reads data input and creates *AuthorizedKeys from it
func ParseAuthorizedKeys(data []byte) (keys *AuthorizedKeys, err error) {
	keys = &AuthorizedKeys{}
	kstr := strings.Split(string(data), "\n")

	for _, k := range kstr {
		if len(k) <= 0 {
			continue
		}
		key, err := ParseAuthorizedKeysEntry(k)
		if err != nil {
			return nil, fmt.Errorf("ERROR: invalid format - %v", err)
		}

		keys.PublicKeys = append(keys.PublicKeys, key)
	}
	return
}

// RequestKeysForUser returns the users github ssh public keys
func (g *GHPubKey) RequestKeysForUser(user string) (authorizedKeys string, err error) {
	if !GHUsernameValid(user) {
		return "", fmt.Errorf("ERROR: Invalid username")
	}
	url, err := url.Parse(fmt.Sprintf("%s/%s.%s", g.BaseUrl, user, g.Ending))
	if err != nil {
		return "", fmt.Errorf("ERROR: Unexpected parsing error - %v", err)
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return "", fmt.Errorf("ERROR: Unexpected request error - %v", err)
	}
	resp, err := g.Client.Do(req)

	if err != nil || resp.StatusCode != 200 {
		return "", fmt.Errorf("ERROR: Request not successfull")
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("ERROR: Reading response")
	}

	keys, err := ParseAuthorizedKeys(data)
	if err != nil {
		return "", fmt.Errorf("ERROR: parsing keys %v", err)
	}

	// fmt.Printf("%v", keys)

	authorizedKeys = keys.GenAuthFIle()

	return
}

// GHUsernameValid checks if a given username is a valid Github username
func GHUsernameValid(user string) bool {
	// r, err := regexp.Compile(`^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$`)
	user = strings.ToLower(user)
	r := regexp.MustCompile(`^[a-z\d]([a-z0-9]|-([a-z0-9])){0,38}$`)

	return r.MatchString(user)
}
