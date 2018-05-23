package ghpubkey

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGHPubKey(t *testing.T) {
	client := NewGHPubKey()

	assert.Equal(t, http.DefaultClient, client.Client)
	assert.Equal(t, GithubURL, client.BaseUrl)
	assert.Equal(t, GithubKeysEnding, client.Ending)
}

func TestGHUsernameValid(t *testing.T) {
	t1 := GHUsernameValid("t3stuser1")
	t2 := GHUsernameValid("t3st-user1")
	t3 := GHUsernameValid("t3stuser1-")
	t4 := GHUsernameValid("-t3stuser1")
	t5 := GHUsernameValid("t3st%user1")

	assert.True(t, t1)
	assert.True(t, t2)
	assert.False(t, t3)
	assert.False(t, t4)
	assert.False(t, t5)
}

func TestParseAuthorizedKeysEntry(t *testing.T) {
	entry := `ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key`
	entry2 := `test`
	_, err := ParseAuthorizedKeysEntry(entry)
	assert.NoError(t, err)

	_, err = ParseAuthorizedKeysEntry(entry2)
	assert.Error(t, err)

}
