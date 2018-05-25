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
	entry3 := `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIK3C5eO9yWpEaNLMyfNqDcLvYMU3NkF23H8uLBIo/czDPr2YGi/DhjGG0PcXyISYWG29/s4bRLYbhhURnW2M4Y=`
	entry4 := `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFHBQrFDDxvyyBMfG8hR/YtLwv4xGIZV3Byy8SzQR8VEVFJHI4sL7ZYwJkXPZslu7t6CVrcvrcnZPBE5pD6oSAE=`
	_, err := ParseAuthorizedKeysEntry(entry)
	assert.NoError(t, err)

	_, err = ParseAuthorizedKeysEntry(entry2)
	assert.Error(t, err)

	_, err = ParseAuthorizedKeysEntry(entry3)
	assert.NoError(t, err)

	_, err = ParseAuthorizedKeysEntry(entry4)
	assert.NoError(t, err)

}

func TestRequestKeysForUser(t *testing.T) {
	client := NewGHPubKey()
	_, err := client.RequestKeysForUser("FATZ")
	assert.NoError(t, err)
	_, err = client.RequestKeysForUser("fatz")
	assert.NoError(t, err)
	_, err = client.RequestKeysForUser("Fatz")
	assert.NoError(t, err)
	_, err = client.RequestKeysForUser("F\"tz")
	assert.Error(t, err)
}
