package cognitosrp

import (
	"cognitosrp/utils"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCognitoSRP(t *testing.T) {
	username := "testuser"
	password := "testpassword"
	poolId := "us-east-1_testpool"
	clientId := "testclientid"
	clientSecret := "testclientsecret"

	csrp, err := NewCognitoSRP(username, password, poolId, clientId, &clientSecret)
	assert.NoError(t, err)
	assert.Equal(t, username, csrp.username)
	assert.Equal(t, password, csrp.password)
	assert.Equal(t, poolId, csrp.poolId)
	assert.Equal(t, clientId, csrp.clientId)
	assert.NotNil(t, csrp.clientSecret)
	assert.Equal(t, clientSecret, *csrp.clientSecret)
}

func TestGetUsername(t *testing.T) {
	csrp := &CognitoSRP{username: "testuser"}
	assert.Equal(t, "testuser", csrp.GetUsername())
}

func TestGetClientId(t *testing.T) {
	csrp := &CognitoSRP{clientId: "testclientid"}
	assert.Equal(t, "testclientid", csrp.GetClientId())
}

func TestGetUserPoolId(t *testing.T) {
	csrp := &CognitoSRP{poolId: "us-east-1_testpool"}
	assert.Equal(t, "us-east-1_testpool", csrp.GetUserPoolId())
}

func TestGetUserPoolName(t *testing.T) {
	csrp := &CognitoSRP{poolName: "testpool"}
	assert.Equal(t, "testpool", csrp.GetUserPoolName())
}

func TestGetAuthParams(t *testing.T) {
	clientSecret := "testclientsecret"
	csrp := &CognitoSRP{
		username:     "testuser",
		clientId:     "testclientid",
		clientSecret: &clientSecret,
		bigA:         big.NewInt(12345),
	}

	params := csrp.GetAuthParams()
	assert.Equal(t, "testuser", params["USERNAME"])
	assert.Equal(t, utils.BigToHex(big.NewInt(12345)), params["SRP_A"])
	assert.Contains(t, params, "SECRET_HASH")
}

func TestGetSecretHash(t *testing.T) {
	clientSecret := "testclientsecret"
	csrp := &CognitoSRP{
		clientId:     "testclientid",
		clientSecret: &clientSecret,
	}

	secretHash, err := csrp.GetSecretHash("testuser")
	assert.NoError(t, err)

	expectedHash := hmac.New(sha256.New, []byte(clientSecret))
	expectedHash.Write([]byte("testusertestclientid"))
	expectedHashStr := base64.StdEncoding.EncodeToString(expectedHash.Sum(nil))

	assert.Equal(t, expectedHashStr, secretHash)
}

func TestPasswordVerifierChallenge(t *testing.T) {
	clientSecret := "testclientsecret"
	csrp := &CognitoSRP{
		username:     "testuser",
		password:     "testpassword",
		poolId:       "us-east-1_testpool",
		clientId:     "testclientid",
		clientSecret: &clientSecret,
		bigN:         utils.HexToBig(nHex),
		g:            utils.HexToBig(gHex),
		k:            utils.HexToBig(utils.HexHash("00" + nHex + "0" + gHex)),
		a:            big.NewInt(12345),
		bigA:         big.NewInt(67890),
	}

	challengeParms := map[string]string{
		"USERNAME":        "testuser",
		"USER_ID_FOR_SRP": "testuser",
		"SALT":            "abcdef",
		"SRP_B":           "123456",
		"SECRET_BLOCK":    base64.StdEncoding.EncodeToString([]byte("secretblock")),
	}

	ts := time.Now()
	response, err := csrp.PasswordVerifierChallenge(challengeParms, ts)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", response["USERNAME"])
	assert.Equal(t, challengeParms["SECRET_BLOCK"], response["PASSWORD_CLAIM_SECRET_BLOCK"])
	assert.Contains(t, response, "PASSWORD_CLAIM_SIGNATURE")
	assert.Contains(t, response, "TIMESTAMP")
	assert.Contains(t, response, "SECRET_HASH")
}
