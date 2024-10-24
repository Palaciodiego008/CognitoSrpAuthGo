package cognitosrp

import (
	"cognitosrp/utils"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestNewCognitoSRP(t *testing.T) {
	username := "testuser"
	password := "testpassword"
	poolId := "us-east-1_testpool"
	clientId := "testclientid"
	clientSecret := "testclientsecret"

	csrp, err := NewCognitoSRP(username, password, poolId, clientId, &clientSecret)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if csrp.username != username {
		t.Errorf("expected username %s, got %s", username, csrp.username)
	}
	if csrp.password != password {
		t.Errorf("expected password %s, got %s", password, csrp.password)
	}
	if csrp.poolId != poolId {
		t.Errorf("expected poolId %s, got %s", poolId, csrp.poolId)
	}
	if csrp.clientId != clientId {
		t.Errorf("expected clientId %s, got %s", clientId, csrp.clientId)
	}
	if csrp.clientSecret == nil || *csrp.clientSecret != clientSecret {
		t.Errorf("expected clientSecret %s, got %v", clientSecret, csrp.clientSecret)
	}
}

func TestGetUsername(t *testing.T) {
	csrp := &CognitoSRP{username: "testuser"}
	if csrp.GetUsername() != "testuser" {
		t.Errorf("expected username testuser, got %s", csrp.GetUsername())
	}
}

func TestGetClientId(t *testing.T) {
	csrp := &CognitoSRP{clientId: "testclientid"}
	if csrp.GetClientId() != "testclientid" {
		t.Errorf("expected clientId testclientid, got %s", csrp.GetClientId())
	}
}

func TestGetUserPoolId(t *testing.T) {
	csrp := &CognitoSRP{poolId: "us-east-1_testpool"}
	if csrp.GetUserPoolId() != "us-east-1_testpool" {
		t.Errorf("expected poolId us-east-1_testpool, got %s", csrp.GetUserPoolId())
	}
}

func TestGetUserPoolName(t *testing.T) {
	csrp := &CognitoSRP{poolName: "testpool"}
	if csrp.GetUserPoolName() != "testpool" {
		t.Errorf("expected poolName testpool, got %s", csrp.GetUserPoolName())
	}
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
	if params["USERNAME"] != "testuser" {
		t.Errorf("expected USERNAME testuser, got %s", params["USERNAME"])
	}
	if params["SRP_A"] != utils.BigToHex(big.NewInt(12345)) {
		t.Errorf("expected SRP_A %s, got %s", utils.BigToHex(big.NewInt(12345)), params["SRP_A"])
	}
	if _, ok := params["SECRET_HASH"]; !ok {
		t.Errorf("expected SECRET_HASH to be present")
	}
}

func TestGetSecretHash(t *testing.T) {
	clientSecret := "testclientsecret"
	csrp := &CognitoSRP{
		clientId:     "testclientid",
		clientSecret: &clientSecret,
	}

	secretHash, err := csrp.GetSecretHash("testuser")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedHash := hmac.New(sha256.New, []byte(clientSecret))
	expectedHash.Write([]byte("testusertestclientid"))
	expectedHashStr := base64.StdEncoding.EncodeToString(expectedHash.Sum(nil))

	if secretHash != expectedHashStr {
		t.Errorf("expected secret hash %s, got %s", expectedHashStr, secretHash)
	}
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
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if response["USERNAME"] != "testuser" {
		t.Errorf("expected USERNAME testuser, got %s", response["USERNAME"])
	}
	if response["PASSWORD_CLAIM_SECRET_BLOCK"] != challengeParms["SECRET_BLOCK"] {
		t.Errorf("expected PASSWORD_CLAIM_SECRET_BLOCK %s, got %s", challengeParms["SECRET_BLOCK"], response["PASSWORD_CLAIM_SECRET_BLOCK"])
	}
	if _, ok := response["PASSWORD_CLAIM_SIGNATURE"]; !ok {
		t.Errorf("expected PASSWORD_CLAIM_SIGNATURE to be present")
	}
	if _, ok := response["TIMESTAMP"]; !ok {
		t.Errorf("expected TIMESTAMP to be present")
	}
	if _, ok := response["SECRET_HASH"]; !ok {
		t.Errorf("expected SECRET_HASH to be present")
	}
}
