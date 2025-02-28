package cognitosrp

import (
	"cognitosrp/utils"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
	nHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
		"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
	// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
	gHex     = "2"
	infoBits = "Caldera Derived Key"
)

// NewCognitoSRP creates a CognitoSRP object
func NewCognitoSRP(username, password, poolId, clientId string, clientSecret *string) (*CognitoSRP, error) {
	c := &CognitoSRP{
		username:     username,
		password:     password,
		poolId:       poolId,
		clientId:     clientId,
		clientSecret: clientSecret,
	}

	if !strings.Contains(poolId, "_") {
		return nil, fmt.Errorf("invalid Cognito User Pool ID (%s), must be in format: '<region>_<pool name>'", poolId)
	}
	c.poolName = strings.Split(poolId, "_")[1]

	c.bigN = utils.HexToBig(nHex)
	c.g = utils.HexToBig(gHex)
	c.k = utils.HexToBig(utils.HexHash("00" + nHex + "0" + gHex))
	c.a = c.generateRandomSmallA()
	c.bigA = c.calculateA()

	return c, nil
}

// CognitoSRP handles SRP authentication with AWS Cognito
type CognitoSRP struct {
	username     string
	password     string
	poolId       string
	poolName     string
	clientId     string
	clientSecret *string
	bigN         *big.Int
	g            *big.Int
	k            *big.Int
	a            *big.Int
	bigA         *big.Int
}

// GetUsername returns the configured Cognito user username
func (csrp *CognitoSRP) GetUsername() string {
	return csrp.username
}

// GetClientId returns the configured Cognito Cient ID
func (csrp *CognitoSRP) GetClientId() string {
	return csrp.clientId
}

// GetUserPoolId returns the configured Cognito User Pool ID
func (csrp *CognitoSRP) GetUserPoolId() string {
	return csrp.poolId
}

// GetUserPoolName returns the configured Cognito User Pool Name
func (csrp *CognitoSRP) GetUserPoolName() string {
	return csrp.poolName
}

// GetAuthParams returns the AuthParms map of values required for make
// InitiateAuth requests
func (csrp *CognitoSRP) GetAuthParams() map[string]string {
	params := map[string]string{
		"USERNAME": csrp.username,
		"SRP_A":    utils.BigToHex(csrp.bigA),
	}

	if secret, err := csrp.GetSecretHash(csrp.username); err == nil {
		params["SECRET_HASH"] = secret
	}

	return params
}

// GetSecretHash returns the secret hash string required to make certain
// Cognito Identity Provider API calls (if client is configured with a secret)
func (csrp *CognitoSRP) GetSecretHash(username string) (string, error) {
	if csrp.clientSecret == nil {
		return "", fmt.Errorf("unable to create secret hash as client secret has not been configured")
	}

	var (
		msg = username + csrp.clientId
		key = []byte(*csrp.clientSecret)
		h   = hmac.New(sha256.New, key)
	)

	h.Write([]byte(msg))

	sh := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return sh, nil
}

// PasswordVerifierChallenge returns the ChallengeResponses map to be used
// inside the cognitoidentityprovider.RespondToAuthChallengeInput object which
// fulfils the PASSWORD_VERIFIER Cognito challenge
func (csrp *CognitoSRP) PasswordVerifierChallenge(challengeParms map[string]string, ts time.Time) (map[string]string, error) {
	var (
		internalUsername = challengeParms["USERNAME"]
		userId           = challengeParms["USER_ID_FOR_SRP"]
		saltHex          = challengeParms["SALT"]
		srpBHex          = challengeParms["SRP_B"]
		secretBlockB64   = challengeParms["SECRET_BLOCK"]

		timestamp = ts.In(time.UTC).Format("Mon Jan 2 03:04:05 MST 2006")
		hkdf      = csrp.getPasswordAuthenticationKey(userId, csrp.password, utils.HexToBig(srpBHex), utils.HexToBig(saltHex))
	)

	secretBlockBytes, err := base64.StdEncoding.DecodeString(secretBlockB64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode challenge parameter 'SECRET_BLOCK', %s", err.Error())
	}

	msg := csrp.poolName + userId + string(secretBlockBytes) + timestamp
	hmacObj := hmac.New(sha256.New, hkdf)
	hmacObj.Write([]byte(msg))
	signature := base64.StdEncoding.EncodeToString(hmacObj.Sum(nil))

	response := map[string]string{
		"TIMESTAMP":                   timestamp,
		"USERNAME":                    internalUsername,
		"PASSWORD_CLAIM_SECRET_BLOCK": secretBlockB64,
		"PASSWORD_CLAIM_SIGNATURE":    signature,
	}
	if secret, err := csrp.GetSecretHash(internalUsername); err == nil {
		response["SECRET_HASH"] = secret
	}

	return response, nil
}

func (csrp *CognitoSRP) generateRandomSmallA() *big.Int {
	randomLongInt := utils.GetRandom(128)

	return big.NewInt(0).Mod(randomLongInt, csrp.bigN)
}

func (csrp *CognitoSRP) calculateA() *big.Int {
	bigA := big.NewInt(0).Exp(csrp.g, csrp.a, csrp.bigN)
	if big.NewInt(0).Mod(bigA, csrp.bigN).Cmp(big.NewInt(0)) == 0 {
		panic("Safety check for A failed. A must not be divisable by N")
	}

	return bigA
}

func (csrp *CognitoSRP) getPasswordAuthenticationKey(username, password string, bigB, salt *big.Int) []byte {
	var (
		userPass     = fmt.Sprintf("%s%s:%s", csrp.poolName, username, password)
		userPassHash = utils.HashSha256([]byte(userPass))

		uVal      = utils.CalculateU(csrp.bigA, bigB)
		xVal      = utils.HexToBig(utils.HexHash(utils.PadHex((salt.Text(16)) + userPassHash)))
		gModPowXN = big.NewInt(0).Exp(csrp.g, xVal, csrp.bigN)
		intVal1   = big.NewInt(0).Sub(bigB, big.NewInt(0).Mul(csrp.k, gModPowXN))
		intVal2   = big.NewInt(0).Add(csrp.a, big.NewInt(0).Mul(uVal, xVal))
		sVal      = big.NewInt(0).Exp(intVal1, intVal2, csrp.bigN)
	)

	ikm := sVal.Text(16)
	s := utils.PadHex(utils.BigToHex(uVal))

	return utils.ComputeHKDF(ikm, s, infoBits)
}
