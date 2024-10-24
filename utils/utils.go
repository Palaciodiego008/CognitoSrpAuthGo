package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

func HashSha256(buf []byte) string {
	a := sha256.New()
	a.Write(buf)

	return hex.EncodeToString(a.Sum(nil))
}

func HexHash(hexStr string) string {
	buf, _ := hex.DecodeString(hexStr)

	return HashSha256(buf)
}

func HexToBig(hexStr string) *big.Int {
	i, ok := big.NewInt(0).SetString(hexStr, 16)
	if !ok {
		panic(fmt.Sprintf("unable to covert \"%s\" to big Int", hexStr))
	}

	return i
}

func BigToHex(val *big.Int) string {
	return val.Text(16)
}

func GetRandom(n int) *big.Int {
	b := make([]byte, n)
	rand.Read(b)

	return HexToBig(hex.EncodeToString(b))
}

func PadHex(hexStr string) string {
	if len(hexStr)%2 == 1 {
		hexStr = fmt.Sprintf("0%s", hexStr)
	} else if strings.Contains("89ABCDEFabcdef", string(hexStr[0])) {
		hexStr = fmt.Sprintf("00%s", hexStr)
	}

	return hexStr
}

func ComputeHKDF(ikm, salt, infoBits string) []byte {
	ikmb, _ := hex.DecodeString(ikm)
	saltb, _ := hex.DecodeString(salt)

	extractor := hmac.New(sha256.New, saltb)
	extractor.Write(ikmb)
	prk := extractor.Sum(nil)
	infoBitsUpdate := append([]byte(infoBits), byte(1))
	extractor = hmac.New(sha256.New, prk)
	extractor.Write(infoBitsUpdate)
	hmacHash := extractor.Sum(nil)

	return hmacHash[:16]
}

func CalculateU(bigA, bigB *big.Int) *big.Int {
	return HexToBig(HexHash(PadHex(bigA.Text(16)) + PadHex(bigB.Text(16))))
}
