package utils

import (
	"math/big"
	"testing"
)

func TestHexToBig(t *testing.T) {
	hexStr := "1a"
	expected := big.NewInt(26)
	result := HexToBig(hexStr)
	if result.Cmp(expected) != 0 {
		t.Errorf("HexToBig(%s) = %s; want %s", hexStr, result, expected)
	}
}

func TestBigToHex(t *testing.T) {
	val := big.NewInt(26)
	expected := "1a"
	result := BigToHex(val)
	if result != expected {
		t.Errorf("BigToHex(%s) = %s; want %s", val, result, expected)
	}
}

func TestGetRandom(t *testing.T) {
	n := 16
	result := GetRandom(n)
	if result.BitLen() <= 0 {
		t.Errorf("GetRandom(%d) = %s; want non-zero value", n, result)
	}
}

func TestPadHex(t *testing.T) {
	hexStr := "a"
	expected := "0a"
	result := PadHex(hexStr)
	if result != expected {
		t.Errorf("PadHex(%s) = %s; want %s", hexStr, result, expected)
	}
}

func TestCalculateU(t *testing.T) {
	bigA := big.NewInt(12345)
	bigB := big.NewInt(67890)
	expected := HexToBig(HexHash(PadHex(bigA.Text(16)) + PadHex(bigB.Text(16))))
	result := CalculateU(bigA, bigB)
	if result.Cmp(expected) != 0 {
		t.Errorf("CalculateU(%s, %s) = %s; want %s", bigA, bigB, result, expected)
	}
}
