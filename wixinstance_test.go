package main

import (
	"testing"
)

func TestWrongSignature(t *testing.T) {
	validator := SignatureValidator{"{test: true}", "some-secret"}

	if validator.VerifySignature("wrong encoded signature") == true {
		t.Fatal("Expected Verify to fail, but it does not")
	}
}

func TestCorrectSignature(t *testing.T) {
	validator := SignatureValidator{"{test: true}", "some-secret"}

	if validator.VerifySignature("S3HIHT1Z27sVq01j0GAxM83cCiYNpxseFXZF4X38Xj8") != true {
		t.Fatal("Expected Verify to pass, but it does not")
	}
}
