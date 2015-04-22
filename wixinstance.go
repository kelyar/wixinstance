package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var (
	WIX_SECRET = os.Getenv("WIX_SECRET")
)

type SignatureValidator struct {
	Payload string
	Secret  string
}

func (v *SignatureValidator) fixPadding(s string) string {
	return s + strings.Repeat("=", 4-len(s)%4)
}

// StdEnc to URLEnc
func (validator *SignatureValidator) fixString(s string) string {
	return strings.Replace(strings.Replace(s, "_", "/", -1), "-", "+", -1)
}

func (v *SignatureValidator) decodePayload() ([]byte, error) {
	return base64.StdEncoding.DecodeString(v.fixPadding(v.fixString(v.Payload)))
}

func (v *SignatureValidator) encode(data []byte) string {
	h := hmac.New(sha256.New, []byte(v.Secret))
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (v *SignatureValidator) VerifySignature(encodedSignature string) bool {
	return v.encode([]byte(v.Payload)) == v.fixPadding(v.fixString(encodedSignature))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8001", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	encodedInstance := r.URL.Query().Get("instance")
	if encodedInstance != "" {
		s := strings.Split(encodedInstance, ".")
		encodedSignature, payload := s[0], s[1]

		validator := SignatureValidator{payload, WIX_SECRET}

		if validator.VerifySignature(encodedSignature) == true {
			data, err := validator.decodePayload()
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Printf("%q\n", data)
		} else {
			http.Error(w, "403 Unauthorized", 403)
		}
	}

}
