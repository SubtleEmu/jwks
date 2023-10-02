	/***************************************************************************************
	* Adapted and inspried from:
	*	https://www.sohamkamani.com/golang/rsa-encryption/
	* 	https://gist.github.com/sohamkamani/08377222d5e3e6bc130827f83b0c073e
	*	https://medium.com/@fedepreli/create-your-own-jwks-endpoint-supporting-both-ecc-and-rsa-algorithms-83e066dbee69
	*	https://curity.io/resources/learn/go-api/
	*	https://github.com/MicahParks/jwkset
	*   ChatGPT - prompt history is found in README
	*	Jacob Hochstetler - main.go/AuthHandler
	*
	***************************************************************************************/
	
	
	package main

	import (
		"crypto/rand"
		"crypto/rsa"
		"encoding/base64"
		"encoding/json"
		"log"
		"math/big"
		"net/http"
		"strconv"
		"time"
		"github.com/golang-jwt/jwt"
	)

	func main() {
		genKeys()
		http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
		http.HandleFunc("/auth", AuthHandler)
		log.Fatal(http.ListenAndServe(":8080", nil))
	}

	var (
		privKey    *rsa.PrivateKey
		expiredPrivKey *rsa.PrivateKey
	)

	func genKeys() {
		var err error
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating RSA keys: %v", err)
		}

		expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating expired RSA keys: %v", err)
		}
	}

	func AuthHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var (
			signingKey *rsa.PrivateKey
			keyID      string
			exp        int64
		)

		signingKey = privKey
		keyID = "randomKeyID"
		exp = time.Now().Add(12 * time.Hour).Unix()

		if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
			signingKey = expiredPrivKey
			keyID = "expiredKeyId"
			exp = time.Now().Add(-12 * time.Hour).Unix()
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"exp": exp,
		})
		token.Header["kid"] = keyID
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "There was a problem signing the token", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(signedToken))
	}

	type (
		JWKS struct {
			Keys []JWK `json:"keys"`
		}
		JWK struct {
			KID       string `json:"kid"`
			Algorithm string `json:"alg"`
			KeyType   string `json:"kty"`
			Use       string `json:"use"`
			N         string `json:"n"`
			E         string `json:"e"`
		}
	)

	func JWKSHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		base64URLEncode := func(b *big.Int) string {
			return base64.RawURLEncoding.EncodeToString(b.Bytes())
		}
		publicKey := privKey.Public().(*rsa.PublicKey)
		resp := JWKS{
			Keys: []JWK{
				{
					KID:       "randomKeyID",
					Algorithm: "RS256",
					KeyType:   "RSA",
					Use:       "sig",
					N:         base64URLEncode(publicKey.N),
					E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
