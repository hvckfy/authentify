package web

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hvckfy/authentify/pkg/datap"
	"github.com/hvckfy/authentify/pkg/key"
)

/*
Connection creates Server client instance.

ip string        - Host IP address
port string      - Host port
caller string    - Caller identifier (unused)
apiKey string    - API authentication key
keyname string   - Host public key PEM filename

Loads public key from keyname, sets fields.
*/
func Connection(ip, port, caller, apiKey, keyname string) Server {
	PubKey, err := key.ImportPublic(keyname)
	if err != nil {
		fmt.Println("PublicKey is not set.")
	}
	return Server{
		ip:        ip,
		port:      port,
		caller:    caller,
		apiKey:    apiKey,
		publicKey: PubKey,
	}
}

/*
DoRequest performs secure request-response cycle.

Arguments:
  - route string: API endpoint path (e.g. "/api/test")
  - input []byte: Request data bytes

Returns:
  - []byte: Decrypted response data
  - error: Any error

Generates ephemeral RSA keypair, encrypts request with server pubkey, sends client pubkey plain.
Decrypts response encrypted to ephemeral privkey.
*/
func (s Server) DoRequest(route string, input []byte) ([]byte, error) {
	clientPubKey, clientPrivKey := key.KeyGen()
	if clientPrivKey == nil {
		return nil, fmt.Errorf("failed to generate client keys")
	}

	pubDER, err := x509.MarshalPKIXPublicKey(clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client pub key: %w", err)
	}
	clientPubB64 := base64.StdEncoding.EncodeToString(pubDER)

	reqInner := map[string]interface{}{
		"ApiKey": s.apiKey,
		"Data":   input,
	}
	jsonInner, err := json.Marshal(reqInner)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inner request: %w", err)
	}

	encryptedBytes, err := datap.Encrypt(jsonInner, s.publicKey)
	if err != nil {
		return nil, err
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(encryptedBytes)

	requestBody := map[string]string{
		"encrypted":    encryptedB64,
		"clientPubKey": clientPubB64,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("http://%s:%s%s", s.ip, s.port, route)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %s", resp.Status)
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response {"encrypted": base64(response_ciphertext)}
	var respMap map[string]string
	if err := json.Unmarshal(responseBody, &respMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response JSON: %w", err)
	}

	respEncryptedB64, ok := respMap["encrypted"]
	if !ok {
		return nil, fmt.Errorf("no 'encrypted' field in response")
	}

	respEncrypted, err := base64.StdEncoding.DecodeString(respEncryptedB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode response encrypted: %w", err)
	}

	decrypted, err := datap.Decrypt(respEncrypted, clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	return decrypted, nil
}

func (h Host) ProcessRequest(requestBody []byte) ([]byte, *rsa.PublicKey, error) {
	// ProcessRequest parses outer JSON, decrypts inner payload, verifies ApiKey == h.ApiKey.
	// Returns data bytes, parsed client public key.
	// Expects {"encrypted": b64(inner), "clientPubKey": b64(pubDER)}
	var reqMap map[string]string
	if err := json.Unmarshal(requestBody, &reqMap); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request JSON: %w", err)
	}

	encryptedB64, ok := reqMap["encrypted"]
	if !ok {
		return nil, nil, fmt.Errorf("no 'encrypted' field in request")
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode encrypted failed: %w", err)
	}

	decryptedJSON, err := datap.Decrypt(encryptedBytes, h.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt failed: %w", err)
	}

	var innerReq map[string]interface{}
	if err := json.Unmarshal(decryptedJSON, &innerReq); err != nil {
		return nil, nil, fmt.Errorf("unmarshal inner request failed: %w", err)
	}

	apiKey, ok := innerReq["ApiKey"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid ApiKey")
	}
	if apiKey != h.ApiKey {
		return nil, nil, fmt.Errorf("apiKey mismatch")
	}

	dataB64, ok := innerReq["Data"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("invalid Data")
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode Data failed: %w", err)
	}

	clientPubB64, ok := reqMap["clientPubKey"]
	if !ok {
		return nil, nil, fmt.Errorf("no clientPubKey in request")
	}

	clientPubDER, err := base64.StdEncoding.DecodeString(clientPubB64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode ClientPubKey failed: %w", err)
	}

	clientPubKeyIf, err := x509.ParsePKIXPublicKey(clientPubDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse client pubkey failed: %w", err)
	}

	clientPubKey, ok := clientPubKeyIf.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("client pubkey not RSA")
	}

	return data, clientPubKey, nil
}

func DoResponse(clientPub *rsa.PublicKey, responseData []byte) ([]byte, error) {
	// DoResponse encrypts response data with client pubkey, returns JSON {"encrypted": b64(ciphertext)}
	encryptedResp, err := datap.Encrypt(responseData, clientPub)
	if err != nil {
		return nil, err
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(encryptedResp)

	respMap := map[string]string{
		"encrypted": encryptedB64,
	}
	return json.Marshal(respMap)
}
