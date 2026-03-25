package web

import "crypto/rsa"

/*
Server holds client connection configuration.

Fields:
  - ip: Target server IP address
  - port: Target server port
  - caller: Caller identifier (unused)
  - apiKey: Authentication API key
  - publicKey: Server public key for encryption
*/
type Server struct {
	ip        string
	port      string
	caller    string
	apiKey    string
	publicKey *rsa.PublicKey
}

/*
Request represents decrypted inner request payload.
*/
type Request struct {
	ApiKey       string `json:"ApiKey"`
	Data         []byte `json:"Data"`
	ClientPubKey *rsa.PublicKey
}

/*
Host holds server configuration.

Fields:
  - ApiKey: Expected client API key
  - PrivateKey: Server private key for decryption
*/
type Host struct {
	ApiKey     string
	PrivateKey *rsa.PrivateKey
}
