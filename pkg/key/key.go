package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

/*
KeyExport generates RSA keypair and saves PEM files.

Arguments:
  - filename string: Base name for output files (e.g. "myapp" → myapp-private.pem, myapp-public.pem)
*/
func KeyExport(filename string) {
	// 1. Generate RSA Key Pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}

	// 2. Export Private Key to PEM
	privateFile, _ := os.Create(fmt.Sprintf("%s-private.pem", filename))
	defer privateFile.Close()

	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pem.Encode(privateFile, privateBlock)

	// 3. Export Public Key to PEM
	publicKey := &privateKey.PublicKey
	publicFile, _ := os.Create(fmt.Sprintf("%s-public.pem", filename))
	defer publicFile.Close()

	// Convert public key to PKIX DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Printf("Error marshaling public key: %v\n", err)
		return
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pem.Encode(publicFile, publicBlock)

	fmt.Printf("Keys generated and exported to %s-private.pem and %s-public.pem\n", filename, filename)
}

/*
KeyGen generates new RSA 2048-bit keypair.

Returns:
  - *rsa.PublicKey: Generated public key
  - *rsa.PrivateKey: Generated private key
*/
func KeyGen() (*rsa.PublicKey, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return nil, nil
	}
	return &privateKey.PublicKey, privateKey
}

/*
ImportPublic loads RSA public key from PEM file.

Arguments:
  - filename string: Path to public key PEM file

Returns:
  - *rsa.PublicKey: Loaded public key
  - error: Any parsing error
*/
func ImportPublic(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected PUBLIC KEY, got %s", block.Type)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaKey, nil
}

/*
ImportPrivate loads RSA private key from PEM file.

Arguments:
  - filename string: Path to private key PEM file

Returns:
  - *rsa.PrivateKey: Loaded private key
  - error: Any parsing error
*/
func ImportPrivate(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected RSA PRIVATE KEY, got %s", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}
