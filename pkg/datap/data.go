package datap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

/*
Encrypt encrypts plaintext using RSA OAEP with SHA256.

Arguments:
  - s []byte: Plaintext data to encrypt
  - key *rsa.PublicKey: RSA public key for encryption

Returns:
  - []byte: OAEP ciphertext
  - error: Encryption error
*/
func Encrypt(s []byte, key *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, s, nil)
	return ciphertext, err
}

/*
Decrypt decrypts RSA OAEP ciphertext using SHA256.

Arguments:
  - e []byte: OAEP ciphertext to decrypt
  - key *rsa.PrivateKey: RSA private key for decryption

Returns:
  - []byte: Original plaintext
  - error: Decryption error
*/
func Decrypt(e []byte, key *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, e, nil)
	return plaintext, err
}
