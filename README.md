# Authentify

Secure client-server communication library using RSA hybrid encryption.

## Features

- RSA key generation and PEM export/import
- Client-server encrypted messaging protocol
- Gin HTTP handler example
- Self-contained roundtrip testing

## Protocol Flow

1. Client generates ephemeral keypair, encrypts `{ApiKey, Data}` with host pubkey
2. Sends `{"encrypted": b64(ciphertext), "clientPubKey": b64(pubDER)}`
3. Host decrypts with privkey, verifies ApiKey, parses client pubkey
4. Host encrypts response data with client pubkey, sends `{"encrypted": b64(ciphertext)}`
5. Client decrypts with privkey → raw data

## Quick Start

```bash
go mod tidy
go run main.go  # server :8080 /api/test
```

Test client:
```bash
go run client_example.go
```

## Usage

### Key Management

```go
pub, priv := key.KeyGen()
key.KeyExport("myapp") // myapp-private.pem, myapp-public.pem
pub2, _ := key.ImportPublic("myapp-public.pem")
```

### Client

```go
s := web.Connection("127.0.0.1", "8080", "", "apikey", "host-public.pem")
resp, err := s.DoRequest("/api/test", []byte("data"))
```

### Server Handler

```go
h := web.Host{ApiKey: "apikey", PrivateKey: priv}
data, clientPub, _, err := h.ProcessRequest(body)
resp := web.DoResponse(clientPub, responseData)
```

## Structure

```
pkg/key/
  - KeyGen() → keys
  - KeyExport(name)
  - ImportPublic/Private(filename)

pkg/datap/
  - Encrypt/Decrypt (RSA OAEP SHA256)

pkg/web/
  - Connection(ip, port, caller, apiKey, pubPem) → Server
  - Server.DoRequest(route, data) → decrypted response
  - Host.ProcessRequest(body) → data, clientPub, apiKey
  - DoResponse(clientPub, data) → response JSON
```

## License

MIT