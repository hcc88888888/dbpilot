package job

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

type TokenProtector interface {
	Protect(context.Context, []byte) ([]byte, error)
	Unprotect(context.Context, []byte) ([]byte, error)
}

type AES256GCMTokenProtector struct {
	key [32]byte
}

func NewAES256GCMTokenProtector(key []byte) (*AES256GCMTokenProtector, error) {
	if len(key) != 32 {
		return nil, errors.New("execution token protection key must contain exactly 32 bytes")
	}
	protector := &AES256GCMTokenProtector{}
	copy(protector.key[:], key)
	return protector, nil
}

func (protector *AES256GCMTokenProtector) Protect(ctx context.Context, token []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidCommandPayload
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if protector == nil || len(token) != sha256.Size {
		return nil, ErrInvalidCommandPayload
	}
	aead, err := protector.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate execution token nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, token, nil), nil
}

func (protector *AES256GCMTokenProtector) Unprotect(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidCommandPayload
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if protector == nil {
		return nil, ErrInvalidCommandPayload
	}
	aead, err := protector.aead()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrInvalidCommandPayload
	}
	nonce := ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], nil)
	if err != nil || len(plaintext) != sha256.Size {
		clearSensitiveBytes(plaintext)
		return nil, ErrInvalidCommandPayload
	}
	return plaintext, nil
}

func (protector *AES256GCMTokenProtector) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(protector.key[:])
	if err != nil {
		return nil, fmt.Errorf("create execution token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create execution token AEAD: %w", err)
	}
	return aead, nil
}
