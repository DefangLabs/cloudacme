package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"defang.io/cloudacme/aws/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type AccountKeyStore interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, key []byte) error
}

var ErrNotFound = errors.New("account key not found")

type FileAccountKeyStore struct {
	Path string
}

func (f FileAccountKeyStore) Load(ctx context.Context) ([]byte, error) {
	keyPem, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return keyPem, err
}

func (f FileAccountKeyStore) Save(ctx context.Context, key []byte) error {
	return os.WriteFile(f.Path, key, 0600)
}

type SSMAccountKeyStore struct {
	Name string
}

func (s SSMAccountKeyStore) Load(ctx context.Context) ([]byte, error) {
	keyPem, err := ssm.GetParameter(ctx, s.Name)
	var notFoundErr *types.ParameterNotFound
	if errors.As(err, &notFoundErr) {
		return nil, ErrNotFound
	}
	return []byte(keyPem), err
}

func (s SSMAccountKeyStore) Save(ctx context.Context, key []byte) error {
	return ssm.PutParameter(ctx, s.Name, string(key))
}

func loadAccountKeySSM(name string) (*ecdsa.PrivateKey, error) {
	keyPem, err := ssm.GetParameter(context.Background(), name)
	var notFoundErr *types.ParameterNotFound
	if errors.As(err, &notFoundErr) {
		return nil, fmt.Errorf("account key not found in SSM")
	} else if err != nil {
		return nil, fmt.Errorf("failed to get account key from SSM: %v", err)
	}
	panic(keyPem)
}

func LoadOrCreateAccountKey(ctx context.Context, keyStore AccountKeyStore) (*ecdsa.PrivateKey, error) {
	keyPem, err := keyStore.Load(ctx)
	if errors.Is(err, ErrNotFound) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generating account key: %v", err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal account key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := keyStore.Save(ctx, keyPem); err != nil {
			return key, fmt.Errorf("failed to store account key: %v", err)
		}
		return key, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to load account key: %v", err)
	}
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, fmt.Errorf("failed to decode account key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse account key: %v", err)
	}
	return key, nil
}
