package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
	"raven/internal/integrity"
)

type fileConfig struct {
	ListenAddress         string `yaml:"listen_address"`
	DatabasePath          string `yaml:"database_path"`
	StreamID              string `yaml:"stream_id"`
	GenesisHash           string `yaml:"genesis_hash"`
	KeyID                 string `yaml:"key_id"`
	PrivateKeyPath        string `yaml:"private_key_path"`
	ProducerTokenEnv      string `yaml:"producer_token_env"`
	AdminTokenEnv         string `yaml:"admin_token_env"`
	RPCURL                string `yaml:"rpc_url"`
	ChainID               uint64 `yaml:"chain_id"`
	ChainGenesisBlockHash string `yaml:"chain_genesis_block_hash"`
	ContractAddress       string `yaml:"contract_address"`
	DeploymentBlock       uint64 `yaml:"deployment_block"`
	DeploymentBlockHash   string `yaml:"deployment_block_hash"`
	RuntimeCodeHash       string `yaml:"runtime_code_hash"`
	AnchorPrivateKeyEnv   string `yaml:"anchor_private_key_env"`
}

type RuntimeConfig struct {
	ListenAddress string
	DatabasePath  string
	StreamID      integrity.Hash
	GenesisHash   integrity.Hash
	ProducerToken string
	AdminToken    string
	Signer        ReceiptSigner
	Anchor        *AnchorConfig
}

func LoadConfig(path string) (RuntimeConfig, error) {
	var result RuntimeConfig
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	dec := yaml.NewDecoder(file)
	dec.KnownFields(true)
	var cfg fileConfig
	if err := dec.Decode(&cfg); err != nil {
		return result, fmt.Errorf("decode witness config: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return result, errors.New("witness config must contain one YAML document")
		}
		return result, fmt.Errorf("decode trailing witness config: %w", err)
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:9091"
	}
	if cfg.DatabasePath == "" || cfg.PrivateKeyPath == "" || cfg.KeyID == "" || cfg.ProducerTokenEnv == "" || cfg.AdminTokenEnv == "" {
		return result, errors.New("database_path, private_key_path, key_id, and both credential environment names are required")
	}
	streamID, err := parseHash(cfg.StreamID)
	if err != nil {
		return result, fmt.Errorf("stream_id: %w", err)
	}
	genesis, err := parseHash(cfg.GenesisHash)
	if err != nil {
		return result, fmt.Errorf("genesis_hash: %w", err)
	}
	if len(cfg.KeyID) > 128 || !utf8.ValidString(cfg.KeyID) || strings.ContainsRune(cfg.KeyID, '\x00') {
		return result, errors.New("key_id must be 1..128 valid UTF-8 bytes without NUL")
	}
	privateBytes, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return result, fmt.Errorf("read witness signing key: %w", err)
	}
	info, err := os.Stat(cfg.PrivateKeyPath)
	if err != nil {
		return result, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return result, errors.New("witness private key permissions must not grant group or other access")
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateBytes)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return result, errors.New("witness private key must be base64-encoded raw Ed25519 private key bytes")
	}
	producerToken := os.Getenv(cfg.ProducerTokenEnv)
	adminToken := os.Getenv(cfg.AdminTokenEnv)
	if len(producerToken) < 32 || len(adminToken) < 32 {
		return result, errors.New("witness producer and admin environment credentials must each contain at least 32 bytes")
	}
	var anchor *AnchorConfig
	if cfg.RPCURL != "" || cfg.AnchorPrivateKeyEnv != "" || cfg.ContractAddress != "" {
		if cfg.RPCURL == "" || cfg.AnchorPrivateKeyEnv == "" || cfg.ContractAddress == "" || cfg.ChainID == 0 || cfg.ChainGenesisBlockHash == "" || cfg.DeploymentBlockHash == "" || cfg.RuntimeCodeHash == "" {
			return result, errors.New("anchoring config requires rpc_url, chain identity, contract address, deployment identity, and anchor_private_key_env")
		}
		key := os.Getenv(cfg.AnchorPrivateKeyEnv)
		if len(strings.TrimPrefix(strings.TrimSpace(key), "0x")) != 64 {
			return result, errors.New("anchor private key environment value must be a 32-byte hex key")
		}
		identity := ChainIdentity{ChainID: cfg.ChainID, GenesisBlockHash: strings.ToLower(cfg.ChainGenesisBlockHash), ContractAddress: strings.ToLower(cfg.ContractAddress), DeploymentBlock: cfg.DeploymentBlock, DeploymentBlockHash: strings.ToLower(cfg.DeploymentBlockHash), RuntimeCodeHash: strings.ToLower(cfg.RuntimeCodeHash)}
		for _, h := range []string{identity.GenesisBlockHash, identity.DeploymentBlockHash, identity.RuntimeCodeHash} {
			if _, err := parseHash(h); err != nil {
				return result, fmt.Errorf("invalid pinned chain hash: %w", err)
			}
		}
		if len(identity.ContractAddress) != 42 || !strings.HasPrefix(identity.ContractAddress, "0x") {
			return result, errors.New("contract_address must be a 20-byte hex address")
		}
		anchor = &AnchorConfig{RPCURL: cfg.RPCURL, Identity: identity, PrivateKeyHex: key}
	}
	result = RuntimeConfig{
		ListenAddress: cfg.ListenAddress,
		DatabasePath:  cfg.DatabasePath,
		StreamID:      streamID,
		GenesisHash:   genesis,
		ProducerToken: producerToken,
		AdminToken:    adminToken,
		Signer:        ReceiptSigner{KeyID: cfg.KeyID, Key: ed25519.PrivateKey(privateKey)},
		Anchor:        anchor,
	}
	return result, nil
}

func GenerateReceiptKey(privatePath, publicPath string) error {
	privateDir := filepath.Dir(privatePath)
	publicDir := filepath.Dir(publicPath)
	if err := os.MkdirAll(privateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateFile, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(privateFile, base64.StdEncoding.EncodeToString(privateKey)); err != nil {
		privateFile.Close()
		os.Remove(privatePath)
		return err
	}
	if err := privateFile.Close(); err != nil {
		os.Remove(privatePath)
		return err
	}
	publicFile, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		os.Remove(privatePath)
		return err
	}
	if _, err := fmt.Fprintln(publicFile, base64.StdEncoding.EncodeToString(publicKey)); err != nil {
		publicFile.Close()
		os.Remove(privatePath)
		os.Remove(publicPath)
		return err
	}
	if err := publicFile.Close(); err != nil {
		os.Remove(privatePath)
		os.Remove(publicPath)
		return err
	}
	return nil
}
