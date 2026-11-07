// Package bootstrap loads node-only trust and connection state from a protected local file.
// A signed manifest cannot add its own trust anchors, qualified builds, or TLS keys.
package bootstrap

import (
  "errors"
  "github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

type Config struct {
  GatewayOrigin string `json:"gatewayOrigin"`
  NodeID string `json:"nodeId"`
  ControlPlaneEpoch string `json:"controlPlaneEpoch"`
  JournalPath string `json:"journalPath"`
  RootCAFile string `json:"rootCAFile"`
  ClientCertFile string `json:"clientCertFile"`
  ClientKeyFile string `json:"clientKeyFile"`
  TrustedSigners map[string]string `json:"trustedSigners"`
  AllowedCapabilities []string `json:"allowedCapabilities"`
  QualifiedBuilds map[string]manifest.Build `json:"qualifiedBuilds"`
  PollSeconds int `json:"pollSeconds"`
  MaxClockSkewSeconds int `json:"maxClockSkewSeconds"`
}

var ErrInvalidBootstrap = errors.New("invalid protected node bootstrap configuration")

func Load(path string) (Config, error) {
  return Config{}, ErrInvalidBootstrap
}

func (c Config) Verifier() (manifest.Verifier, error) {
  return manifest.Verifier{}, ErrInvalidBootstrap
}

func ReadPrivatePEM(path string) ([]byte, error) {
  return nil, ErrInvalidBootstrap
}
