package data

import (
    "github.com/privateerproj/privateer-sdk/config"
)

// Payload contains a very small set of fields used by example evaluations.
type Payload struct {
    Config *config.Config
}

// Loader builds and returns a minimal payload for the evaluation.
// Signature matches what the SDK expects
func Loader(cfg *config.Config) (payload any, err error) {
    return Payload{
        Config: cfg,
    }, nil
}
