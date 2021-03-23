package storage

import "github.com/dexidp/dex/pkg/log"

// StorageConfig is a configuration that can create a storage.
type StorageConfig interface {
	Open(logger log.Logger) (Storage, error)
}
