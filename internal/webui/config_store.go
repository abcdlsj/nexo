package webui

import (
	"github.com/abcdlsj/nexo/internal/configstore"
	"github.com/abcdlsj/nexo/pkg/config"
)

// configStore is the shared configuration writer also used by the control
// plane, so remote and local edits share one serializer.
type configStore = configstore.Store

func newConfigStore(initial *config.Config, path string, onChange func() error) *configStore {
	return configstore.New(initial, path, onChange)
}
