package compose

// ComposeFile represents a parsed docker-compose file.
type ComposeFile struct {
	Path     string         `json:"path"`
	Services map[string]any `json:"services,omitempty"`
	Networks map[string]any `json:"networks,omitempty"`
	Volumes  map[string]any `json:"volumes,omitempty"`
}
