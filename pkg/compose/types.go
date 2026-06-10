package compose

// PortMapping describes a port mapping for a container.
type PortMapping struct {
	Host      string `json:"host,omitempty"`
	Container string `json:"container"`
	Protocol  string `json:"protocol,omitempty"`
}

// VolumeMapping describes a volume/bind mount.
type VolumeMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type,omitempty"`
}
