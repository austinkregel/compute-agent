package compose

// ScanResult is the transport-friendly result of scanning a directory for compose files.
type ScanResult struct {
	Dir   string        `json:"dir"`
	Files []ComposeFile `json:"files"`
	Error string        `json:"error,omitempty"`
}

// ComposeFile describes a single docker-compose file found during a scan.
type ComposeFile struct {
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Services []string `json:"services"`
	Includes []string `json:"includes,omitempty"`
}

// ParseResult is the transport-friendly result of fully parsing a compose file.
type ParseResult struct {
	File     string                    `json:"file"`
	Services []ParsedService           `json:"services"`
	Networks map[string]ParsedNetwork  `json:"networks,omitempty"`
	Volumes  map[string]ParsedVolume   `json:"volumes,omitempty"`
	Error    string                    `json:"error,omitempty"`
}

// ParsedService is a transport-friendly representation of a compose service.
type ParsedService struct {
	Name        string                       `json:"name"`
	Image       string                       `json:"image"`
	Ports       []string                     `json:"ports,omitempty"`
	Volumes     []string                     `json:"volumes,omitempty"`
	Command     []string                     `json:"command,omitempty"`
	Entrypoint  []string                     `json:"entrypoint,omitempty"`
	ExtraHosts  []string                     `json:"extraHosts,omitempty"`
	Devices     []string                     `json:"devices,omitempty"`
	Environment map[string]string            `json:"environment,omitempty"`
	Labels      map[string]string            `json:"labels,omitempty"`
	DependsOn   map[string]ServiceDependency `json:"dependsOn,omitempty"`
	HealthCheck *HealthCheckConfig           `json:"healthCheck,omitempty"`
	Deploy      *DeployConfig                `json:"deploy,omitempty"`
	Restart     string                       `json:"restart,omitempty"`
	NetworkMode string                       `json:"networkMode,omitempty"`
	Networks    []string                     `json:"networks,omitempty"`
}

// ServiceDependency captures the condition for a depends_on entry.
type ServiceDependency struct {
	Condition string `json:"condition"`
}

// HealthCheckConfig is the transport-friendly representation of a health check.
type HealthCheckConfig struct {
	Test        []string `json:"test,omitempty"`
	Interval    string   `json:"interval,omitempty"`
	Timeout     string   `json:"timeout,omitempty"`
	StartPeriod string   `json:"startPeriod,omitempty"`
	Retries     int      `json:"retries,omitempty"`
	Disable     bool     `json:"disable,omitempty"`
}

// DeployConfig is the transport-friendly representation of deploy settings.
type DeployConfig struct {
	Replicas  *int            `json:"replicas,omitempty"`
	Resources *ResourceConfig `json:"resources,omitempty"`
}

// ResourceConfig holds limits and reservations.
type ResourceConfig struct {
	Limits       *ResourceSpec `json:"limits,omitempty"`
	Reservations *ResourceSpec `json:"reservations,omitempty"`
}

// ResourceSpec describes CPU/memory/device resource constraints.
type ResourceSpec struct {
	CPUs    float64      `json:"cpus,omitempty"`
	Memory  string       `json:"memory,omitempty"`
	Devices []DeviceSpec `json:"devices,omitempty"`
}

// DeviceSpec describes a device request (e.g. GPU).
type DeviceSpec struct {
	Capabilities []string `json:"capabilities,omitempty"`
	Count        int      `json:"count,omitempty"`
	Driver       string   `json:"driver,omitempty"`
}

// ParsedNetwork is the transport-friendly representation of a compose network.
type ParsedNetwork struct {
	Driver   string `json:"driver,omitempty"`
	External bool   `json:"external,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// ParsedVolume is the transport-friendly representation of a compose volume.
type ParsedVolume struct {
	Driver   string `json:"driver,omitempty"`
	External bool   `json:"external,omitempty"`
}
