//go:build !linux

package telemetry

// GPUDevice describes a detected GPU.
type GPUDevice struct {
	Index              int     `json:"index"`
	Name               string  `json:"name"`
	Vendor             string  `json:"vendor"`
	UUID               string  `json:"uuid,omitempty"`
	MemoryMB           int64   `json:"memoryMB,omitempty"`
	DriverVersion      string  `json:"driverVersion,omitempty"`
	ComputeCapability  string  `json:"computeCapability,omitempty"`
	Temperature        float64 `json:"temperature,omitempty"`
	UtilizationPercent float64 `json:"utilizationPercent,omitempty"`
	MemoryUsedMB       int64   `json:"memoryUsedMB,omitempty"`
	MemoryFreeMB       int64   `json:"memoryFreeMB,omitempty"`
}

// DetectGPUs is a no-op on non-Linux platforms.
func DetectGPUs() []GPUDevice {
	return nil
}
