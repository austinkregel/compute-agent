package telemetry

import (
	"os/exec"
	"strings"
)

// GPUCapability describes a detected GPU.
type GPUCapability struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
	VRAM   string `json:"vram,omitempty"`
}

// DetectGPUs probes for NVIDIA and AMD GPUs using CLI tools.
func DetectGPUs() []GPUCapability {
	var caps []GPUCapability
	caps = append(caps, detectNvidia()...)
	caps = append(caps, detectAMD()...)
	return caps
}

func detectNvidia() []GPUCapability {
	out, err := exec.Command("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil
	}
	var caps []GPUCapability
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, ", ", 2)
		if len(parts) < 1 || parts[0] == "" {
			continue
		}
		cap := GPUCapability{Vendor: "nvidia", Model: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			cap.VRAM = strings.TrimSpace(parts[1]) + " MiB"
		}
		caps = append(caps, cap)
	}
	return caps
}

func detectAMD() []GPUCapability {
	out, err := exec.Command("rocm-smi", "--showproductname", "--csv").Output()
	if err != nil {
		return nil
	}
	var caps []GPUCapability
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines[1:] {
		fields := strings.SplitN(line, ",", 2)
		if len(fields) < 2 || fields[1] == "" {
			continue
		}
		caps = append(caps, GPUCapability{Vendor: "amd", Model: strings.TrimSpace(fields[1])})
	}
	return caps
}
