//go:build linux

package telemetry

import (
	"context"
	"strconv"
	"strings"
	"time"
)

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

// DetectGPUs probes for NVIDIA and AMD GPUs via vendor CLI tools.
func DetectGPUs() []GPUDevice {
	var gpus []GPUDevice
	gpus = append(gpus, detectNVIDIA()...)
	gpus = append(gpus, detectAMD()...)
	return gpus
}

func detectNVIDIA() []GPUDevice {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := "index,name,uuid,memory.total,driver_version,compute_cap,temperature.gpu,utilization.gpu,memory.used,memory.free"
	stdout, _, _, err := runCmd(ctx,
		"nvidia-smi",
		"--query-gpu="+query,
		"--format=csv,noheader,nounits",
	)
	if err != nil {
		return nil
	}

	var gpus []GPUDevice
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ", ")
		if len(fields) < 10 {
			continue
		}

		idx, _ := strconv.Atoi(strings.TrimSpace(fields[0]))
		memTotal, _ := strconv.ParseInt(strings.TrimSpace(fields[3]), 10, 64)
		temp, _ := strconv.ParseFloat(strings.TrimSpace(fields[6]), 64)
		util, _ := strconv.ParseFloat(strings.TrimSpace(fields[7]), 64)
		memUsed, _ := strconv.ParseInt(strings.TrimSpace(fields[8]), 10, 64)
		memFree, _ := strconv.ParseInt(strings.TrimSpace(fields[9]), 10, 64)

		gpus = append(gpus, GPUDevice{
			Index:              idx,
			Name:               strings.TrimSpace(fields[1]),
			Vendor:             "NVIDIA",
			UUID:               strings.TrimSpace(fields[2]),
			MemoryMB:           memTotal,
			DriverVersion:      strings.TrimSpace(fields[4]),
			ComputeCapability:  strings.TrimSpace(fields[5]),
			Temperature:        temp,
			UtilizationPercent: util,
			MemoryUsedMB:       memUsed,
			MemoryFreeMB:       memFree,
		})
	}
	return gpus
}

func detectAMD() []GPUDevice {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stdout, _, _, err := runCmd(ctx, "rocm-smi", "--showid", "--showtemp", "--showuse", "--showmeminfo", "vram", "--csv")
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return nil
	}

	var gpus []GPUDevice
	for i, line := range lines[1:] {
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}

		gpu := GPUDevice{
			Index:  i,
			Vendor: "AMD",
			Name:   strings.TrimSpace(fields[0]),
		}

		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if v, err := strconv.ParseFloat(f, 64); err == nil {
				if gpu.Temperature == 0 {
					gpu.Temperature = v
				} else if gpu.UtilizationPercent == 0 {
					gpu.UtilizationPercent = v
				}
			}
		}

		gpus = append(gpus, gpu)
	}
	return gpus
}
