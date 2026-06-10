package telemetry

// This file ensures gpu_caps.go compiles regardless of whether nvidia-smi
// or rocm-smi are available at compile time. The actual detection happens
// at runtime via exec.Command.
