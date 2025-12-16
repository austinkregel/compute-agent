//go:build !linux && !windows

package telemetry

// getBatteryInfoImpl is a best-effort battery collector. On unsupported platforms it returns nil.
func getBatteryInfoImpl() (*BatteryInfo, error) {
	return nil, nil
}

