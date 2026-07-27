//go:build !linux && !windows

package telemetry

// batteryDebugLog is a debug logger function for battery discovery. Not used on non-Linux platforms.
var batteryDebugLog func(msg string)

// batterySupported is false on platforms with no battery telemetry
// implementation. See battery_linux.go.
const batterySupported = false

// getBatteryInfoImpl is a best-effort battery collector. On unsupported platforms it returns nil.
func getBatteryInfoImpl() (*BatteryInfo, error) {
	return nil, nil
}
