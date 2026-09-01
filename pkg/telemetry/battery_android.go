//go:build android

package telemetry

// batteryDebugLog mirrors the Linux implementation's hook; the Android
// collector does its own logging on the app side.
var batteryDebugLog func(msg string)

// batterySupported is true on Android: the companion app can always read
// battery state via BatteryManager, even though sysfs is closed to us.
const batterySupported = true

// getBatteryInfoImpl asks the registered HostProvider (the companion app,
// via the local IPC bridge) instead of reading /sys/class/power_supply,
// which an app-uid process may not open on a stock device.
func getBatteryInfoImpl() (*BatteryInfo, error) {
	p := currentHostProvider()
	if p == nil {
		// Companion not wired up yet; not an error, just nothing to report.
		return nil, nil
	}
	return p.BatteryInfo()
}
