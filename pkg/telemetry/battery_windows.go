//go:build windows

package telemetry

import (
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"
)

// Minimal WMI model for Win32_Battery.
type win32Battery struct {
	DeviceID                 string
	EstimatedChargeRemaining uint16
	BatteryStatus            uint16
}

func getBatteryInfoImpl() (*BatteryInfo, error) {
	var dst []win32Battery
	// Note: Win32_Battery may be absent on desktops/servers; treat as "no battery".
	if err := wmi.Query("SELECT DeviceID, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery", &dst); err != nil {
		return nil, fmt.Errorf("wmi Win32_Battery query failed: %w", err)
	}
	if len(dst) == 0 {
		return nil, nil
	}

	out := &BatteryInfo{}
	for _, b := range dst {
		dev := BatteryDevice{
			ID:      strings.TrimSpace(b.DeviceID),
			Percent: float64(b.EstimatedChargeRemaining),
			Status:  normalizeWinBatteryStatus(b.BatteryStatus),
		}
		out.Devices = append(out.Devices, dev)
	}
	if len(out.Devices) == 0 {
		return nil, nil
	}
	return out, nil
}

func normalizeWinBatteryStatus(code uint16) string {
	// See Win32_Battery.BatteryStatus:
	// 1=Discharging, 2=AC, 3=Fully Charged, 4=Low, 5=Critical, 6=Charging,
	// 7=Charging and High, 8=Charging and Low, 9=Charging and Critical,
	// 10=Undefined, 11=Partially Charged.
	switch code {
	case 1:
		return "discharging"
	case 2, 6, 7, 8, 9, 11:
		return "charging"
	case 3:
		return "full"
	default:
		return "unknown"
	}
}
