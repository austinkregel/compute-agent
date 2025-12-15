package telemetry

import "testing"

func TestParseAptGetSimulatedUpgradeCount(t *testing.T) {
	out := `
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
Inst libc6 [2.35-0ubuntu3.4] (2.35-0ubuntu3.5 Ubuntu:22.04/jammy-updates [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])
Conf libc6 (2.35-0ubuntu3.5 Ubuntu:22.04/jammy-updates [amd64])
Conf openssl (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates [amd64])
`
	if got := parseAptGetSimulatedUpgradeCount(out); got != 2 {
		t.Fatalf("count mismatch: got %d want %d", got, 2)
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	out := `
Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Ventura 13.6.1-22G313
	Title: macOS Ventura 13.6.1, 774355K [recommended] [restart]
	Action: restart
* Label: Security Update 2025-001 (Sonoma)
	Title: Security Update 2025-001, 12345K [recommended]
	Action: install
`
	avail, sec, restart := parseSoftwareUpdateList(out)
	if avail != 2 {
		t.Fatalf("available mismatch: got %d want %d", avail, 2)
	}
	if sec != 1 {
		t.Fatalf("security mismatch: got %d want %d", sec, 1)
	}
	if !restart {
		t.Fatalf("restartRequired mismatch: got %v want %v", restart, true)
	}
}


