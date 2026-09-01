//go:build windows

package secureeval

import (
	"errors"
	"testing"
)

func TestWindowsPhysicalMemorySamplerUsesOneStatusResult(t *testing.T) {
	calls := 0
	totals, err := sampleWindowsPhysicalMemoryWithCall(func(status *windowsMemoryStatusEx) error {
		calls++
		if status.length != uint32(windowsMemoryStatusExBytes) {
			t.Fatalf("MEMORYSTATUSEX length=%d, want %d", status.length, windowsMemoryStatusExBytes)
		}
		status.totalPhys = 33_618_251_776
		status.availPhys = 17_192_038_400
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || totals != (physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}) {
		t.Fatalf("Windows calls/totals=%d/%+v", calls, totals)
	}

	sentinel := errors.New("GlobalMemoryStatusEx sentinel")
	if _, err = sampleWindowsPhysicalMemoryWithCall(func(*windowsMemoryStatusEx) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("syscall error=%v, want sentinel", err)
	}
	for _, invalid := range []physicalMemoryTotals{{}, {total: 1, available: 2}} {
		if _, err = sampleWindowsPhysicalMemoryWithCall(func(status *windowsMemoryStatusEx) error {
			status.totalPhys, status.availPhys = invalid.total, invalid.available
			return nil
		}); err == nil {
			t.Fatalf("invalid Windows totals %+v were accepted", invalid)
		}
	}
}
