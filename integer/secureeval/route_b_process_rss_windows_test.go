//go:build windows

package secureeval

import (
	"errors"
	"testing"
	"unsafe"
)

func TestWindowsProcessPeakRSSCall(t *testing.T) {
	peak, err := sampleWindowsProcessPeakRSSWithCall(func(counters *windowsProcessMemoryCounters) error {
		if counters.cb != uint32(unsafe.Sizeof(windowsProcessMemoryCounters{})) {
			t.Fatalf("PROCESS_MEMORY_COUNTERS cb=%d", counters.cb)
		}
		counters.peakWorkingSetSize = 987_654_321
		return nil
	})
	if err != nil || peak != 987_654_321 {
		t.Fatalf("Windows peak RSS=%d/%v", peak, err)
	}
	sentinel := errors.New("psapi sentinel")
	if peak, err = sampleWindowsProcessPeakRSSWithCall(func(*windowsProcessMemoryCounters) error { return sentinel }); !errors.Is(err, sentinel) || peak != 0 {
		t.Fatalf("Windows call failure=%d/%v", peak, err)
	}
	if peak, err = sampleWindowsProcessPeakRSSWithCall(func(*windowsProcessMemoryCounters) error { return nil }); err == nil || peak != 0 {
		t.Fatalf("Windows zero peak=%d/%v", peak, err)
	}
	if peak, err = sampleWindowsProcessPeakRSSWithCall(nil); err == nil || peak != 0 {
		t.Fatalf("Windows nil call=%d/%v", peak, err)
	}
}
