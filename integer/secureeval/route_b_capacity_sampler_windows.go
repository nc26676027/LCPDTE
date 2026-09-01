//go:build windows

package secureeval

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const windowsMemoryStatusExBytes = 64

type windowsMemoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func (productionPhysicalMemorySampler) samplePhysicalMemory() (physicalMemoryTotals, error) {
	globalMemoryStatusExProc := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	return sampleWindowsPhysicalMemoryWithCall(func(status *windowsMemoryStatusEx) error {
		result, _, callErr := globalMemoryStatusExProc.Call(uintptr(unsafe.Pointer(status)))
		if result != 0 {
			return nil
		}
		if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
			return callErr
		}
		return syscall.EINVAL
	})
}

func sampleWindowsPhysicalMemoryWithCall(call func(*windowsMemoryStatusEx) error) (physicalMemoryTotals, error) {
	if call == nil {
		return physicalMemoryTotals{}, errors.New("secureeval: nil GlobalMemoryStatusEx call")
	}
	if unsafe.Sizeof(windowsMemoryStatusEx{}) != windowsMemoryStatusExBytes {
		return physicalMemoryTotals{}, errors.New("secureeval: unexpected MEMORYSTATUSEX layout")
	}
	status := windowsMemoryStatusEx{length: windowsMemoryStatusExBytes}
	if err := call(&status); err != nil {
		return physicalMemoryTotals{}, fmt.Errorf("secureeval: GlobalMemoryStatusEx: %w", err)
	}
	value := physicalMemoryTotals{total: status.totalPhys, available: status.availPhys}
	if err := value.validate(); err != nil {
		return physicalMemoryTotals{}, err
	}
	return value, nil
}
