//go:build windows

package secureeval

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

type windowsProcessMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

func sampleProductionProcessPeakRSS() (uint64, error) {
	getCurrentProcess := syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcess")
	getProcessMemoryInfo := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	process, _, callErr := getCurrentProcess.Call()
	if process == 0 {
		if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
			return 0, fmt.Errorf("secureeval: GetCurrentProcess: %w", callErr)
		}
		return 0, errors.New("secureeval: GetCurrentProcess returned a zero handle")
	}
	return sampleWindowsProcessPeakRSSWithCall(func(counters *windowsProcessMemoryCounters) error {
		result, _, processErr := getProcessMemoryInfo.Call(
			process, uintptr(unsafe.Pointer(counters)), uintptr(counters.cb),
		)
		if result != 0 {
			return nil
		}
		if processErr != nil && !errors.Is(processErr, syscall.Errno(0)) {
			return processErr
		}
		return syscall.EINVAL
	})
}

func sampleWindowsProcessPeakRSSWithCall(call func(*windowsProcessMemoryCounters) error) (uint64, error) {
	if call == nil {
		return 0, errors.New("secureeval: nil GetProcessMemoryInfo call")
	}
	size := unsafe.Sizeof(windowsProcessMemoryCounters{})
	if size == 0 || size > uintptr(^uint32(0)) {
		return 0, errors.New("secureeval: invalid PROCESS_MEMORY_COUNTERS layout")
	}
	counters := windowsProcessMemoryCounters{cb: uint32(size)}
	if err := call(&counters); err != nil {
		return 0, fmt.Errorf("secureeval: GetProcessMemoryInfo: %w", err)
	}
	peak := uint64(counters.peakWorkingSetSize)
	if peak == 0 {
		return 0, errors.New("secureeval: GetProcessMemoryInfo returned zero peak working set")
	}
	return peak, nil
}
