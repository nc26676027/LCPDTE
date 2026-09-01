package secureeval

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxLinuxProcessStatusBytes = 64 * 1024

var errUnsupportedProcessPeakRSS = errors.New("secureeval: process peak RSS sampling is unsupported on this platform")

func parseLinuxProcessPeakRSS(reader io.Reader) (uint64, error) {
	if reader == nil {
		return 0, errors.New("secureeval: nil /proc/self/status reader")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxLinuxProcessStatusBytes+1))
	if err != nil {
		return 0, fmt.Errorf("secureeval: read /proc/self/status: %w", err)
	}
	if len(payload) > maxLinuxProcessStatusBytes {
		return 0, errors.New("secureeval: /proc/self/status exceeds the bounded parser limit")
	}

	var peak uint64
	found := false
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "VmHWM:" {
			continue
		}
		if found {
			return 0, errors.New("secureeval: duplicate VmHWM in /proc/self/status")
		}
		if len(fields) != 3 || fields[2] != "kB" || !isUnsignedDecimal(fields[1]) {
			return 0, errors.New("secureeval: malformed VmHWM in /proc/self/status")
		}
		kilobytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil || kilobytes == 0 || kilobytes > ^uint64(0)/1024 {
			return 0, errors.New("secureeval: invalid VmHWM in /proc/self/status")
		}
		peak = kilobytes * 1024
		found = true
	}
	if !found {
		return 0, errors.New("secureeval: /proc/self/status lacks VmHWM")
	}
	return peak, nil
}

func isUnsignedDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
