package vault

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type DeviceInfo struct {
	Fingerprint string            `json:"fingerprint"`
	Platform    string            `json:"platform"`
	Identifiers map[string]string `json:"identifiers"`
	Hardware    map[string]string `json:"hardware"`
}

func GetDeviceInfo() (*DeviceInfo, error) {
	info := &DeviceInfo{
		Platform:    runtime.GOOS,
		Identifiers: make(map[string]string),
		Hardware:    make(map[string]string),
	}
	var idErr error
	switch runtime.GOOS {
	case "windows":
		info.Identifiers, idErr = getWindowsIdentifiers()
		info.Hardware = getWindowsHardwareInfo()
	case "darwin":
		info.Identifiers, idErr = getMacIdentifiers()
		info.Hardware = getMacHardwareInfo()
	case "linux":
		info.Identifiers, idErr = getLinuxIdentifiers()
		info.Hardware = getLinuxHardwareInfo()
	default:
		return nil, fmt.Errorf("unsupported platform")
	}
	if idErr != nil {
		return nil, fmt.Errorf("identifier error: %v", idErr)
	}
	fingerprint, err := generateFingerprint(info.Identifiers)
	if err != nil {
		return nil, err
	}
	info.Fingerprint = fingerprint
	return info, nil
}

func generateFingerprint(ids map[string]string) (string, error) {
	var parts []string
	for _, v := range ids {
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no identifiers available")
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("%x", hash), nil
}

func getWindowsIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			ids["bios_uuid"] = strings.TrimSpace(lines[1])
		}
	}
	cmd = exec.Command("reg", "query",
		"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
		"/v", "MachineGuid")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "MachineGuid") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					ids["machine_guid"] = parts[len(parts)-1]
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Windows identifiers")
	}
	return ids, nil
}

func getWindowsHardwareInfo() map[string]string {
	info := make(map[string]string)
	if output, err := exec.Command("wmic", "computersystem", "get", "manufacturer,model").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			parts := strings.Fields(lines[1])
			if len(parts) >= 2 {
				info["manufacturer"] = parts[0]
				info["model"] = strings.Join(parts[1:], " ")
			}
		}
	}
	if output, err := exec.Command("wmic", "cpu", "get", "name").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			info["cpu"] = strings.TrimSpace(lines[1])
		}
	}
	if output, err := exec.Command("wmic", "memorychip", "get", "capacity").Output(); err == nil {
		var total uint64
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] {
			if cp := strings.TrimSpace(line); cp != "" {
				var bytes uint64
				_, _ = fmt.Sscanf(cp, "%d", &bytes)
				total += bytes
			}
		}
		if total > 0 {
			info["memory"] = fmt.Sprintf("%d GB", total/1024/1024/1024)
		}
	}
	return info
}

func getMacIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, " = ")
				if len(parts) == 2 {
					ids["platform_uuid"] = strings.Trim(parts[1], "\"")
				}
			}
		}
	}
	if _, exists := ids["platform_uuid"]; !exists {
		cmd = exec.Command("system_profiler", "SPHardwareDataType")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Hardware UUID") {
					parts := strings.Split(line, ": ")
					if len(parts) == 2 {
						ids["hardware_uuid"] = strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get macOS identifiers")
	}
	return ids, nil
}

func getMacHardwareInfo() map[string]string {
	info := make(map[string]string)
	cmd := exec.Command("sysctl", "-n", "hw.model")
	if output, err := cmd.Output(); err == nil {
		info["model"] = strings.TrimSpace(string(output))
	}
	cmd = exec.Command("system_profiler", "SPHardwareDataType")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Chip") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					info["cpu"] = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Memory") {
				parts := strings.Split(line, ": ")
				if len(parts) == 2 {
					info["memory"] = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return info
}

func getLinuxIdentifiers() (map[string]string, error) {
	ids := make(map[string]string)
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		ids["dmi_uuid"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		ids["machine_id"] = strings.TrimSpace(string(data))
	}
	if output, err := exec.Command("hostid").Output(); err == nil {
		ids["host_id"] = strings.TrimSpace(string(output))
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("failed to get Linux identifiers")
	}
	return ids, nil
}

func getLinuxHardwareInfo() map[string]string {
	info := make(map[string]string)
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		info["manufacturer"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		info["model"] = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					info["cpu"] = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal") {
				parts := strings.Fields(line)
				if len(parts) == 3 {
					info["memory"] = fmt.Sprintf("%s %s", parts[1], parts[2])
				}
			}
		}
	}
	return info
}

func GetDeviceFingerPrint() (string, error) {
	deviceInfo, err := GetDeviceInfo()
	if err != nil {
		return "", fmt.Errorf("Error getting device info: %v\n", err)
	}
	return deviceInfo.Fingerprint, nil
}
