package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ANSI color codes
const (
	Off     = "\033[0m"
	Black   = "\033[0;30m"
	Red     = "\033[0;31m"
	Green   = "\033[0;32m"
	Yellow  = "\033[0;33m"
	Blue    = "\033[0;34m"
	Purple  = "\033[0;35m"
	Cyan    = "\033[0;36m"
	White   = "\033[0;37m"
	BBlack  = "\033[1;30m"
	BRed    = "\033[1;31m"
	BGreen  = "\033[1;32m"
	BYellow = "\033[1;33m"
	BBlue   = "\033[1;34m"
	BPurple = "\033[1;35m"
	BCyan   = "\033[1;36m"
	BWhite  = "\033[1;37m"
	UWhite  = "\033[4;37m"
	ANSWER  = "\t\t\t\t\t" // Tab for answers
)

// Global variables
var (
	debug              bool
	deviceID           string
	deviceModel        string
	deviceManufacturer string
)

// debugLog outputs debug information if debug mode is enabled
func debugLog(format string, a ...interface{}) {
	if debug {
		fmt.Fprintf(os.Stderr, BCyan+"[DEBUG] "+fmt.Sprintf(format, a...)+Off+"\n")
	}
}

// runCommand executes a command and returns its output
func runCommand(name string, args ...string) (string, error) {
	if debug {
		start := time.Now()
		cmd := exec.Command(name, args...)
		output, err := cmd.CombinedOutput()
		duration := time.Since(start)
		debugLog("Command '%s %s' took %s", name, strings.Join(args, " "), duration)
		return string(output), err
	}

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// adbCommand executes an adb command for the selected device
func adbCommand(args ...string) (string, error) {
	adbArgs := append([]string{"-s", deviceID}, args...)
	if debug {
		return runCommand("adb", adbArgs...)
	}

	cmd := exec.Command("adb", adbArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// printUsage displays help information
func printUsage() {
	fmt.Println("Usage: android-mgt [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -c, --check          Check if there is a Burp Suite Pro System CA on the device.")
	fmt.Println("  -s, --save-certs     Extract and save all certificate authorities from the device.")
	fmt.Println("  -p, --proxy [IP:PORT|auto|remove]")
	fmt.Println("                       - [IP:PORT]  Set a specific proxy address (e.g., 192.168.1.100:8080).")
	fmt.Println("                       - auto       Automatically detect local IPs and allow selection.")
	fmt.Println("                       - remove     Remove any existing proxy settings.")
	fmt.Println("                       - show       Display the current proxy settings.")
	fmt.Println("  -r, --root [yes|no]  Enable or disable full root on Genymotion. If no option is provided,")
	fmt.Println("                       an interactive prompt appears if the device isn't already rooted.")
	fmt.Println("  -d, --delete         Remove the Burp Suite CA from the device.")
	fmt.Println("  -h, --help           Show this help message and exit.")
	fmt.Println("  --debug              Enable debug mode.")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  This tool retrieves device information, extracts the Burp Suite certificate authority (CA)")
	fmt.Println("  from the device, compares its fingerprint with an exported certificate, and provides an option")
	fmt.Println("  to install/update the CA in /system/etc/security/cacerts. If using Genymotion, it can enable")
	fmt.Println("  full root by setting persist.sys.root_access=3. Additionally, it allows setting a proxy for")
	fmt.Println("  network traffic inspection using Burp Suite, and can remove the Burp Suite CA if needed.")
	fmt.Println()
}

// printMissingDERInstructions displays instructions for creating a DER file
func printMissingDERInstructions() {
	pwd, _ := os.Getwd()
	fmt.Printf("%s[-] No DER file named 'cacert.der' found in the current directory: %s%s\n", BRed, pwd, Off)
	fmt.Printf("%s[i] To create it, follow these steps:%s\n", BBlue, Off)
	fmt.Printf("%s    1. Open Burp Suite -> Proxy -> Proxy settings%s\n", BBlue, Off)
	fmt.Printf("%s    2. Click 'Import / Export CA Certificate' -> Select 'Export Certificate in DER format'%s\n", BBlue, Off)
	fmt.Printf("%s    3. Save it as 'cacert.der' in this directory.%s\n", BBlue, Off)
}

// detectOS returns the current operating system
func detectOS() string {
	switch runtime.GOOS {
	case "linux":
		return "Linux"
	case "darwin":
		return "Mac"
	default:
		return "Other"
	}
}

// installADBForOS installs adb for the current OS
func installADBForOS(osType string) error {
	if osType == "Linux" {
		// Check if apt is available
		_, err := exec.LookPath("apt")
		if err == nil {
			fmt.Printf("%s[*] Installing adb via 'sudo apt install android-platform-tools'...%s\n", BYellow, Off)
			cmd := exec.Command("sudo", "apt", "update")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				return err
			}

			cmd = exec.Command("sudo", "apt", "install", "-y", "android-platform-tools")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
		return fmt.Errorf("'apt' not found; please install adb manually for your Linux distribution")
	} else if osType == "Mac" {
		// Check if brew is available
		_, err := exec.LookPath("brew")
		if err == nil {
			fmt.Printf("%s[*] Installing adb via 'brew install android-platform-tools'...%s\n", BYellow, Off)
			cmd := exec.Command("brew", "install", "android-platform-tools")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
		return fmt.Errorf("Homebrew not found; please install Homebrew or adb manually")
	}
	return fmt.Errorf("Unsupported OS. Please install adb manually")
}

// checkADBInstalled checks if adb is installed and offers to install it
func checkADBInstalled() bool {
	_, err := exec.LookPath("adb")
	if err != nil {
		fmt.Printf("%s[-] adb not found on your system.%s\n", BRed, Off)
		fmt.Print("Do you want to install it now? [Y/n] ")
		reader := bufio.NewReader(os.Stdin)
		reply, _ := reader.ReadString('\n')
		reply = strings.TrimSpace(reply)

		if reply == "" || strings.ToLower(reply)[0] == 'y' {
			osType := detectOS()
			err = installADBForOS(osType)
			if err != nil {
				fmt.Printf("%s[-] Error installing adb: %v%s\n", BRed, err, Off)
				return false
			}
			return true
		}
		fmt.Printf("%s[*] Exiting. You must have 'adb' installed to continue.%s\n", BYellow, Off)
		return false
	}
	return true
}

// selectDeviceOrFail selects a device or fails if none are available
func selectDeviceOrFail() bool {
	output, err := exec.Command("adb", "devices").Output()
	if err != nil {
		fmt.Printf("%s[-] Error running adb devices: %v%s\n", BRed, err, Off)
		return false
	}

	lines := strings.Split(string(output), "\n")
	var devices []string

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasSuffix(line, "\tdevice") {
			devices = append(devices, strings.Split(line, "\t")[0])
		}
	}

	if len(devices) == 0 {
		fmt.Printf("%s[-] No online device found. Offline or no devices connected.%s\n", BRed, Off)
		return false
	}

	if len(devices) == 1 {
		deviceID = devices[0]
		fmt.Printf("%s[+] Exactly one device found: %s%s\n", BGreen, deviceID, Off)
		return true
	}

	fmt.Printf("%s[!] Multiple online devices detected. Please select one:%s\n", BYellow, Off)
	for i, device := range devices {
		fmt.Printf("[%d] %s\n", i+1, device)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter selection: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		index, err := strconv.Atoi(input)
		if err != nil || index < 1 || index > len(devices) {
			fmt.Printf("%sInvalid selection.%s\n", BRed, Off)
			continue
		}

		deviceID = devices[index-1]
		fmt.Printf("%s[+] Using device: %s%s\n", BGreen, deviceID, Off)
		return true
	}
}

// getDeviceInfo retrieves information about the device
func getDeviceInfo() {
	// Get Android SDK version
	sdkVersion, _ := adbCommand("shell", "getprop", "ro.build.version.sdk")
	sdkVersion = strings.TrimSpace(sdkVersion)

	// Determine Android code name
	var codeName string
	sdkNum, _ := strconv.Atoi(sdkVersion)
	switch {
	case sdkNum >= 14 && sdkNum <= 15:
		codeName = "Ice Cream Sandwich"
	case sdkNum >= 16 && sdkNum <= 18:
		codeName = "Jelly Bean"
	case sdkNum >= 19 && sdkNum <= 20:
		codeName = "KitKat"
	case sdkNum >= 21 && sdkNum <= 22:
		codeName = "Lollipop"
	case sdkNum == 23:
		codeName = "Marshmallow"
	case sdkNum >= 24 && sdkNum <= 25:
		codeName = "Nougat"
	case sdkNum >= 26 && sdkNum <= 27:
		codeName = "Oreo"
	case sdkNum == 28:
		codeName = "Pie"
	case sdkNum == 29:
		codeName = "Android 10"
	case sdkNum == 30:
		codeName = "Android 11"
	case sdkNum == 31:
		codeName = "Android 12"
	case sdkNum == 32:
		codeName = "Android 12L"
	case sdkNum == 33:
		codeName = "Android 13"
	default:
		codeName = "Unknown"
	}

	// Get other device properties
	androidVersion, _ := adbCommand("shell", "getprop", "ro.build.version.release")
	androidVersion = strings.TrimSpace(androidVersion)

	androidCodename, _ := adbCommand("shell", "getprop", "ro.build.version.codename")
	androidCodename = strings.TrimSpace(androidCodename)

	deviceManufacturer, _ = adbCommand("shell", "getprop", "ro.product.manufacturer")
	deviceManufacturer = strings.TrimSpace(deviceManufacturer)

	deviceModel, _ = adbCommand("shell", "getprop", "ro.product.model")
	deviceModel = strings.TrimSpace(deviceModel)

	deviceImei, _ := adbCommand("shell", "getprop", "persist.gsm.imei")
	deviceImei = strings.TrimSpace(deviceImei)

	deviceSerial, _ := adbCommand("get-serialno")
	deviceSerial = strings.TrimSpace(deviceSerial)

	deviceName, _ := adbCommand("shell", "getprop", "ro.product.name")
	deviceName = strings.TrimSpace(deviceName)

	deviceBuildID, _ := adbCommand("shell", "getprop", "ro.build.id")
	deviceBuildID = strings.TrimSpace(deviceBuildID)

	deviceBuildFingerprint, _ := adbCommand("shell", "getprop", "ro.build.fingerprint")
	deviceBuildFingerprint = strings.TrimSpace(deviceBuildFingerprint)

	// Print device information
	fmt.Printf("Device model: %s%s%s\n", Yellow, deviceModel, Off)
	fmt.Printf("Device manufacturer: %s%s%s\n", Yellow, deviceManufacturer, Off)

	// Check if device ID is all zeros
	allZeros := true
	for _, c := range deviceImei {
		if c != '0' {
			allZeros = false
			break
		}
	}

	if allZeros {
		fmt.Printf("Device ID: %s%s%s\n", BRed, deviceImei, Off)
	} else {
		fmt.Printf("Device ID: %s%s%s\n", Yellow, deviceImei, Off)
	}

	fmt.Printf("Device serial number: %s%s%s\n", Yellow, deviceSerial, Off)
	fmt.Printf("Device name: %s%s%s\n", Yellow, deviceName, Off)
	fmt.Printf("Device build ID: %s%s%s\n", Yellow, deviceBuildID, Off)
	fmt.Printf("Device build fingerprint: %s%s%s\n", Yellow, deviceBuildFingerprint, Off)
	fmt.Printf("Android SDK version: %s%s%s\n", Yellow, sdkVersion, Off)
	fmt.Printf("Android version code name: %s%s%s\n", Yellow, codeName, Off)
	fmt.Printf("Android Version: %s%s (%s)%s\n", Yellow, androidVersion, androidCodename, Off)
}

// checkRooted checks if the device is rooted (returns true if rooted)
func checkRooted(printStatus bool) bool {
	debugLog("Checking root status...")

	output, err := adbCommand("shell", "id")
	if err != nil {
		debugLog("Error checking root status: %v", err)
		return false
	}

	debugLog("Root check returned: %s", output)
	isRooted := strings.Contains(output, "uid=0")

	if printStatus {
		if isRooted {
			fmt.Printf("Device root status: %sRooted%s\n", BGreen, Off)
		} else {
			fmt.Printf("Device root status: %sNot Rooted%s\n", BRed, Off)
		}
	}

	return isRooted
}

// pullAllCerts extracts all certificates from the device
func pullAllCerts() {
	// Create cacerts directory if it doesn't exist
	err := os.MkdirAll("cacerts", 0755)
	if err != nil {
		fmt.Printf("%s[-] Failed to create cacerts directory: %v%s\n", BRed, err, Off)
		return
	}

	_, err = adbCommand("pull", "/system/etc/security/cacerts/", "./cacerts")
	if err != nil {
		fmt.Printf("%s[-] Unable to extract System CAs from device: %v%s\n", BRed, err, Off)
		return
	}

	fmt.Printf("%s[+]%s Successfully extracted System CAs to \"./cacerts\".\n", BGreen, Off)
}

// enableGenymotionRoot enables root on Genymotion devices
func enableGenymotionRoot() bool {
	fmt.Printf("%s[*] Attempting to enable full root on Genymotion (persist.sys.root_access=3)...%s\n", BYellow, Off)

	_, err := adbCommand("root")
	if err != nil {
		return false
	}

	_, err = adbCommand("wait-for-device")
	if err != nil {
		return false
	}

	_, err = adbCommand("shell", "setprop", "persist.sys.root_access", "3")
	if err != nil {
		return false
	}

	_, err = adbCommand("root")
	if err != nil {
		return false
	}

	_, err = adbCommand("wait-for-device")
	if err != nil {
		return false
	}

	return true
}

// disableGenymotionRoot disables root on Genymotion devices
func disableGenymotionRoot() {
	rootAccess, _ := adbCommand("shell", "getprop", "persist.sys.root_access")
	rootAccess = strings.TrimSpace(rootAccess)

	if rootAccess == "0" {
		fmt.Printf("%s[*] Root access is already disabled.%s\n", BYellow, Off)
		return
	}

	fmt.Printf("%s[*] Disabling root access...%s\n", BYellow, Off)
	_, err := adbCommand("shell", "setprop", "persist.sys.root_access", "0")
	if err != nil {
		fmt.Printf("%s[-] Failed to disable root access: %v%s\n", BRed, err, Off)
		return
	}

	fmt.Printf("%s[+] Root access disabled.%s\n", BGreen, Off)
	_, _ = adbCommand("reboot")
}

// remountSystem attempts to remount the system partition as read-write
func remountSystem(printStatus bool) bool {
	debugLog("Attempting to remount system partition...")
	var success bool = false

	// Approach 1: Direct root remount - single command with proper quoting
	output, err := adbCommand("shell", "su -c 'mount -o rw,remount /'")
	if err == nil && !strings.Contains(output, "failed") {
		debugLog("Successfully remounted / as rw")
		if printStatus {
			fmt.Printf("%s[+]%s Remounted '/' read-write.\n", BGreen, Off)
		}
		success = true
	} else {
		debugLog("Failed to remount / directly: %v", err)

		// Approach 2: System remount
		output, err = adbCommand("shell", "su -c 'mount -o rw,remount /system'")
		if err == nil && !strings.Contains(output, "failed") {
			debugLog("Successfully remounted /system as rw")
			if printStatus {
				fmt.Printf("%s[+]%s Remounted '/system' read-write.\n", BGreen, Off)
			}
			success = true
		} else {
			debugLog("Failed to remount /system directly: %v", err)
		}
	}

	// Check mount status after remount attempts
	output, _ = adbCommand("shell", "mount | grep -E '(/system|/) '")
	debugLog("Current mount status:\n%s", output)

	return success
}

// directMountAndCopy moves a certificate to the system certificate store
func directMountAndCopy(certName string) bool {
	debugLog("Starting directMountAndCopy with cert_name: %s", certName)

	// Check if the source file exists
	output, err := adbCommand("shell", "test", "-f", "/sdcard/"+certName, "&&", "echo", "exists")
	if err != nil || !strings.Contains(output, "exists") {
		debugLog("Source file /sdcard/%s does not exist!", certName)
		fmt.Printf("%s[-] Source certificate file not found on device%s\n", BRed, Off)
		return false
	}

	// Try to remount with more verbose output
	fmt.Printf("%s[*] Attempting direct remount of '/' or '/system'...%s\n", BYellow, Off)

	if !remountSystem(true) {
		fmt.Printf("%s[-] Failed to remount system partition read-write.%s\n", BRed, Off)
		return false
	}

	// Try the move operation
	fmt.Printf("%s[*] Attempting to move certificate...%s\n", BYellow, Off)
	_, err = adbCommand("shell", "su", "-c", fmt.Sprintf("mv /sdcard/%s /system/etc/security/cacerts/%s", certName, certName))
	if err != nil {
		fmt.Printf("%s[-] Failed to move certificate to /system/etc/security/cacerts/.%s\n", BRed, Off)
		return false
	}

	// Verify move success
	output, err = adbCommand("shell", "su", "-c", fmt.Sprintf("test -f /system/etc/security/cacerts/%s && echo exists", certName))
	if err != nil || !strings.Contains(output, "exists") {
		debugLog("File is missing after 'mv' command.")
		fmt.Printf("%s[-] Certificate move succeeded, but file isn't found in the destination.%s\n", BRed, Off)
		return false
	}

	fmt.Printf("%s[+] Certificate moved successfully.%s\n", BGreen, Off)

	// Set permissions and ownership
	_, _ = adbCommand("shell", "su", "-c", fmt.Sprintf("chmod 644 /system/etc/security/cacerts/%s", certName))
	_, _ = adbCommand("shell", "su", "-c", fmt.Sprintf("chown root:root /system/etc/security/cacerts/%s", certName))
	_, _ = adbCommand("shell", "su", "-c", fmt.Sprintf("chcon u:object_r:system_file:s0 /system/etc/security/cacerts/%s", certName))

	return true
}

// pushCertificate installs a certificate on the device
func pushCertificate() bool {
	derFile := "cacert.der"

	// Check root
	if !checkRooted(false) {
		fmt.Printf("%s[!] Attempting to enable root now...%s\n", BYellow, Off)
		if !enableGenymotionRoot() {
			// Root enable attempt failed
			if !checkRooted(false) {
				fmt.Printf("%s[-] Unable to verify or enable root on %s %s.%s\n", BRed, deviceManufacturer, deviceModel, Off)
				fmt.Printf("%s[-] Couldn't install the certificate on the device.%s\n", BRed, Off)
				return false
			}
		}

		// Double-check root after enabling
		if !checkRooted(false) {
			fmt.Printf("%s[-] Unable to verify or enable root on %s %s.%s\n", BRed, deviceManufacturer, deviceModel, Off)
			fmt.Printf("%s[-] Couldn't install the certificate on the device.%s\n", BRed, Off)
			return false
		}
	}

	// Check if DER exists
	if _, err := os.Stat(derFile); os.IsNotExist(err) {
		printMissingDERInstructions()
		return false
	}

	// Convert DER to PEM
	fmt.Printf("%s[+]%s Converting certificate from DER to PEM...\n", BGreen, Off)
	cmd := exec.Command("openssl", "x509", "-inform", "DER", "-in", derFile, "-out", "cacert.pem")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("%s[-] OpenSSL conversion from DER to PEM failed: %v%s\n", BRed, err, Off)
		return false
	}

	// Get certificate hash
	cmd = exec.Command("openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", "cacert.pem")
	hashOutput, err := cmd.Output()
	if err != nil {
		fmt.Printf("%s[-] Failed to get certificate hash: %v%s\n", BRed, err, Off)
		return false
	}
	hash := strings.Split(string(hashOutput), "\n")[0]

	// Rename certificate
	certName := hash + ".0"
	fmt.Printf("%s[+]%s Renaming 'cacert.pem' to '%s'...\n", BGreen, Off, certName)
	err = os.Rename("cacert.pem", certName)
	if err != nil {
		fmt.Printf("%s[-] Failed to rename certificate: %v%s\n", BRed, err, Off)
		return false
	}

	// Push certificate to device
	fmt.Printf("%s[+]%s Pushing certificate %s to /sdcard/%s\n", BGreen, Off, certName, certName)
	_, err = adbCommand("push", certName, "/sdcard/"+certName)
	if err != nil {
		fmt.Printf("%s[-] Failed to push %s to /sdcard/: %v%s\n", BRed, certName, err, Off)
		return false
	}

	// Install certificate using direct mount
	fmt.Printf("%s[*] Trying direct mount method...%s\n", BYellow, Off)
	if directMountAndCopy(certName) {
		fmt.Printf("%s[+]%s Direct mount method succeeded!\n", BGreen, Off)
	} else {
		// Fall back to tmpfs trick
		fmt.Printf("%s[!] Falling back to tmpfs trick...%s\n", BYellow, Off)
		command := fmt.Sprintf(
			"mkdir -m 700 /data/local/tmp/htk-ca-copy && "+
				"cp /system/etc/security/cacerts/* /data/local/tmp/htk-ca-copy/ && "+
				"mount -t tmpfs tmpfs /system/etc/security/cacerts && "+
				"mv /data/local/tmp/htk-ca-copy/* /system/etc/security/cacerts/ && "+
				"mv /sdcard/%s /system/etc/security/cacerts/%s && "+
				"chown root:root /system/etc/security/cacerts/* && "+
				"chmod 644 /system/etc/security/cacerts/* && "+
				"chcon u:object_r:system_file:s0 /system/etc/security/cacerts/* && "+
				"rm -r /data/local/tmp/htk-ca-copy",
			certName, certName)

		_, err = adbCommand("shell", "su", "-c", command)
		if err != nil {
			fmt.Printf("%s[-] Certificate installation failed even via tmpfs fallback: %v%s\n", BRed, err, Off)
			return false
		}
		fmt.Printf("%s[+]%s Certificate installed via tmpfs fallback!\n", BGreen, Off)
	}

	// Reboot device
	fmt.Printf("%s[*] Rebooting the device for changes to take effect...%s\n", BYellow, Off)
	_, _ = adbCommand("shell", "reboot")
	time.Sleep(5 * time.Second)
	_, _ = adbCommand("wait-for-device")
	fmt.Printf("%s[+]%s%s Certificate successfully installed!%s\n", BGreen, BYellow, Off)
	return true
}

// checkBurpCert checks if a Burp CA certificate is installed on the device
func checkBurpCert() {
	fmt.Println()
	fmt.Printf("%sChecking for Burp Suite CA on this device...%s\n", BWhite, Off)
	fmt.Println()

	burpSystemDer := "./cacert.der"
	burpSystemPem := "/system/etc/security/cacerts/9a5ba575.0"
	localCertFound := false
	deviceCertFound := false
	var derSHA1, derSHA256, sysSHA1, sysSHA256 string

	// Check for local DER
	if _, err := os.Stat(burpSystemDer); err == nil {
		fmt.Printf("%s[+]%s Found local DER '%s' with these fingerprints:\n", BGreen, Off, burpSystemDer)

		cmd := exec.Command("openssl", "x509", "-inform", "DER", "-in", burpSystemDer, "-noout", "-fingerprint", "-sha1")
		output, err := cmd.CombinedOutput()
		if err == nil {
			derSHA1 = strings.TrimSpace(string(output))
			fmt.Printf("   %s\n", derSHA1)
		}

		cmd = exec.Command("openssl", "x509", "-inform", "DER", "-in", burpSystemDer, "-noout", "-fingerprint", "-sha256")
		output, err = cmd.CombinedOutput()
		if err == nil {
			derSHA256 = strings.TrimSpace(string(output))
			fmt.Printf("   %s\n", derSHA256)
		}

		fmt.Println()
		localCertFound = true
	}

	// Check for device CA
	output, err := adbCommand("shell", "ls", burpSystemPem)
	if err == nil && !strings.Contains(output, "No such file") {
		fmt.Printf("%s[+]%s Burp Suite CA found on the device (%s) with fingerprints:\n", BGreen, Off, burpSystemPem)

		// Get certificate from device
		certData, err := adbCommand("shell", "cat", burpSystemPem)
		if err == nil {
			// Create temporary file
			tempFile, err := os.CreateTemp("", "burp-cert-*.pem")
			if err == nil {
				tempFile.WriteString(certData)
				tempFile.Close()

				// Get SHA1 fingerprint
				cmd := exec.Command("openssl", "x509", "-inform", "PEM", "-in", tempFile.Name(), "-noout", "-fingerprint", "-sha1")
				output, err := cmd.Output()
				if err == nil {
					sysSHA1 = strings.TrimSpace(string(output))
					fmt.Printf("   %s\n", sysSHA1)
				}

				// Get SHA256 fingerprint
				cmd = exec.Command("openssl", "x509", "-inform", "PEM", "-in", tempFile.Name(), "-noout", "-fingerprint", "-sha256")
				output, err = cmd.Output()
				if err == nil {
					sysSHA256 = strings.TrimSpace(string(output))
					fmt.Printf("   %s\n", sysSHA256)
				}

				// Remove temporary file
				os.Remove(tempFile.Name())
			}
		}

		fmt.Println()
		deviceCertFound = true
	}

	// Compare or offer to install
	if localCertFound && deviceCertFound {
		if derSHA1 == sysSHA1 && derSHA1 != "" {
			fmt.Printf("%s[+]%s%s The fingerprints match! No need to reinstall.%s\n", BGreen, BYellow, Off)
			fmt.Print("Unnecessary, but reinstall anyway? [N/y] ")
			reader := bufio.NewReader(os.Stdin)
			reply, _ := reader.ReadString('\n')
			reply = strings.TrimSpace(reply)

			if strings.ToLower(reply) == "y" {
				pushCertificate()
			} else {
				fmt.Printf("%s[+]%s Have a nice day.\n", BYellow, Off)
			}
		} else {
			fmt.Printf("%s[-] The fingerprints do not match.%s\n", BRed, Off)
			fmt.Print("Install the local DER certificate now? [Y/n] ")
			reader := bufio.NewReader(os.Stdin)
			reply, _ := reader.ReadString('\n')
			reply = strings.TrimSpace(reply)

			if reply == "" || strings.ToLower(reply)[0] == 'y' {
				pushCertificate()
			}
		}
	} else if localCertFound && !deviceCertFound {
		fmt.Printf("%s[-] No Burp Suite CA found in system store.%s\n", BRed, Off)
		fmt.Print("Install the local certificate? [Y/n] ")
		reader := bufio.NewReader(os.Stdin)
		reply, _ := reader.ReadString('\n')
		reply = strings.TrimSpace(reply)

		if reply == "" || strings.ToLower(reply)[0] == 'y' {
			pushCertificate()
		}
	} else if !localCertFound && deviceCertFound {
		fmt.Printf("%s[-] No local 'cacert.der' found for comparison.%s\n", BRed, Off)
		printMissingDERInstructions()
	} else {
		fmt.Printf("%s[-] No Burp Suite CA found locally or on the device.%s\n", BRed, Off)
		printMissingDERInstructions()
	}
}

// deleteBurpCert removes a Burp CA certificate from the device
func deleteBurpCert() {
	fmt.Println()
	fmt.Printf("%sChecking for Burp Suite CA on this device...%s\n", BWhite, Off)
	fmt.Println()

	output, err := adbCommand("shell", "ls", "/system/etc/security/cacerts/9a5ba575.0")
	if err != nil || strings.Contains(output, "No such file") {
		fmt.Printf("%s[-] Burp Suite CA not found on the device. Nothing to delete.%s\n", BRed, Off)
		return
	}

	fmt.Printf("%s[+]%s Burp Suite CA found. Preparing to delete...\n", BGreen, Off)

	if !checkRooted(false) {
		fmt.Printf("%s[-] Device is not rooted. Cannot delete system CA.%s\n", BRed, Off)
		return
	}

	fmt.Printf("%s[*] Attempting to remount system partition...%s\n", BYellow, Off)
	if !remountSystem(false) {
		fmt.Printf("%s[-] Failed to remount system partition read-write. Cannot delete CA.%s\n", BRed, Off)
		return
	}

	fmt.Printf("%s[*] Deleting Burp Suite CA...%s\n", BYellow, Off)
	_, err = adbCommand("shell", "su", "-c", "rm -f /system/etc/security/cacerts/9a5ba575.0")
	if err != nil {
		fmt.Printf("%s[-] Failed to delete Burp Suite CA: %v%s\n", BRed, err, Off)
		return
	}

	fmt.Printf("%s[+] Successfully deleted Burp Suite CA.%s\n", BGreen, Off)

	fmt.Printf("%s[*] Rebooting the device to apply changes...%s\n", BYellow, Off)
	_, _ = adbCommand("shell", "reboot")
	time.Sleep(5 * time.Second)
	_, _ = adbCommand("wait-for-device")
	fmt.Printf("%s[+] Device rebooted. Burp Suite CA should be removed.%s\n", BGreen, Off)
}

// getLocalIPs gets available local IP addresses
func getLocalIPs() (string, string) {
	osType := detectOS()
	var ips []string

	if osType == "Mac" {
		// macOS: get non-loopback IPs
		cmd := exec.Command("ifconfig")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			re := regexp.MustCompile(`inet\s+(\d+\.\d+\.\d+\.\d+)`)

			for _, line := range lines {
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 && matches[1] != "127.0.0.1" {
					ips = append(ips, matches[1])
				}
			}
		}
	} else if osType == "Linux" {
		// Linux: get non-loopback IPs
		cmd := exec.Command("hostname", "-I")
		output, err := cmd.Output()
		if err == nil {
			for _, ip := range strings.Fields(string(output)) {
				if ip != "" {
					ips = append(ips, ip)
				}
			}
		}
	} else {
		fmt.Printf("%s[-] Unsupported OS for automatic IP detection.%s\n", BRed, Off)
		return "", ""
	}

	// Add loopback address
	ips = append(ips, "127.0.0.1")

	// Display available IPs
	fmt.Printf("%s[!] Available IP Addresses:%s\n", BYellow, Off)
	for i, ip := range ips {
		fmt.Printf("%s[%d]%s %s\n", BGreen, i+1, Off, ip)
	}

	// Get user choice
	reader := bufio.NewReader(os.Stdin)
	var selectedIP string

	for {
		fmt.Print("Choose an IP address (default: 127.0.0.1): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "" {
			selectedIP = "127.0.0.1"
			break
		}

		index, err := strconv.Atoi(choice)
		if err == nil && index > 0 && index <= len(ips) {
			selectedIP = ips[index-1]
			break
		}

		fmt.Printf("%sInvalid choice. Please select a number from the list.%s\n", BRed, Off)
	}

	// Get port
	fmt.Print("Enter proxy port (default: 8080): ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)

	if portStr == "" {
		portStr = "8080"
	}

	proxyAddress := selectedIP + ":" + portStr
	return selectedIP, proxyAddress
}

// setProxy sets or displays proxy settings on the device
func setProxy(proxy string) {
	if proxy == "" || proxy == "show" {
		// Display current proxy
		output, err := adbCommand("shell", "settings", "get", "global", "http_proxy")
		if err != nil || strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" || strings.TrimSpace(output) == ":0" {
			fmt.Printf("%s[*] No proxy is currently set on the device.%s\n", BYellow, Off)
		} else {
			fmt.Printf("%s[+] Current proxy setting: %s%s\n", BGreen, strings.TrimSpace(output), Off)
		}
	} else if proxy == "remove" {
		fmt.Printf("%s[*] Removing proxy settings from the device...%s\n", BYellow, Off)
		_, err := adbCommand("shell", "settings", "put", "global", "http_proxy", ":0")
		if err != nil {
			fmt.Printf("%s[-] Failed to remove proxy settings: %v%s\n", BRed, err, Off)
			return
		}
		fmt.Printf("%s[+] Proxy settings removed.%s\n", BGreen, Off)
	} else if proxy == "auto" {
		// Auto-detect IP / Port
		_, proxyAddress := getLocalIPs()
		if proxyAddress == "" {
			return
		}

		fmt.Printf("%s[*] Setting proxy to %s...%s\n", BYellow, proxyAddress, Off)
		_, err := adbCommand("shell", "settings", "put", "global", "http_proxy", proxyAddress)
		if err != nil {
			fmt.Printf("%s[-] Failed to set proxy: %v%s\n", BRed, err, Off)
			return
		}
		fmt.Printf("%s[+] Proxy set to %s%s\n", BGreen, proxyAddress, Off)
	} else {
		fmt.Printf("%s[*] Setting proxy to %s...%s\n", BYellow, proxy, Off)
		_, err := adbCommand("shell", "settings", "put", "global", "http_proxy", proxy)
		if err != nil {
			fmt.Printf("%s[-] Failed to set proxy: %v%s\n", BRed, err, Off)
			return
		}
		fmt.Printf("%s[+] Proxy set to %s%s\n", BGreen, proxy, Off)
	}
}

func main() {
	// Define command-line flags
	checkFlag := flag.Bool("c", false, "Check for Burp Suite Pro System CA on the device")
	checkLongFlag := flag.Bool("check", false, "Check for Burp Suite Pro System CA on the device")

	saveCertsFlag := flag.Bool("s", false, "Extract and save all certificate authorities from the device")
	saveCertsLongFlag := flag.Bool("save-certs", false, "Extract and save all certificate authorities from the device")

	proxyFlag := flag.String("p", "", "Set a specific proxy address (e.g., 192.168.1.100:8080)")
	proxyLongFlag := flag.String("proxy", "", "Set a specific proxy address (e.g., 192.168.1.100:8080)")

	rootFlag := flag.String("r", "", "Enable or disable full root on Genymotion")
	rootLongFlag := flag.String("root", "", "Enable or disable full root on Genymotion")

	deleteFlag := flag.Bool("d", false, "Remove the Burp Suite CA from the device")
	deleteLongFlag := flag.Bool("delete", false, "Remove the Burp Suite CA from the device")

	helpFlag := flag.Bool("h", false, "Show help message and exit")
	helpLongFlag := flag.Bool("help", false, "Show help message and exit")

	debugFlag := flag.Bool("debug", false, "Enable debug mode")

	// Parse flags
	flag.Parse()

	// Combine short and long flags
	check := *checkFlag || *checkLongFlag
	saveCerts := *saveCertsFlag || *saveCertsLongFlag
	proxy := *proxyFlag
	if *proxyLongFlag != "" {
		proxy = *proxyLongFlag
	}
	root := *rootFlag
	if *rootLongFlag != "" {
		root = *rootLongFlag
	}
	deleteCA := *deleteFlag || *deleteLongFlag
	help := *helpFlag || *helpLongFlag
	debug = *debugFlag

	// Print help and exit if requested
	if help {
		printUsage()
		return
	}

	// Check if adb is installed
	if !checkADBInstalled() {
		return
	}

	// Select device
	if !selectDeviceOrFail() {
		return
	}

	// Get device info
	getDeviceInfo()

	// Check root status
	checkRooted(true)

	// Process actions based on flags
	if check {
		checkBurpCert()
	}

	if saveCerts {
		pullAllCerts()
	}

	// Handle proxy flag - fixed logic
	if proxy != "" || *proxyFlag != "" || *proxyLongFlag != "" {
		setProxy(proxy)
	}

	// Handle root flag - fixed logic
	if root != "" || *rootFlag != "" || *rootLongFlag != "" {
		if root == "yes" {
			if checkRooted(false) {
				fmt.Printf("%s[+] Device is already rooted. No need to enable root.%s\n", BGreen, Off)
			} else {
				enableGenymotionRoot()
			}
		} else if root == "no" {
			disableGenymotionRoot()
		} else {
			// If no arg, prompt if device is not rooted
			if checkRooted(false) {
				fmt.Printf("%s[+] Device is already rooted. No need to enable root.%s\n", BGreen, Off)
			} else {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Enable full root on Genymotion? (Y/n): ")
				reply, _ := reader.ReadString('\n')
				reply = strings.TrimSpace(reply)

				if reply == "" || strings.ToLower(reply)[0] == 'y' {
					enableGenymotionRoot()
				} else {
					fmt.Printf("%s[+] Skipping Genymotion root changes.%s\n", BYellow, Off)
				}
			}
		}
	}

	if deleteCA {
		deleteBurpCert()
	}

	// If no flags were specified, show help
	if !check && !saveCerts && proxy == "" && *proxyFlag == "" && *proxyLongFlag == "" &&
		root == "" && *rootFlag == "" && *rootLongFlag == "" && !deleteCA {
		//printUsage()
	}
}
