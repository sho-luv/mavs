#!/bin/bash

###############################################################################
#  Debug / Error Trap
###############################################################################
DEBUG=0

# Initial argument parsing to detect --debug before other options
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG=1
            set -x  # Enable bash debugging
            shift
            ;;
        *)
            # Stop parsing here; remaining args handled later
            break
            ;;
    esac
done

# Print line number on any error
trap 'echo "Error on line $LINENO"' ERR

###############################################################################
#  Colors
###############################################################################
Off='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'
Red='\033[0;31m'
Green='\033[0;32m'
Yellow='\033[0;33m'
Blue='\033[0;34m'
Purple='\033[0;35m'
Cyan='\033[0;36m'
White='\033[0;37m'

# Bold
BBlack='\033[1;30m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BBlue='\033[1;34m'
BPurple='\033[1;35m'
BCyan='\033[1;36m'
BWhite='\033[1;37m'

# Underline
UWhite='\033[4;37m'

###############################################################################
#  Debug Logging and Timing
###############################################################################
debug_log() {
    [[ $DEBUG -eq 1 ]] && echo -e "${BCyan}[DEBUG] $*${Off}" >&2
}

time_cmd() {
    if [[ $DEBUG -eq 1 ]]; then
        local start end duration
        start=$(date +%s%N)
        "$@"
        end=$(date +%s%N)
        duration=$(( (end - start) / 1000000 ))
        debug_log "Command '$*' took ${duration}ms"
    else
        "$@"
    fi
}

adb_command() {
    if [[ $DEBUG -eq 1 ]]; then
        adb -s "$DEVICE_ID" "$@"
    else
        adb -s "$DEVICE_ID" "$@" 2>/dev/null
    fi
}

###############################################################################
#  Usage
###############################################################################
usage() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -c, --check          Check if there is a Burp Suite Pro System CA on the device."
    echo "  -s, --save-certs     Extract and save all certificate authorities from the device."
    echo "  -p, --proxy [IP:PORT|auto|remove]"
    echo "                       - [IP:PORT]  Set a specific proxy address (e.g., 192.168.1.100:8080)."
    echo "                       - auto       Automatically detect local IPs and allow selection."
    echo "                       - remove     Remove any existing proxy settings."
    echo "                       - (no arg)   Display the current proxy settings."
    echo "  -r, --root [yes|no]  Enable or disable full root on Genymotion. If no option is provided,"
    echo "                       an interactive prompt appears if the device isn't already rooted."
    echo "  -d, --delete         Remove the Burp Suite CA from the device."
    echo "  -h, --help           Show this help message and exit."
    echo
    echo "Description:"
    echo "  This script retrieves device information, extracts the Burp Suite certificate authority (CA)"
    echo "  from the device, compares its fingerprint with an exported certificate, and provides an option"
    echo "  to install/update the CA in /system/etc/security/cacerts. If using Genymotion, it can enable"
    echo "  full root by setting persist.sys.root_access=3. Additionally, it allows setting a proxy for"
    echo "  network traffic inspection using Burp Suite, and can remove the Burp Suite CA if needed."
    echo
    exit 1
}
# If -h or --help is used, print usage and exit immediately
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

###############################################################################
#  Print Missing DER Instructions
###############################################################################
print_missing_der_instructions() {
    echo -e "${BRed}[-] No DER file named 'cacert.der' found in the current directory: $(pwd)${Off}"
    echo -e "${BBlue}[i] To create it, follow these steps:${Off}"
    echo -e "${BBlue}    1. Open Burp Suite -> Proxy -> Proxy settings${Off}"
    echo -e "${BBlue}    2. Click 'Import / Export CA Certificate' -> Select 'Export Certificate in DER format'${Off}"
    echo -e "${BBlue}    3. Save it as 'cacert.der' in this directory.${Off}"
}

###############################################################################
#  Detect OS
###############################################################################
detect_os() {
    local uname_out
    uname_out=$(uname -s 2>/dev/null || echo "Unknown")

    case "$uname_out" in
        Linux*)  echo "Linux" ;;
        Darwin*) echo "Mac"   ;;
        *)       echo "Other" ;;
    esac
}

###############################################################################
#  Install ADB for OS
###############################################################################
install_adb_for_os() {
    local current_os="$1"

    if [[ "$current_os" == "Linux" ]]; then
        if command -v apt &>/dev/null; then
            echo -e "${BYellow}[*] Installing adb via 'sudo apt install android-platform-tools'...${Off}"
            sudo apt update && sudo apt install -y android-platform-tools
        else
            echo -e "${BRed}[-] 'apt' not found; please install adb manually for your Linux distribution.${Off}"
            exit 1
        fi
    elif [[ "$current_os" == "Mac" ]]; then
        if command -v brew &>/dev/null; then
            echo -e "${BYellow}[*] Installing adb via 'brew install android-platform-tools'...${Off}"
            brew install android-platform-tools
        else
            echo -e "${BRed}[-] Homebrew not found; please install Homebrew or adb manually.${Off}"
            exit 1
        fi
    else
        echo -e "${BRed}[-] Unsupported OS. Please install adb manually.${Off}"
        exit 1
    fi
}

###############################################################################
#  check_adb_installed
###############################################################################
check_adb_installed() {
    if ! command -v adb &>/dev/null; then
        echo -e "${BRed}[-] adb not found on your system.${Off}"
        read -p "Do you want to install it now? [Y/n] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
            local this_os
            this_os=$(detect_os)
            install_adb_for_os "$this_os"
        else
            echo -e "${BYellow}[*] Exiting. You must have 'adb' installed to continue.${Off}"
            exit 1
        fi
    fi
}

###############################################################################
#  select_device_or_fail
###############################################################################
select_device_or_fail() {
    local devices_list
    devices_list=$(adb devices | awk '/\tdevice$/ {print $1}')

    if [ -z "$devices_list" ]; then
        echo -e "${BRed}[-] No online device found. Offline or no devices connected.${Off}"
        exit 1
    fi

    local device_count
    device_count=$(echo "$devices_list" | wc -l | tr -d ' ')

    if [ "$device_count" -eq 1 ]; then
        DEVICE_ID="$devices_list"
        echo -e "${BGreen}[+] Exactly one device found: $DEVICE_ID${Off}"
    else
        echo -e "${BYellow}[!] Multiple online devices detected. Please select one:${Off}"
        select chosen_device in $devices_list; do
            if [ -n "$chosen_device" ]; then
                DEVICE_ID="$chosen_device"
                echo -e "${BGreen}[+] Using device: $DEVICE_ID${Off}"
                break
            else
                echo -e "${BRed}Invalid selection.${Off}"
            fi
        done
    fi
}

###############################################################################
#  Global Vars
###############################################################################
device_model=""
device_manufacturer=""

###############################################################################
#  get_device_info
###############################################################################
get_device_info() {
    local sdk_version code_name android_version android_codename
    local device_serial device_name device_build_id device_build_fingerprint

    sdk_version=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.sdk | tr -d '\r')

    case $sdk_version in
        14|15) code_name="Ice Cream Sandwich";;
        16|17|18) code_name="Jelly Bean";;
        19|20)   code_name="KitKat";;
        21|22)   code_name="Lollipop";;
        23)      code_name="Marshmallow";;
        24|25)   code_name="Nougat";;
        26|27)   code_name="Oreo";;
        28)      code_name="Pie";;
        29)      code_name="Android 10";;
        30)      code_name="Android 11";;
        31)      code_name="Android 12";;
        32)      code_name="Android 12L";;
        33)      code_name="Android 13";;
        *)       code_name="Unknown";;
    esac

    android_version=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.release | tr -d '\r')
    android_codename=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.codename | tr -d '\r')

    device_manufacturer=$(adb -s "$DEVICE_ID" shell getprop ro.product.manufacturer | tr -d '\r')
    device_model=$(adb -s "$DEVICE_ID" shell getprop ro.product.model | tr -d '\r')
    device_id=$(adb -s "$DEVICE_ID" shell getprop persist.gsm.imei)
    device_serial=$(adb -s "$DEVICE_ID" get-serialno | tr -d '\r')
    device_name=$(adb -s "$DEVICE_ID" shell getprop ro.product.name | tr -d '\r')
    device_build_id=$(adb -s "$DEVICE_ID" shell getprop ro.build.id | tr -d '\r')
    device_build_fingerprint=$(adb -s "$DEVICE_ID" shell getprop ro.build.fingerprint | tr -d '\r')

    echo -e "Device model: ${Yellow}$device_model${Off}"
    echo -e "Device manufacturer: ${Yellow}$device_manufacturer${Off}"
    if [[ "$device_id" =~ ^0+$ ]]; then
        echo -e "Device ID: ${BRed}$device_id${Off}"  # Print in red if only zeros
    else
        echo -e "Device ID: ${Yellow}$device_id${Off}"
    fi
    echo -e "Device serial number: ${Yellow}$device_serial${Off}"
    echo -e "Device name: ${Yellow}$device_name${Off}"
    echo -e "Device build ID: ${Yellow}$device_build_id${Off}"
    echo -e "Device build fingerprint: ${Yellow}$device_build_fingerprint${Off}"
    echo -e "Android SDK version: ${Yellow}$sdk_version${Off}"
    echo -e "Android version code name: ${Yellow}$code_name${Off}"
    echo -e "Android Version: ${Yellow}${android_version} (${android_codename})${Off}"
}

###############################################################################
#  check_rooted - returns 0 if device is rooted, 1 otherwise
###############################################################################
check_rooted() {
    local print_status=${1:-false}
    debug_log "Checking root status..."
    local root_status
    root_status=$(adb -s "$DEVICE_ID" shell id 2>/dev/null)

    debug_log "Root check returned: $root_status"
    if [[ $root_status == *"uid=0"* ]]; then
        [[ "$print_status" == "true" ]] && echo -e "Device root status: ${BGreen}Rooted${Off}"
        return 0
    else
        [[ "$print_status" == "true" ]] && echo -e "Device root status: ${BRed}Not Rooted${Off}"
        return 1
    fi
}

###############################################################################
#  pull_all_certs
###############################################################################
pull_all_certs() {
    if ! adb -s "$DEVICE_ID" pull "/system/etc/security/cacerts/" ./cacerts &>/dev/null; then
        echo -e "${BRed}[-] Unable to extract System CAs from device.${Off}"
    else
        echo -e "${BGreen}[+]${Off} Successfully extracted System CAs to \"./cacerts\"."
    fi
}

###############################################################################
#  enable_genymotion_root
###############################################################################
enable_genymotion_root() {
    echo -e "${BYellow}[*] Attempting to enable full root on Genymotion (persist.sys.root_access=3)...${Off}"
    if  adb -s "$DEVICE_ID" root  &>/dev/null && \
        adb -s "$DEVICE_ID" wait-for-device    &>/dev/null && \
        adb -s "$DEVICE_ID" shell setprop persist.sys.root_access 3 &>/dev/null && \
        adb -s "$DEVICE_ID" root               &>/dev/null && \
        adb -s "$DEVICE_ID" wait-for-device; then
        #echo -e "${BGreen}[+]${Off} Genymotion root access enabled Yay!"
        return 0
    else
        return 1
    fi
}

###############################################################################
#  disable_genymotion_root (for "--root no" branch)
###############################################################################
disable_genymotion_root() {
    local root_access
    root_access=$(adb -s "$DEVICE_ID" shell getprop persist.sys.root_access)

    if [[ "$root_access" == "0" ]]; then
        echo -e "${BYellow}[*] Root access is already disabled.${Off}"
    else
        echo -e "${BYellow}[*] Disabling root access...${Off}"
        if adb -s "$DEVICE_ID" shell setprop persist.sys.root_access 0; then
            echo -e "${BGreen}[+] Root access disabled.${Off}"
            adb -s "$DEVICE_ID" reboot
        else
            echo -e "${BRed}[-] Failed to disable root access.${Off}"
        fi
    fi
}

###############################################################################
#  remount_system - Attempts to remount system partition as read-write
###############################################################################
remount_system() {
    local print_status=${1:-true}  # Whether to print status messages
    debug_log "Attempting to remount system partition..."
    local remount_success=1  # success is 0, failure is 1 so we set it to fasle  
    
    # Approach 1: Direct root remount
    if adb -s "$DEVICE_ID" shell "su -c 'mount -o rw,remount /'" 2>&1; then
        debug_log "Successfully remounted / as rw"
        [[ "$print_status" == "true" ]] && echo -e "${BGreen}[+]${Off} Remounted '/' read-write."
        remount_success=0
    else
        debug_log "Failed to remount / directly"
        
        # Approach 2: System remount if first approach failed
        if adb -s "$DEVICE_ID" shell "su -c 'mount -o rw,remount /system'" 2>&1; then
            debug_log "Successfully remounted /system as rw"
            [[ "$print_status" == "true" ]] && echo -e "${BGreen}[+]${Off} Remounted '/system' read-write."
        else
            debug_log "Failed to remount /system directly"
            remount_success=1
        fi
    fi
    
    # Check mount status after remount attempts
    debug_log "Current mount status:"
    adb -s "$DEVICE_ID" shell "mount | grep -E '(/system|/) '"
    
    return $remount_success
}

###############################################################################
#  direct_mount_and_copy
###############################################################################
direct_mount_and_copy() {
    local cert_name="$1"
    debug_log "Starting direct_mount_and_copy with cert_name: $cert_name"
    
    # First check if the source file exists
    if ! adb -s "$DEVICE_ID" shell "test -f /sdcard/${cert_name}"; then
        debug_log "Source file /sdcard/${cert_name} does not exist!"
        echo -e "${BRed}[-] Source certificate file not found on device${Off}"
        return 1
    fi
    
    # Check source file permissions
    debug_log "Checking source file permissions..."
    adb -s "$DEVICE_ID" shell "ls -l /sdcard/${cert_name}"
    
    # Try to remount with more verbose output
    echo -e "${BYellow}[*] Attempting direct remount of '/' or '/system'...${Off}"
    
    if ! remount_system; then
        echo -e "${BRed}[-] Failed to remount system partition read-write.${Off}"
        return 1
    fi
    
    # Try the move operation...
    echo -e "${BYellow}[*] Attempting to move certificate...${Off}"
    if adb -s "$DEVICE_ID" shell "su -c 'mv /sdcard/${cert_name} /system/etc/security/cacerts/${cert_name}'" &>/dev/null; then
        # Verify move success
        if adb -s "$DEVICE_ID" shell "su -c 'test -f /system/etc/security/cacerts/${cert_name}'" &>/dev/null; then
            echo -e "${BGreen}[+] Certificate moved successfully.${Off}"
            adb -s "$DEVICE_ID" shell "su -c 'chmod 644 /system/etc/security/cacerts/${cert_name}'"
            adb -s "$DEVICE_ID" shell "su -c 'chown root:root /system/etc/security/cacerts/${cert_name}'"
            adb -s "$DEVICE_ID" shell "su -c 'chcon u:object_r:system_file:s0 /system/etc/security/cacerts/${cert_name}'"
            return 0
        else
            debug_log "File is missing after 'mv' command."
            echo -e "${BRed}[-] Certificate move succeeded, but file isn't found in the destination.${Off}"
            return 1
        fi
    else
        echo -e "${BRed}[-] Failed to move certificate to /system/etc/security/cacerts/.${Off}"
        return 1
    fi
}

###############################################################################
#  push_certificate
###############################################################################
push_certificate() {
    local DER_FILE="cacert.der"

    # Check root
    if ! check_rooted; then
        echo -e "${BYellow}[!] Attempting to enable root now...${Off}"
        if ! enable_genymotion_root; then
            # Root enable attempt failed
            if ! check_rooted; then
                echo -e "${BRed}[-] Unable to verify or enable root on ${device_manufacturer} ${device_model}.${Off}"
                echo -e "${BRed}[-] Couldn't install the certificate on the device.${Off}"
                return 1
            fi
        fi

        # Double-check root after enabling
        if ! check_rooted; then
            echo -e "${BRed}[-] Unable to verify or enable root on ${device_manufacturer} ${device_model}.${Off}"
            echo -e "${BRed}[-] Couldn't install the certificate on the device.${Off}"
            return 1
        fi
    fi

    # Check if DER exists
    if [[ ! -f "$DER_FILE" ]]; then
        print_missing_der_instructions
        return 1
    fi

    echo -e "${BGreen}[+]${Off} Converting certificate from DER to PEM..."
    if ! openssl x509 -inform DER -in "$DER_FILE" -out cacert.pem; then
        echo -e "${BRed}[-] OpenSSL conversion from DER to PEM failed.${Off}"
        return 1
    fi

    local HASH
    HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
    echo -e "${BGreen}[+]${Off} Renaming 'cacert.pem' to '${HASH}.0'..."
    mv cacert.pem "$HASH.0"

    local CERT_NAME="$HASH.0"
    echo -e "${BGreen}[+]${Off} Pushing certificate $CERT_NAME to /sdcard/$CERT_NAME"
    if ! adb -s "$DEVICE_ID" push "$CERT_NAME" "/sdcard/$CERT_NAME" &>/dev/null; then
        echo -e "${BRed}[-] Failed to push $CERT_NAME to /sdcard/.${Off}"
        return 1
    fi

    echo -e "${BYellow}[*] Trying direct mount method...${Off}"
    if direct_mount_and_copy "$CERT_NAME"; then
        echo -e "${BGreen}[+]${Off} Direct mount method succeeded!"
    else
        echo -e "${BYellow}[!] Falling back to tmpfs trick...${Off}"
        if adb -s "$DEVICE_ID" shell "su -c '\
                mkdir -m 700 /data/local/tmp/htk-ca-copy && \
                cp /system/etc/security/cacerts/* /data/local/tmp/htk-ca-copy/ && \
                mount -t tmpfs tmpfs /system/etc/security/cacerts && \
                mv /data/local/tmp/htk-ca-copy/* /system/etc/security/cacerts/ && \
                mv /sdcard/'"$CERT_NAME"' /system/etc/security/cacerts/'"$CERT_NAME"' && \
                chown root:root /system/etc/security/cacerts/* && \
                chmod 644 /system/etc/security/cacerts/* && \
                chcon u:object_r:system_file:s0 /system/etc/security/cacerts/* && \
                rm -r /data/local/tmp/htk-ca-copy'" \
        ; then
            echo -e "${BGreen}[+]${Off} Certificate installed via tmpfs fallback!"
        else
            echo -e "${BRed}[-] Certificate installation failed even via tmpfs fallback.${Off}"
            return 1
        fi
    fi

    echo -e "${BYellow}[*] Rebooting the device for changes to take effect...${Off}"
    adb -s "$DEVICE_ID" shell reboot
    sleep 5
    adb -s "$DEVICE_ID" wait-for-device
    echo -e "${BGreen}[+]${BYellow} Certificate successfully installed!${Off}"
    return 0
}

###############################################################################
#  check_burp_cert
###############################################################################
check_burp_cert() {
    echo ""
    echo -e "${BWhite}Checking for Burp Suite CA on this device...${Off}"
    echo ""

    local burp_system_der="./cacert.der"
    local burp_system_pem="/system/etc/security/cacerts/9a5ba575.0"
    local local_cert_found=0
    local device_cert_found=0
    local der_sha1=""
    local der_sha256=""
    local sys_sha1=""
    local sys_sha256=""

    # 1) Local DER
    if [[ -f "$burp_system_der" ]]; then
        echo -e "${BGreen}[+]${Off} Found local DER '$burp_system_der' with these fingerprints:"
        der_sha1=$(openssl x509 -inform DER -in "$burp_system_der" -noout -fingerprint -sha1 2>/dev/null)
        der_sha256=$(openssl x509 -inform DER -in "$burp_system_der" -noout -fingerprint -sha256 2>/dev/null)
        echo "   $der_sha1"
        echo "   $der_sha256"
        echo ""
        local_cert_found=1
    fi

    # 2) Device CA
    if adb -s "$DEVICE_ID" shell ls "$burp_system_pem" &>/dev/null; then
        echo -e "${BGreen}[+]${Off} Burp Suite CA found on the device ($burp_system_pem) with fingerprints:"
        sys_sha1=$(adb -s "$DEVICE_ID" shell cat "$burp_system_pem" | openssl x509 -inform PEM -noout -fingerprint -sha1 2>/dev/null)
        sys_sha256=$(adb -s "$DEVICE_ID" shell cat "$burp_system_pem" | openssl x509 -inform PEM -noout -fingerprint -sha256 2>/dev/null)
        echo "   $sys_sha1"
        echo "   $sys_sha256"
        echo ""
        device_cert_found=1
    fi

    # 3) Compare or offer to install
    if [[ $local_cert_found -eq 1 && $device_cert_found -eq 1 ]]; then
        if [[ "$der_sha1" == "$sys_sha1" && -n "$der_sha1" ]]; then
            echo -e "${BGreen}[+]${BYellow} The fingerprints match! No need to reinstall.${Off}"
            read -p "Unnecessary, but reinstall anyway? [N/y] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                push_certificate
            else
                echo -e "${BYellow}[+]${Off} Have a nice day."
            fi
        else
            echo -e "${BRed}[-] The fingerprints do not match.${Off}"
            read -p "Install the local DER certificate now? [Y/n] " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]] && push_certificate
        fi
    elif [[ $local_cert_found -eq 1 && $device_cert_found -eq 0 ]]; then
        echo -e "${BRed}[-] No Burp Suite CA found in system store.${Off}"
        read -p "Install the local certificate? [Y/n] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]] && push_certificate
    elif [[ $local_cert_found -eq 0 && $device_cert_found -eq 1 ]]; then
        echo -e "${BRed}[-] No local 'cacert.der' found for comparison.${Off}"
        print_missing_der_instructions
    else
        echo -e "${BRed}[-] No Burp Suite CA found locally or on the device.${Off}"
        print_missing_der_instructions
    fi
}

###############################################################################
#  delete_burp_cert
###############################################################################
delete_burp_cert() {
    echo ""
    echo -e "${BWhite}Checking for Burp Suite CA on this device...${Off}"
    echo ""

    if adb -s "$DEVICE_ID" shell ls "/system/etc/security/cacerts/9a5ba575.0" &>/dev/null; then
        echo -e "${BGreen}[+]${Off} Burp Suite CA found. Preparing to delete..."
    else
        echo -e "${BRed}[-] Burp Suite CA not found on the device. Nothing to delete.${Off}"
        return
    fi

    if ! check_rooted; then
        echo -e "${BRed}[-] Device is not rooted. Cannot delete system CA.${Off}"
        return
    fi

    echo -e "${BYellow}[*] Attempting to remount system partition...${Off}"
    if ! remount_system; then
        echo -e "${BRed}[-] Failed to remount system partition read-write. Cannot delete CA.${Off}"
        return 1
    fi

    echo -e "${BYellow}[*] Deleting Burp Suite CA...${Off}"
    if adb -s "$DEVICE_ID" shell "su -c 'rm -f /system/etc/security/cacerts/9a5ba575.0'"; then
        echo -e "${BGreen}[+] Successfully deleted Burp Suite CA.${Off}"
    else
        echo -e "${BRed}[-] Failed to delete Burp Suite CA.${Off}"
        return
    fi

    echo -e "${BYellow}[*] Rebooting the device to apply changes...${Off}"
    adb -s "$DEVICE_ID" shell reboot
    sleep 5
    adb -s "$DEVICE_ID" wait-for-device
    echo -e "${BGreen}[+] Device rebooted. Burp Suite CA should be removed.${Off}"
}

###############################################################################
#  get_local_ips
###############################################################################
get_local_ips() {
    local os_type
    os_type=$(detect_os)
    local ips=()

    if [[ "$os_type" == "Mac" ]]; then
        # macOS: non-loopback IPs
        ips=($(ifconfig | awk '/inet / && !/127.0.0.1/ {print $2}'))
    elif [[ "$os_type" == "Linux" ]]; then
        # Linux: non-loopback IPs
        ips=($(hostname -I))
    else
        echo -e "${BRed}[-] Unsupported OS for automatic IP detection.${Off}"
        return 1
    fi

    ips+=("127.0.0.1")

    echo -e "${BYellow}[!] Available IP Addresses:${Off}"
    local i=1
    for ip in "${ips[@]}"; do
        echo -e "${BGreen}[$i]${Off} $ip"
        ((i++))
    done

    local choice
    while true; do
        read -p "Choose an IP address (default: 127.0.0.1): " choice
        if [[ -z "$choice" ]]; then
            PROXY_IP="127.0.0.1"
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice > 0 && choice <= ${#ips[@]} )); then
            PROXY_IP="${ips[$((choice-1))]}"
            break
        else
            echo -e "${BRed}Invalid choice. Please select a number from the list.${Off}"
        fi
    done

    read -p "Enter proxy port (default: 8080): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-8080}
    PROXY_ADDRESS="$PROXY_IP:$PROXY_PORT"
}

###############################################################################
#  set_proxy
###############################################################################
set_proxy() {
    local proxy="$1"

    if [[ -z "$proxy" ]]; then
        # Display current proxy
        local current_proxy
        current_proxy=$(adb -s "$DEVICE_ID" shell settings get global http_proxy 2>/dev/null)
        if [[ -z "$current_proxy" || "$current_proxy" == "null" || "$current_proxy" == ":0" ]]; then
            echo -e "${BYellow}[*] No proxy is currently set on the device.${Off}"
        else
            echo -e "${BGreen}[+] Current proxy setting: $current_proxy${Off}"
        fi
    elif [[ "$proxy" == "remove" ]]; then
        echo -e "${BYellow}[*] Removing proxy settings from the device...${Off}"
        adb -s "$DEVICE_ID" shell settings put global http_proxy :0
        echo -e "${BGreen}[+] Proxy settings removed.${Off}"
    elif [[ "$proxy" == "auto" ]]; then
        # Auto-detect IP / Port
        get_local_ips
        echo -e "${BYellow}[*] Setting proxy to $PROXY_ADDRESS...${Off}"
        adb -s "$DEVICE_ID" shell settings put global http_proxy "$PROXY_ADDRESS"
        echo -e "${BGreen}[+] Proxy set to $PROXY_ADDRESS${Off}"
    else
        echo -e "${BYellow}[*] Setting proxy to $proxy...${Off}"
        adb -s "$DEVICE_ID" shell settings put global http_proxy "$proxy"
        echo -e "${BGreen}[+] Proxy set to $proxy${Off}"
    fi
}

###############################################################################
#  Main
###############################################################################
if check_adb_installed; then
    select_device_or_fail
    get_device_info

    # Check root status
    # Check if device is rooted
    if ! check_rooted true; then        
        # Get device manufacturer
        # device_manufacturer=$(adb -s "$DEVICE_ID" shell getprop ro.product.manufacturer | tr -d '\r')

        # # Check if the manufacturer is Genymobile
        # if [[ "$device_manufacturer" == "Genymobile" ]]; then
        #     # Prompt to enable root if the manufacturer is Genymobile
        #     read -p "$(echo -e "${BGreen}[+]${Off} Identified Genymobile device would you like to root the device? [Y/n] ")" REPLY
        #     if [[ -z "$REPLY" || "$REPLY" =~ ^[Yy]$ ]]; then
        #         # Call a function to root the device or enable root access
        #         #echo -e "${BYellow}[*] Attempting to root the device...${Off}"
        #         if enable_genymotion_root; then
        #             echo -e "${BGreen}[+] Device rooted successfully.${Off}"
        #         else
        #             echo -e "${BRed}[-] Failed to root the device.${Off}"
        #         fi
        #     else
        #         echo -e "${BYellow}[+]${Off} Skipping root operation.${Off}"
        #     fi
        # else
        #     echo -e "${BRed}[-] Device is not rooted, and it is not a Genymobile device. Skipping root operation.${Off}"
        # fi
        echo ""
    fi



    # Now parse the rest of the command-line arguments
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -c|--check)
                check_burp_cert
                shift
                ;;
            -s|--save-certs)
                pull_all_certs
                shift
                ;;
            -p|--proxy)
                # e.g. --proxy auto, --proxy remove, --proxy 192.168.1.100:8080
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    if [[ "$2" == "remove" || "$2" == "auto" ]]; then
                        set_proxy "$2"
                    else
                        PROXY_ADDRESS="$2"
                        set_proxy "$PROXY_ADDRESS"
                    fi
                    shift
                else
                    set_proxy  # No arg -> display current proxy
                fi
                shift
                ;;
            -r|--root)
                # e.g. --root yes, --root no
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    ENABLE_ROOT="$2"
                    shift
                else
                    # If no arg, prompt if device is not rooted
                    if check_rooted; then
                        echo -e "${BGreen}[+] Device is already rooted. No need to enable root.${Off}"
                        shift
                        continue
                    fi
                    read -p "Enable full root on Genymotion? (Y/n): " REPLY
                    if [[ -z "$REPLY" || "$REPLY" =~ ^[Yy]$ ]]; then
                        ENABLE_ROOT="yes"
                    else
                        ENABLE_ROOT="no"
                    fi
                fi

                if [[ "$ENABLE_ROOT" == "yes" ]]; then
                    if check_rooted; then
                        echo -e "${BGreen}[+] Device is already rooted. No need to enable root.${Off}"
                    else
                        enable_genymotion_root
                    fi
                elif [[ "$ENABLE_ROOT" == "no" ]]; then
                    # Use the dedicated function for disabling root
                    disable_genymotion_root
                else
                    echo -e "${BYellow}[+] Skipping Genymotion root changes.${Off}"
                fi
                shift
                ;;
            -d|--delete)
                delete_burp_cert
                shift
                ;;
            *)
                echo -e "${BRed}Unknown option: $1${Off}"
                usage
                ;;
        esac
    done
fi
