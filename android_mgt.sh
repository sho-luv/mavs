#!/bin/bash

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
#  Usage
###############################################################################
usage() {
  	echo "Usage: $0 [options]"
  	echo
  	echo "Options:"
  	echo "  -c, --check         Check if there is a Burp Suite Pro System CA on the device."
  	echo "  -a, --all           Pull all certificate authorities from the device."
  	echo "  --enable-geny-root  (Optional) Force the Genymotion root-enabling procedure."
  	echo
  	echo "Description:"
  	echo "  This script retrieves device information, extracts the Burp Suite certificate authority (CA) from the device,"
  	echo "  compares its fingerprint with an exported certificate, and provides an option to install/update the CA in"
  	echo "  /system/etc/security/cacerts. If using Genymotion, it can enable full root by setting persist.sys.root_access=3."
  	echo
  	exit 1
}

###############################################################################
#  Detect OS
###############################################################################
detect_os() {
  # You can also use: [[ "$OSTYPE" == "darwin"* ]] for macOS
  local uname_out
  uname_out=$(uname -s 2>/dev/null || echo "Unknown")

  case "$uname_out" in
    Linux*)   echo "Linux" ;;
    Darwin*)  echo "Mac"   ;;
    *)        echo "Other" ;;
  esac
}

###############################################################################
#  Install ADB for OS
###############################################################################
install_adb_for_os() {
  local current_os="$1"

  if [[ "$current_os" == "Linux" ]]; then
    # Attempt apt-based install
    if command -v apt &>/dev/null; then
      echo -e "${BYellow}[*] Installing adb via 'sudo apt install android-platform-tools'...${Off}"
      sudo apt update && sudo apt install -y android-platform-tools
    else
      echo -e "${BRed}[-] 'apt' not found; please install adb manually for your Linux distribution.${Off}"
      exit 1
    fi

  elif [[ "$current_os" == "Mac" ]]; then
    # Attempt brew-based install
    if command -v brew &>/dev/null; then
      echo -e "${BYellow}[*] Installing adb via 'brew install android-platform-tools'...${Off}"
      brew install android-platform-tools
    else
      echo -e "${BRed}[-] Homebrew not found; please install Homebrew and try again, or install adb manually.${Off}"
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
check_adb_installed(){
	if ! command -v adb &> /dev/null; then
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
#  - Lists all online devices. If none, exit. If 1, pick it. If multiple, prompt.
###############################################################################
select_device_or_fail(){
  local devices_list
  devices_list=$(adb devices | awk '/\tdevice$/ {print $1}')  # Only those listed as "device"

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
    # If you want to auto-pick the first device, remove this select menu:
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
#  get_device_info
###############################################################################
get_device_info(){
	local sdk_version code_name android_version android_codename
	local device_model device_manufacturer device_serial device_name
	local device_build_id device_build_fingerprint

	sdk_version=$(adb -s "$DEVICE_ID" shell getprop ro.build.version.sdk | tr -d '\r')
	code_name=""

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

	device_model=$(adb -s "$DEVICE_ID" shell getprop ro.product.model | tr -d '\r')
	device_manufacturer=$(adb -s "$DEVICE_ID" shell getprop ro.product.manufacturer | tr -d '\r')
	device_serial=$(adb -s "$DEVICE_ID" get-serialno | tr -d '\r')
	device_name=$(adb -s "$DEVICE_ID" shell getprop ro.product.name | tr -d '\r')
	device_build_id=$(adb -s "$DEVICE_ID" shell getprop ro.build.id | tr -d '\r')
	device_build_fingerprint=$(adb -s "$DEVICE_ID" shell getprop ro.build.fingerprint | tr -d '\r')

	echo -e "Device model: ${Yellow}$device_model${Off}"
	echo -e "Device manufacturer: ${Yellow}$device_manufacturer${Off}"
	echo -e "Device serial number: ${Yellow}$device_serial${Off}"
	echo -e "Device name: ${Yellow}$device_name${Off}"
	echo -e "Device build ID: ${Yellow}$device_build_id${Off}"
	echo -e "Device build fingerprint: ${Yellow}$device_build_fingerprint${Off}"
	echo -e "Android SDK version: ${Yellow}$sdk_version${Off}"
	echo -e "Android version code name: ${Yellow}$code_name${Off}"
	echo -e "Android Version: ${Yellow}${android_version} (${android_codename})${Off}"
}

################################################################################
##  check_rooted
################################################################################
#check_rooted(){
#	local root_status
#	root_status=$(adb -s "$DEVICE_ID" shell id)
#
#	if [[ $root_status == *"uid=0"* ]]; then
#		adb_root_check="${BGreen}Rooted${Off}"
#	else
#		adb_root_check="${BRed}Not Rooted${Off}"
#	fi
#
#	echo -ne "Device root status: $adb_root_check "
#
#	if adb -s "$DEVICE_ID" shell -t su -c pm list packages &> /dev/null; then
#		echo -e "${BWhite}successfully listed packages with root${Off}"
#
#	 # 2) If that fails, try normal (non-su) pm list packages
#	elif adb -s "$DEVICE_ID" shell "pm list packages" &>/dev/null; then
#	    echo -e "${BYellow}[!] 'su' not available, but listed packages normally.${Off}"
#
#
#	else
#		echo -e "${BRed}Cannot list packages with root${Off}"
#	fi
#}
###############################################################################
#  check_rooted - Distinguishes “already root (uid=0)” vs. “needs su” vs. “unrooted”
###############################################################################
check_rooted(){
  local root_status
  root_status=$(adb -s "$DEVICE_ID" shell id 2>/dev/null)

  # Check if ADB shell is already running as root
  if [[ $root_status == *"uid=0"* ]]; then
    echo -ne "Device root status: ${BGreen}Rooted${Off} "
    # In this case, we likely don't need su at all
    if adb -s "$DEVICE_ID" shell "pm list packages" &>/dev/null; then
      echo -e "- successfully listed packages without 'su' (already root)."
    else
      echo -e "- unable to list packages with normal shell. Something else is wrong."
    fi

  else
    # ADB shell is not root (uid != 0)
    echo -ne "Device root status: ${BRed}Not Rooted${Off} "

    # Try listing packages with su -c
    if adb -s "$DEVICE_ID" shell -t su -c "pm list packages" &>/dev/null; then
      echo -e "${BWhite}successfully listed packages with 'su'${Off}"

    # If su didn't work, try normal pm list packages
    elif adb -s "$DEVICE_ID" shell "pm list packages" &>/dev/null; then
      echo -e "${BYellow}[!] 'su' not used or not needed, but listed packages normally (device is not running as root).${Off}"

    else
      echo -e "${BRed}Cannot list packages either with or without 'su'.${Off}"
    fi
  fi
}


###############################################################################
#  pull_all_certs
###############################################################################
pull_all_certs(){
	if ! adb -s "$DEVICE_ID" pull "/system/etc/security/cacerts/" ./cacerts &> /dev/null; then
		echo -e "${BRed}[-] Unable to extract System CAs from device.${Off}"
	else
		echo -e "${BGreen}[+]${Off} Successfully extracted System CAs to \"./cacerts\"."
	fi
}

###############################################################################
#  enable_genymotion_root
###############################################################################
enable_genymotion_root(){
	echo -e "${BYellow}[*] Attempting to enable full root on Genymotion (persist.sys.root_access=3)...${Off}"
	adb -s "$DEVICE_ID" root
	sleep 2
	adb -s "$DEVICE_ID" wait-for-device

	adb -s "$DEVICE_ID" shell setprop persist.sys.root_access 3
	sleep 1

	adb -s "$DEVICE_ID" root
	sleep 2
	adb -s "$DEVICE_ID" wait-for-device
	echo -e "${BGreen}[+]${Off} Genymotion root access enabled (if supported)."
}

###############################################################################
#  direct_mount_and_copy
###############################################################################
direct_mount_and_copy(){
	local cert_name="$1"

	echo -e "${BYellow}[*] Attempting direct remount of '/' or '/system'...${Off}"
	if adb -s "$DEVICE_ID" shell su -c "mount -o rw,remount /" &>/dev/null; then
		echo -e "${BGreen}[+]${Off} Remounted '/' read-write."
	elif adb -s "$DEVICE_ID" shell su -c "mount -o rw,remount /system" &>/dev/null; then
		echo -e "${BGreen}[+]${Off} Remounted '/system' read-write."
	else
		echo -e "${BRed}[-] Failed to remount system partition read-write.${Off}"
		return 1
	fi

	# Move from /sdcard/${cert_name} to /system/etc/security/cacerts/${cert_name}
	if adb -s "$DEVICE_ID" shell su -c "mv /sdcard/${cert_name} /system/etc/security/cacerts/${cert_name}" &>/dev/null; then
		adb -s "$DEVICE_ID" shell su -c "chmod 644 /system/etc/security/cacerts/${cert_name}"
		adb -s "$DEVICE_ID" shell su -c "chown root:root /system/etc/security/cacerts/${cert_name}"
		adb -s "$DEVICE_ID" shell su -c "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/${cert_name}"
		echo -e "${BGreen}[+]${Off} Certificate moved to system store with direct remount."
		return 0
	else
		echo -e "${BRed}[-] Failed to move certificate with direct remount method.${Off}"
		return 1
	fi
}

###############################################################################
#  push_certificate
###############################################################################
push_certificate() {
	local DER_FILE="cacert.der"

	if [[ ! -f "$DER_FILE" ]]; then
		echo -e "${BRed}[-] No DER file named 'cacert.der' found in current directory.${Off}"
		return 1
	fi

	echo -e "${BGreen}[+]${Off} Converting certificate from DER to PEM..."
	if ! openssl x509 -inform DER -in "$DER_FILE" -out cacert.pem; then
		echo -e "${BRed}[-] OpenSSL conversion from DER to PEM failed.${Off}"
		return 1
	fi

	echo -e "${BGreen}[+]${Off} Renaming certificate to Android <hash>.0 format..."
	local HASH
	HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
	mv cacert.pem "$HASH.0"

	local CERT_NAME="$HASH.0"
	echo -e "${BGreen}[+]${Off} Pushing certificate $CERT_NAME to /sdcard/$CERT_NAME"
	if ! adb -s "$DEVICE_ID" push "$CERT_NAME" "/sdcard/$CERT_NAME" &>/dev/null; then
		echo -e "${BRed}[-] Failed to push $CERT_NAME to device /sdcard.${Off}"
		return 1
	fi

	echo -e "${BYellow}[*] Trying direct mount method...${Off}"
	if direct_mount_and_copy "$CERT_NAME"; then
		echo -e "${BGreen}[+]${Off} Direct mount method succeeded!"
	else
		# If direct method fails, use the tmpfs fallback
		echo -e "${BYellow}[!] Falling back to tmpfs trick...${Off}"
		if adb -s "$DEVICE_ID" shell -t su -c "set -e; \
			mkdir -m 700 /data/local/tmp/htk-ca-copy; \
			cp /system/etc/security/cacerts/* /data/local/tmp/htk-ca-copy/; \
			mount -t tmpfs tmpfs /system/etc/security/cacerts; \
			mv /data/local/tmp/htk-ca-copy/* /system/etc/security/cacerts/; \
			mv /sdcard/$CERT_NAME /system/etc/security/cacerts/$CERT_NAME; \
			chown root:root /system/etc/security/cacerts/*; \
			chmod 644 /system/etc/security/cacerts/*; \
			chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*; \
			rm -r /data/local/tmp/htk-ca-copy" \
		; then
			echo -e "${BGreen}[+]${Off} Certificate successfully installed via tmpfs fallback!"
		else
			echo -e "${BRed}[-] Certificate installation failed even via tmpfs fallback.${Off}"
			return 1
		fi
	fi

	# Optional: reboot so the system picks up the new CA
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
check_burp_cert(){
	echo ""
	echo -e "${BWhite}Checking for Burp Suite CA on this device...${Off}"
	echo ""

	# Attempt to pull the usual Burp cert from system
	if adb -s "$DEVICE_ID" pull "/system/etc/security/cacerts/9a5ba575.0" . &> /dev/null; then
		echo -e "${BGreen}[+]${Off} Found Burp Suite System CA as \"./9a5ba575.0\""
	fi

	get_sha1_fingerprint(){
		local burp_cert=$1
		local type=$2
		openssl x509 -in "${burp_cert}" -inform "${type}" -noout -fingerprint -sha1 2>/dev/null
	}
	get_sha256_fingerprint(){
		local burp_cert=$1
		local type=$2
		openssl x509 -in "${burp_cert}" -inform "${type}" -noout -fingerprint -sha256 2>/dev/null
	}

	local burp_system_pem="./9a5ba575.0"   # Pulled from device if exists
	local burp_system_der="./cacert.der"   # Locally exported DER file

	if [[ -f "$burp_system_pem" ]]; then
		echo -e "${BGreen}[+]${Off} Burp PEM certificate is in system store with these fingerprints:"
		local pem_sha1
		local pem_sha256
		pem_sha1="$(get_sha1_fingerprint "$burp_system_pem" "PEM")"
		pem_sha256="$(get_sha256_fingerprint "$burp_system_pem" "PEM")"
		echo "   $pem_sha1"
		echo "   $pem_sha256"
		echo ""

		if [[ -f "$burp_system_der" ]]; then
			echo -e "${BGreen}[+]${Off} Found local DER '$burp_system_der' with these fingerprints:"
			local der_sha1
			local der_sha256
			der_sha1="$(get_sha1_fingerprint "$burp_system_der" "DER")"
			der_sha256="$(get_sha256_fingerprint "$burp_system_der" "DER")"
			echo "   $der_sha1"
			echo "   $der_sha256"
			echo ""

			if [[ "$der_sha1" == "$pem_sha1" ]]; then
				echo -e "${BGreen}[+]${BYellow} The fingerprints match! No need to reinstall.${Off}"
				read -p "Unnecessary, but do you want to reinstall anyway? [N/y] " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					push_certificate
				else
					echo -e "${BYellow}[+]${Off} Have a nice day :)"
				fi
			else
				echo -e "${BRed}[-] The fingerprints do not match.${Off}"
				read -p "Install the DER from this directory now? [Y/n] " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
					push_certificate
				fi
			fi
		else
			echo -e "${BRed}[-] No local 'cacert.der' found for comparison.${Off}"
			echo -e "    Please export Burp's CA in DER format and name it 'cacert.der'."
		fi
	else
		echo -e "${BRed}[-] No Burp Suite CA (9a5ba575.0) found in system store.${Off}"
		if [[ -f "$burp_system_der" ]]; then
			echo -e "${BGreen}[+]${Off} Found local DER '$burp_system_der' with these fingerprints:"
			local der_sha1
			local der_sha256
			der_sha1="$(get_sha1_fingerprint "$burp_system_der" "DER")"
			der_sha256="$(get_sha256_fingerprint "$burp_system_der" "DER")"
			echo "   $der_sha1"
			echo "   $der_sha256"
			echo ""

			read -p "Do you want to install this certificate? [Y/n] " -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
				push_certificate
			else
				echo -e "${BYellow}[+]${Off} Ok, have a nice day :)"
			fi
		else
			echo -e "${BRed}[-] No local 'cacert.der' found; cannot install Burp CA.${Off}"
			echo -e "${BYellow}Export a DER cert from Burp and rename it 'cacert.der'.${Off}"
		fi
	fi
}

###############################################################################
#  Main
###############################################################################
if check_adb_installed; then
	# Instead of checking if ANY device is connected, let's pick specifically
	# the one we want from among online devices.
	select_device_or_fail

	# Now we can safely run all commands using $DEVICE_ID
	get_device_info
	check_rooted

	while [[ "$#" -gt 0 ]]; do
		case "$1" in
			-c|--check)
				check_burp_cert
				shift
				;;
			-a|--all)
				pull_all_certs
				shift
				;;
			--enable-geny-root)
				enable_genymotion_root
				shift
				;;
			-h|--help)
				usage
				;;
			*)
				echo -e "${BRed}Unknown option: $1${Off}"
				usage
				;;
		esac
	done
fi

