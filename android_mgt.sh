#!/bin/bash

Off='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# Underline
UWhite='\033[4;37m'       # White



# Function to display usage
usage() {
  	echo "Usage: $0 [-c|--check]"
  	echo
  	echo "Options:"
  	echo "  -c, --check Check if there is a Burp Suite Pro System CA on the Android Device."
  	echo "  -a, --all Pull all the certificate authorities from the Android device."
  	echo
  	echo "Description:"
  	echo " This script retrieves device information, extracts the Burp Suite certificate authority (CA) from the device,"
	echo " compares its fingerprint with an exported certificate, and provides an option to install the certificate if needed."
	echo " The script is designed to help manage Burp Suite CA certificates on rooted Android devices, ensuring the proper"
	echo " certificate is installed and up-to-date for security testing purposes."
	echo ""

  echo
  exit 1
}

check_adb_installed(){
	if ! command -v adb &> /dev/null; then
		echo "adb not found. Please install Android platform tools."
		read -p "Do you want to install it now? [Y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
			sudo apt install android-platform-tools
		else
			exit 1
		fi
	fi
}

check_device_connected(){
	# Check if a device is connected
	if ! adb get-state &> /dev/null; then
		echo "No device found. Please connect a device or check if adb is working."
		exit 1
	fi
}

get_device_info(){
	sdk_version=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
	code_name=""

	case $sdk_version in
		14|15) code_name="Ice Cream Sandwich";;
		16|17|18) code_name="Jelly Bean";;
		19|20) code_name="KitKat";;
		21|22) code_name="Lollipop";;
		23) code_name="Marshmallow";;
		24|25) code_name="Nougat";;
		26|27) code_name="Oreo";;
		28) code_name="Pie";;
		29) code_name="Android 10";;
		30) code_name="Android 11";;
		31) code_name="Android 12";;
		32) code_name="Android 12L";;
		33) code_name="Android 13";;
		*) code_name="Unknown";;
	esac

	# Get Android version and codename
	android_version=$(adb shell getprop ro.build.version.release)
	android_codename=$(adb shell getprop ro.build.version.codename)

	device_model=$(adb shell getprop ro.product.model | tr -d '\r')
	device_manufacturer=$(adb shell getprop ro.product.manufacturer | tr -d '\r')
	device_serial=$(adb get-serialno)
	device_name=$(adb shell getprop ro.product.name | tr -d '\r')
	device_build_id=$(adb shell getprop ro.build.id | tr -d '\r')
	device_build_fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')

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

check_rooted(){
	root_status=$(adb shell id)

	if [[ $root_status == *"uid=0"* ]]; then
		adb_root_check="${BGreen}Rooted${Off}"
	else
		adb_root_check="${BRed}Not Rooted${Off}"
	fi

	echo -ne "Device root status: $adb_root_check "

	root_get_packages=$(adb shell -t su -c pm list packages)

	if adb shell -t su -c pm list packages &> /dev/null; then
		echo -e "${BWhite}successfully listed packages with root${Off}"
	else
		echo -e "${BRed}Can not list packages with root${Off}"
	fi
}

pull_all_certs(){
	if ! adb pull "/system/etc/security/cacerts/" . &> /dev/null; then
		echo -e "${BRed}Was unable to extract the System CA's from device${Off}"
		#exit 1
	else
		echo -e "${BGreen}[+] ${Off}Successfully extracted System CA's to "./cacerts"${Off}"
	fi

}

check_burp_cert(){
	echo ""
	echo -e "${BWhite}Let's Check The Certificate Authorities On This Device:${Off}"
	echo ""


	# Check if you can extract CA certificates
	if adb pull "/system/etc/security/cacerts/9a5ba575.0" . &> /dev/null; then
		echo -e "${BGreen}[+] ${Off}Successfully extracted Burp Suite System CA to "./9a5ba575.0"${Off}"
	fi

	get_sha1_fingerprint(){
		local burp_cert=$1
		local type=$2
		echo -e "    $(openssl x509 -in ${burp_cert} -inform ${type} -noout -fingerprint -sha1)"
		
	}
	get_sha256_fingerprint(){
		local burp_cert=$1
		local type=$2
		echo -e "    $(openssl x509 -in ${burp_cert} -inform ${type} -noout -fingerprint -sha256)"
		
	}

	push_certificate() {
		
		echo -e "${BGreen}[+] ${Off}Converting certificate from DER to PEM${Off}"
		openssl x509 -inform DER -in cacert.der -out cacert.pem 

		echo -e "${BGreen}[+] ${Off}Changing name of certificate to Android format${Off}"
		HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1) 
		mv cacert.pem $HASH.0 

		echo -e "${BGreen}[+] ${Off}Moving certificate to Android sdcard${Off}"
		adb push $HASH.0 /sdcard/
	  
		echo -e "${BGreen}[+] ${Off}Using ADB shell to create virtual temporary file system${Off}"
		if adb shell -t su -c "set -e; \
			mkdir -m 700 /data/local/tmp/htk-ca-copy; \
			cp /system/etc/security/cacerts/* /data/local/tmp/htk-ca-copy/; \
			mount -t tmpfs tmpfs /system/etc/security/cacerts; \
			mv /data/local/tmp/htk-ca-copy/ /system/etc/security/cacerts/; \
			mv /sdcard/$HASH.0 /system/etc/security/cacerts/; \
			chown root:root /system/etc/security/cacerts/*; \
			chmod 644 /system/etc/security/cacerts/*; \
			chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*; \
			rm -r /data/local/tmp/htk-ca-copy"
		then
			echo -e "${BGreen}[+] ${BYellow}Certificate successfully Installed!${Off}"
		else
			echo -e "${BRed}[+] ${Off}Certificate Installation Failed :(${Off}"
		fi
	}

	# Check if there is already a Burp certificate on device
	if [ -e "./9a5ba575.0" ]; then
		burp_system_pem="./9a5ba575.0"
	else 
		if [ -e "./cacerts/9a5ba575.0" ]; then
			burp_system_pem="./cacerts/9a5ba575.0"
		fi
	fi

	burp_system_der="./cacert.der"

	if [ -e "$burp_system_pem" ]; then

		echo -e "${BGreen}[+] ${Off}Found Burp PEM formated certificate already installed on this device with following fingerprints:${Off}"
		echo ""
		pem_sha1=$(get_sha1_fingerprint "$burp_system_pem" "PEM")
		pem_sha256=$(get_sha256_fingerprint "$burp_system_pem" "PEM")
		echo -e "   $pem_sha1"
		echo -e "   $pem_sha256"

		if [ -e "$burp_system_der" ]; then

			#echo ""
			echo -e "${BGreen}[+] ${Off}Found Burp exported DER formated certificate in current directory with following fingerprintes:${Off}"
			echo ""
			der_sha1=$(get_sha1_fingerprint "$burp_system_der" "DER")
			der_sha256=$(get_sha256_fingerprint "$burp_system_der" "DER")
			echo -e "   $der_sha1"
			echo -e "   $der_sha256"

			if [[ "$der_sha1" == "$pem_sha1" ]]; then
				echo ""
				echo -e "${BGreen}[+] ${BYellow}The fingerprints match! No need to install again.${Off}"
				echo ""
				read -p "It's unnecessary, however do you want to still want to install it? [N/y]" -n 1 -r
				if [[ $REPLY =~ ^[Nn]$ || $REPLY == "" ]]; then
					echo ""
					echo -e "${BYellow}[+] ${Off}Have a nice day :)${Off}"
					echo ""
					exit 1
				else
					echo ""
					push_certificate
					echo ""
					echo -e "${BGreen}[+] ${BYellow}Certificate successfully Installed!${Off}"
					echo ""
					echo -e "${BYellow}[+] ${Off}Have a nice day :)${Off}"
					echo ""
				fi
			else
				echo -e "${BRed}[+] ${Off}The fingerprints do not match!:${Off}"
				read -p "Do you want to install the one in this directory now? [Y/n] " -n 1 -r
				if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
					push_certificate

					echo -e "${BGreen}[+] ${BYellow}Certificate successfully Installed!${Off}"
				fi
			fi
		else
			echo ""
			echo -e "${BRed}[+] ${Off}Found no Burp xported DER foramated certificate named "cacert.der" in current directory"
			echo -e "${BRed}    ${Off}Please export DER formated Burp Suite Pro certificate: \n (Proxy Settings -> Import/export CA certificate -> Certificate in DER format) "
				exit 1
		fi
	else
		echo -e "${BRed}[+] ${Off}Did not Find Burp Suite CA certificate on this device${Off}"
		if [ -e "$burp_system_der" ]; then

			echo -e "${BGreen}[+] ${Off}Found Burp exported DER formated certificate in current directory with following fingerprintes:${Off}"
			echo ""
			der_sha1=$(get_sha1_fingerprint "$burp_system_der" "DER")
			der_sha256=$(get_sha256_fingerprint "$burp_system_der" "DER")
			echo -e "   $der_sha1"
			echo -e "   $der_sha256"

			echo ""
			read -p "Do you want to install this certificate? [Y/n] " -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
					push_certificate

				echo ""
				echo -e "${BGreen}[+] ${BYellow}Certificate successfully Installed!${Off}"
				echo ""
				echo -e "${BYellow}[+] ${Off}Have a nice day :)${Off}"
				echo ""
			else
				echo ""
				echo ""
				echo -e "${BYellow}[+] ${Off}Ok Then have a nice day :)${Off}"
				echo ""
			fi
		else
			echo -e "${BRed}[+] ${Off}Found no Burp xported DER foramated certificate named "cacert.der" in current directory"
			echo -e "${BYellow}[+] ${Off}Please export DER formated Burp Suite Pro certificate:"
			echo -e "${BYellow}[+] ${Off}(Proxy Settings -> Import/export CA certificate -> Certificate in DER format) save it here as cacert.der "
			echo -e "${BYellow}[+] ${Off}Save it to this directory and name it \"cacert.der\""
			echo ""
		fi
	fi
}	

if check_adb_installed && check_device_connected; then
	get_device_info
	check_rooted
	if [[ "$#" -gt 0 ]]; then

		case $1 in
			-c|--check)
				check_burp_cert
				shift
				;;
			-a|--all)
				shift
				;;
			-h)
				usage
				break
				;;
		esac
	fi
fi	
