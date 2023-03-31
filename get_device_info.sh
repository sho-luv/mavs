#!/bin/bash

#
# By Leon Johnson - twitter.com/sho_luv

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

# Check if a device is connected
if ! adb get-state &> /dev/null; then
    echo "No device found. Please connect a device or check if adb is working."
    exit 1
fi

api_level=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
code_name=""

case $api_level in
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
echo -e "Android version code name: ${Yellow}$code_name${Off}"
echo -e "Android Version: ${Yellow}${android_version} (${android_codename})${Off}"
echo -e "Android API level: ${Yellow}$api_level${Off}"

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
