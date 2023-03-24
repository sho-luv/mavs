#!/bin/bash

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

echo "Device model: $device_model"
echo "Device manufacturer: $device_manufacturer"
echo "Device serial number: $device_serial"
echo "Device name: $device_name"
echo "Device build ID: $device_build_id"
echo "Device build fingerprint: $device_build_fingerprint"
echo "Android SDK version: $sdk_version"
echo "Android version code name: $code_name"
echo "Android Version: ${android_version} (${android_codename})"


