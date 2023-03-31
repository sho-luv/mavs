#! /bin/bash

############################################
# by Leon Johnson @sho_luv
#
# This is a program to parse automate testing
# apk files. It is intended to fill gap of tools
# that do not show users how to verify findings
# the -e options shows how to manually verify
# anything this tool finds.
#
# requirements:
#	apkinfo
#	d2j-dex2jar
#	zipgrep
#	apktool
#
# this program will do the following:
# [x] extract and display info with apkinfo
# This script will check for misconfigurations within the APK.
# First it uses apkinfo to extract information about the apk.
# Then it uses d2j-dex2jar to get a .jar file form the apk
# It then uses zipgrep to search .jar file for misconfigurations
# Checks:
	# 1. 	[x] insufficient certificat validation
	# 			[x] hostname verified:
	# 			[x] auth in protected space:
	# [x] check logging enabled
	# 	[x] check log.e calls
	# 	[X] check logger calls
	# [X] check if app allows snapshots to be taken
	# [X] check if backups are allowed
	# [X] check if debuggin was left enabled
	# [X] check for android:usesCleartextTraffic=true
	# [ ] check outdated software (in progress)
	#	[ ]	libpng
	#	[ ]	sqlite
	# [ ] check broadcast: sendBroadcast
	# [ ] check for external storage WRITE_EXTERNAL_STORAGE
	# [ ] MODE_WORLD_READABLE
	# [ ] MODE_WORLD_WRITABLE
	# [ ] check certificate: jarsigner -verify -certs file.apk  
	# [ ] add more info to finding Insecure Mobile Device Data Storage about int/ext storage
	# [ ] basic hardcoded secrets check apktool

# Reset
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

ANSWER='\t\t\t\t\t'	  # Tab for answers
EXPLOIT=""
VERBOSE=""
scriptVersion='1.0'


banner="
                                   ╓
                        ╕         ╒╣╕                     ╣╣╣─    ╦╣╣
                ╓      ║╬         ╣╣╣      ╒             ╣╣╣─  ╒╣╣╩╙╣╬║╣
                ╣╕     ╣╣        ╫╣ ╫╣     ╡  ╔         ╣╣╣   ╦╣╩   ║╣╬
               ╣╣╣    ║╣╣╬      ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣   ╣╣╬    ╞╩
             ╒╣╣╩╣╣╖ ╔╣╬╣╣╕    ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣     ╙╣╣╣╦╗╖
            ╔╣╣╜  ╝╣╣╣╜ ╙╣╣═╩╜║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣          ╠╜╝╣╣╣╣╗╖
          ╓╣╣╩           ╚╣╣ ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖
        ╒╣╣╬╗╗╗           ╚╣╣╖           ╙╣╣╗   ╙╣╣╣╣╩    ╓╣╣╩╙ ║╣             ╙╣╣╣╖
      ╓╣╣╝╜╙╙╙╙            ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╬    ├╣╣╖    ╬           ╓╓╗╣╣╣╩
                       ║╣╣╣╣╣╣╣╣╣╖           ╓╣╣╣ ╣╬      ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙
                             └╙╙╨╝╝╝╝╝╝╝╝╝╨╜╜╙╙╙   ╣

		${BWhite}Mobile Application Vulnerability Scanner${Off} | ${BYellow}@sho_luv${Off}
"

# code from: https://natelandau.com/boilerplate-shell-script-template/

usage() {
  echo -e "${Off}${banner}${Off} 

Usage: $(basename $0) [OPTIONS]

 Required:
  -f <apk>	Andorid APK file to decompile and run static analysis
 
 Options:
  -v 		Verbose, show affected files
  -e 		Show how to exploit finding
  -h 		Show this help

"
}

if [ $# -eq 0 ]; then
	usage >&2;
    exit 0
else
	while getopts "hf:ve" option; do
	  case ${option} in
		h ) usage
			exit 0
			#echo "Usage: $0 -f file.apk [-h]"
			;;
		f ) APK="$OPTARG"
			rflag=true
			;;
		v ) VERBOSE=true
			;;
		e ) EXPLOIT=true
			;;
		*)
			echo "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
	  esac
	done
fi

if [ -z $rflag ]; then
	usage
    echo "Required -f option is missing" >&2
    exit 1
fi

# Check if apkinfo is installed
if ! which apkinfo > /dev/null; then
    echo -e "${BRed}apkinfo is not installed.${Off}"
    read -p "Do you want to install it now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
        sudo apt install apkinfo
    else
        exit 1
    fi
fi

# Check if dex2jar is installed
if ! which d2j-dex2jar > /dev/null; then
    echo -e "${BRed}dex2jar is not installed.${Off}"
    read -p "Do you want to install it now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
        sudo apt install dex2jar
    else
        exit 1
    fi
fi


# Check if zipgrep is installed
if ! which zipgrep > /dev/null; then
    echo -e "${BRed}zipgrep is not installed.${Off}"
    read -p "Do you want to install it now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
        sudo apt install zipgrep
    else
        exit 1
    fi
fi

# Check if apktool is installed
if ! which apktool > /dev/null; then
    echo -e "${BRed}apktool is not installed.${Off}"
    read -p "Do you want to install it now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ || $REPLY == "" ]]; then
        sudo apt install apktool
    else
        exit 1
    fi
fi

if [ -f "$APK" ]; then 
  	echo -e "${banner}"
	info=$(apkinfo $APK 2> /dev/null | awk -F': ' '{print $2}')
    IFS=$'\n' info=(${info})

	app_name=${info[1]}
	apk_file=${info[0]}
	package_name=${info[2]}
	version_name=${info[3]}
	version_code=${info[4]}
	vulns_checked="9"

	echo -e " App Name: \t${BWhite}${app_name}${Off}"
	echo -e " APK File: \t${BWhite}${apk_file}${Off}"
	echo -e " Package Name: \t${BWhite}${package_name}${Off}"
	echo -e " Version Name: \t${BWhite}${version_name}${Off}"
	echo -e " Version Code: \t${BWhite}${version_code}${Off}"
	echo -e " Vuln Check #: \t${BWhite}${vulns_checked}${Off}"

	echo -e "\n${UWhite} Checking JAR File Misconfigurations ${Off}\n"
	d2j-dex2jar $APK -o apk.jar > /dev/null 2>&1	# create jar file from apk

		######################
		# Check Cert Pinning #
		######################

			echo -e " ${UWhite}Insufficient Certificate Validation${Off}\n"
			check1="$(zipgrep -al ALLOW_ALL_HOSTNAME_VERIFIER apk.jar 2>&1)"
			check2="$(zipgrep -al canAuthenticateAgainstProtectionSpace apk.jar 2>&1)"
			echo -ne " Check ${BWhite}Hostname Verified${Off}: "
			if [ -z "$check1" ]; then
				echo -e "\t\t${BGreen}Not vulnerable${Off}"
			else
				echo -e "\t\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then
					echo -e "ALLOW_ALL_HOSTNAME_VERIFIER found:\n${check1}"
				fi
			fi

			echo -ne " Check ${BWhite}auth in protected space${Off}: "
			if [ -z "$check2" ]; then
				echo -e "\t${BGreen}Not vulnerable${Off}\n"
			else
				echo -e "\t${BRed}Vulnerable ${Off}\n"
				if [ -n "$VERBOSE" ]; then 
					echo "canAuthenticateAgainstProtectionSpace found:\n${check2}"
				fi
			fi

			# Show how to exploit Cert Pinning
			if [ -n "$EXPLOIT" ]; then
				if [ -n "$check1" ]||[ -n "$check2" ]; then
					echo -en " ${BYellow}[+] Exploit Cert Not Validated:${Off}"
					echo -e "\tInstall any valid certificat on device and attempt to capture "
					echo -e "${ANSWER}application traffic. This can be done with a self signed certificate"
					echo -e "${ANSWER}generated by Burp Suite or Bettercatp"
					echo -e "${ANSWER}Install Cert iOS: ${BCyan}https://t.ly/WgJ9${Off}"
					echo -e "${ANSWER}Install Cert Android: ${BCyan}https://t.ly/MpIl${Off}"
					echo gb		-e "${ANSWER}Install Cert Windows Mobile: ${BCyan}https://t.ly/In0K${Off}\n"
				fi
			fi

		###################################
		# Check if application logs stuff #
		###################################

			echo -e " ${UWhite}Checking Logging Enabled${Off}\n"
			check1="$(zipgrep -ali Log.e apk.jar 2>&1)"
			check2="$(zipgrep -ali logger apk.jar 2>&1)"
			echo -ne " Check ${BWhite}Logging Enabled${Off} (Log.e calls): "
			if [ -z "$check1" ]; then
				echo -e "\t${BGreen}Not vulnerable${Off}"
			else
				echo -e "\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then
					echo -e "\n${BWhite}Found Log.e in following files:${Off}\n${check1}"
				fi
			fi
			echo -ne " Check ${BWhite}Logging Enabled${Off} (Logger calls): "
			if [ -z "$check2" ]; then
				echo -e "\t${BGreen}Not vulnerable${Off}"
			else
				echo -e "\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then
					echo -e "\n${BWhite}Found logger in following files:${Off}\n${check1}"
				fi
			fi

			# Show how to exploit logging

			if [ -n "$EXPLOIT" ]; then
				if [ -n "$check1" ]||[ -n "$check2" ]; then
					echo -en " ${BYellow}[+] Exploit Logging Enabled:${Off}"
					echo -e "\t\tLogging can be examined with logcat. This traffic can be captured and"
					echo -e "${ANSWER}examined or paresed while being captured. As an examples:"
					echo -e "${ANSWER}${BCyan}adb logcat -v time | grep '${package_name}'${Off}"
					echo -e "${ANSWER}${BCyan}adb logcat -v time | grep -E \"credit|passw|ssn|social\"${Off}"
					echo -e "${ANSWER}${BCyan}adb logcat -v time > '${app_name}.log'${Off}"
				fi
			fi

		######################################
		# Check application snapshot allowed #
		######################################

		# notes:
			# prevent screen shots with: FLAG_SECURE
			# https://wwws.nightwatchcybersecurity.com/2016/04/13/research-securing-android-applications-from-screen-capture/
			# prevent snapshots with excludeFromRecents
			# onPause() function called just before app goes into background

			echo -ne "\n Check ${BWhite}Snapshots Allowed${Off}: "
			check="$(zipgrep -ali excludeFromRecents=\"true\" apk.jar 2>&1)"
			if [ -n "$check" ]; then
				echo -e "\t\t${BGreen}Not vulnerable${Off}"
			else
				echo -e "\t\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then
					echo -e "${Yellow}excludeFromRecents=\"true\" not found! (Needed to prevent snapshots) ${Off}"
				fi

				# Show how to exploit logging

				if [ -n "$EXPLOIT" ]; then
					echo -en " ${BYellow}[+] Exploit Snapshots Enabled:${Off}"
					echo -e "\t\tNote: Root access required to access Snapshots"
					echo -e "${ANSWER}Open the application to a screen with sensitive info"
					echo -e "${ANSWER}then change to another app or the homescreen. A snapshot"
					echo -e "${ANSWER}will have been created. Verify image is not blank"
					echo -e "${ANSWER}by accessing it. Commands to access images:"
					#echo -e "${ANSWER}${BCyan}adb shell \"su -c 'cp -r /data/system/recent_images /sdcard/'\" && adb pull /sdcard/recent_images && adb shell \"su -c 'rm -r /sdcard/recent_images'\"${Off}"
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'cp -r /data/system/recent_images /sdcard/'\"${Off}"
					echo -e "${ANSWER}${BCyan}adb pull /sdcard/recent_images${Off}" 
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'rm -r /sdcard/recent_images'\"${Off}"
					echo -e "${ANSWER}${BCyan} or "
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'cp -r /data/system_ce/0/snapshots /sdcard/'\"${Off}"
					echo -e "${ANSWER}${BCyan}adb pull /sdcard/snapshots${Off}" 
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'rm -r /sdcard/snapshots'\"${Off}"
					
					#adb shell "su -c 'cp -rf /data/system_ce/0/snapshots /data/local/tmp/ && chmod -R 777 /data/local/tmp/snapshots'" && adb pull /data/local/tmp/snapshots && adb shell "su -c 'rm -r /data/local/tmp/snapshots'"
					echo -e "${ANSWER}${BYellow}Newer versions of Android:"
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'cp -rf /data/system_ce/0/snapshots /data/local/tmp/'\"${Off}"
					echo -e "${ANSWER}${BCyan}chmod -R 777 \"/data/local/tmp/snapshots\"${Off}"
					echo -e "${ANSWER}${BCyan}adb pull \"/data/local/tmp/snapshots\"${Off}"
					echo -e "${ANSWER}${BCyan}adb shell \"su -c 'rm -r /data/local/tmp/snapshots'\"${Off}"
				fi
			fi

	rm apk.jar	# clean up jar file
	
	#########################################################
	# decompile apk file to examin androidManifest.xml file #
	#########################################################

	apktool d $APK -f -o apk > /dev/null 2>&1

	echo -e "\n${UWhite} Checking APK for outdated software versions ${Off}\n"

		###############################
		# Check if app allows backups #
		###############################

		# help solving this problem:
		# https://unix.stackexchange.com/questions/285924/how-to-compare-a-programs-version-in-a-shell-script
		# 

			echo -ne " Checking ${BWhite}Outdated Software Versions${Off}: "

			# Search for outdated libpng versions
			outdated="$(grep -air 'libpng version' apk)"
			if [ -n "$outdated" ]; then 	# true if string not empty
				echo -ne "\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then 	# true if string not empty
					echo "\nThe following libpng versions were identified: "
					echo -e "${ANSWER}${outdated}"
				else
					echo "The following libpng versions were identified: ${outdated}"
				fi

				if [ -n "$EXPLOIT" ]; then
					echo -en "\n ${BYellow}[+] Exploit Outdated Software Versions:${Off}"
				fi
			else
				echo -e "\t${BGreen}Not vulnerable${Off}"
			fi

	echo -e "\n${UWhite} Checking androidManifest.xml For Misconfigurations ${Off}\n"

		###############################
		# Check if app allows backups #
		###############################

			echo -ne " Checking ${BWhite}Backups Allowed${Off}: "
			backup="$(grep 'android:allowBackup="false"' apk/AndroidManifest.xml)"
			if [ -z "$backup" ]; then 	# true if string is empty
				echo -ne "\t\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then 	# true if string not empty
					backup2="$(grep 'android:allowBackup="true"' apk/AndroidManifest.xml)"
					if [ -n "$backup2" ]; then
						echo "android:allowBackup=\"true\" found in apk/AndroidManifest.xml"
					else
						echo "android:allowBackup=\"false\" not explicitly set to prevent backups"
					fi
				else
					echo ""
				fi

				# Show how to exploit backups

				if [ -n "$EXPLOIT" ]; then
					echo -en "\n ${BYellow}[+] Exploit Backups Allowed:${Off}"
					echo -e "\t\tIf backups are allowed it is possible to make a backup without"
					echo -e "${ANSWER}rooting the device. This means any user can make a backup and view files"
					echo -e "${ANSWER}adb used to create backup, then printf to extract backup. Commands to run:"
					echo -e "${ANSWER}${BCyan}adb backup ${package_name}${White} -then-${Off}"
					command='( printf "\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00" ; tail -c +25 backup.ab ) |  tar xfvz -'
					echo -e "${ANSWER}${BCyan}${command}${Off}\n"
				fi
			else
				echo -e "\t\t${BGreen}Not vulnerable${Off}"
			fi

		#################################
		# Check if app allows cleartext #
		#################################

			echo -ne " Checking ${BWhite}Cleartext Allowed${Off}: "
			cleartext="$(grep 'android:usesCleartextTraffic="false"' apk/AndroidManifest.xml)"
			if [ -z "$cleartext" ]; then 	# true if string is empty
				echo -ne "\t\t${BRed}Vulnerable ${Off}"
				if [ -n "$VERBOSE" ]; then 	# true if string not empty
					cleartext2="$(grep 'android:allowBackup="true"' apk/AndroidManifest.xml)"
					if [ -n "$cleartext2" ]; then
						echo "android:usesCleartextTraffic=\"true\" found in apk/AndroidManifest.xml"
					else
						echo "android:usesCleartextTraffic=\"false\" not explicitly set to prevent cleartext"
					fi
				else
					echo ""
				fi

				# Show how to exploit cleartext

				if [ -n "$EXPLOIT" ]; then
					echo -en "\n ${BYellow}[+] Exploit Cleartext Allowed:${Off}"
					echo -e "\t\tIf cleartext is allowed, it may be possible to sniff cleartext traffic"
				fi
			else
				echo -e "\t\t${BGreen}Not vulnerable${Off}"
			fi

		#################################
		# Check if app allows debugging #
		#################################

			echo -ne " Checking ${BWhite}Debugging Enabled${Off}: "
			debug="$(grep 'android:debuggable="true"' apk/AndroidManifest.xml)"
			if [ -n "$debug" ]; then
				echo -en "\t\t${BRed}Vulnerable${Off} "
				if [ -n "$VERBOSE" ]; then 
					echo -e "android:debuggable=\"true\" found in apk/AndroidManifest.xml"
				else
					echo ""
				fi

				# Show how to exploit logging

				if [ -n "$EXPLOIT" ]; then
					echo -en "\n ${BYellow}[+] Exploit Debugging Enable:${Off}"
					echo -e "\t\tIf debugging is enabled, it is possible to login as the application"
					echo -e "${ANSWER}and access the applications directory/files. Root is not needed."
					echo -e "${ANSWER}Example commands to run"
					echo -e "${ANSWER}${BCyan}adb shell run-as ${package_name}${White} -or-${Off}"
					# check which one of these works...
					echo -e "${ANSWER}${BCyan}adb shell run-as ${package_name} tar c ./ > debug.tar && tar -xvf debug.tar --one-top-level${Off}"
					echo -e "${ANSWER}-or-${Off}"
					echo -e "${ANSWER}${BCyan}adb shell exec-out run-as ${package_name} tar c databases/ > databases.tar${Off}"
				fi
			else
				echo -e "\t\t${BGreen}Not vulnerable${Off}"
			fi

		#################################
		# Check for hardcoded pem files #
		#################################

			echo -ne " Checking ${BWhite}hardcoded *.pem files${Off}: "
			debug="$(find  apk/ -name *.pem)"
			if [ -n "$debug" ]; then
				echo -en "\t\t${BRed}Vulnerable${Off} "
				if [ -n "$VERBOSE" ]; then 
					echo -e "found pem file in decompiled apk"
					echo -e "${debug}"
				else
					echo ""
				fi

				# Show how to exploit logging

				if [ -n "$EXPLOIT" ]; then
					echo -en "\n ${BYellow}[+] Exploit Hardcoded PEM File Found:${Off}"
					echo -e "\t\tHard coding encryption keys allows an attacker to unencrypt data"
					echo -e "${ANSWER}access the identified PEM files"
				fi
			else
				echo -e "\t${BGreen}Not vulnerable${Off}"
			fi

	echo -e "\n${UWhite} Check Framework Used To Build Application ${Off}\n"

		#########################################
		# Check if application is using flutter #
		#########################################

			echo -ne " Checking ${BWhite}App built with flutter${Off}: "
			debug="$(find  apk/ -name libflutter.so)"
			if [ -n "$debug" ]; then
				echo -en "\t${BGreen}True${Off} "
				if [ -n "$VERBOSE" ]; then 
					echo -e "This application was built with Google's framework Flutter"
					echo -e "${debug}"
				else
					echo ""
				fi

				# Show how to exploit logging

				if [ -n "$EXPLOIT" ]; then
					echo -en " ${BYellow}[+] Proxying flutter traffic:${Off}"
					echo -e "\t\thttps://play.google.com/store/apps/details?id=org.proxydroid"
					echo -e "${ANSWER}https://blog.funwith.app/posts/proxy-flutter-apps/"
					echo -e "${ANSWER}https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/"
					echo -e "${ANSWER}https://www.horangi.com/blog/a-pentesting-guide-to-intercepting-traffic-from-flutter-apps"
					echo -e "${ANSWER}something useful..."
					echo -e "${ANSWER}# how make system cert from burp cert"
					echo -e "${ANSWER}Burp Suite -> Proxy -> Options -> Import / export CA certificate -> save as 'cacert.der'"
					echo -e "${ANSWER}openssl x509 -inform DER -in cacert.der -out cacert.pem"
					echo -e "${ANSWER}openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1 | xargs -t -I name mv cacert.pem name.0"
					echo -e "${ANSWER}adb push <cert>.0 /sdcard/"
					echo -e "${ANSWER}adb shell"
					echo -e "${ANSWER}su"
					echo -e "${ANSWER}mount -o rw,remount /"
					echo -e "${ANSWER}mv /sdcard/<cert>.0 /system/etc/security/cacerts/"
					echo -e "${ANSWER}chmod 644 /system/etc/security/cacerts/<cert>.0"
					echo -e "${ANSWER}chown root:root /system/etc/security/cacerts/<cert>.0"

				fi
			else
				echo -e "\t${BGreen}Not Using Flutter Proceed Normally${Off}"
			fi

	echo -e "\n${UWhite} Insecure Mobile Device Data Storage ${Off}\n"

		########################################
		# Insecure Mobile Device Data Storage #
		#######################################

			echo -ne " Checking ${BWhite}Device Data Storage${Off}: "
			echo -en "\t\t${BYellow}Requires Manual Check${Off} "

			# Show how to exploit logging

			if [ -n "$EXPLOIT" ]; then
				echo -en "\n ${BYellow}[+] Check device data storage${Off}"
				echo -e "\t\tEnter fake information into the application where possible."
				echo -e "${ANSWER}Save usernames, emails, phone, bank info, etc"
				echo -e "${ANSWER}Store as much informtion as possible inside the application"
				echo -e "${ANSWER} "
				echo -e "${ANSWER}Connect device via OTG USB cable"
				echo -e "${ANSWER}Then download ${package_name} to local dir with the command:"
				echo -e "${ANSWER}${BCyan}adb shell \"su -c 'cp -rf /data/data/${package_name} /data/local/tmp/ && chmod -R 777 /data/local/tmp/${package_name}'\" && adb pull /data/local/tmp/${package_name} && adb shell \"su -c 'rm -r /data/local/tmp/${package_name}'\"${Off}"
				echo -e "${ANSWER} "
				echo -e "${ANSWER}Now you can search ${package_name} for sensitive data"
				echo -e "${ANSWER}Places to find sensitive data include:"
			   	echo -e "${ANSWER}  - Shared Preferences: ./${package_name}/shared_prefs/"
				echo -e "${ANSWER}  - SQLite Databases: ./${package_name}/databases/"
			   	echo -e "${ANSWER}  - Internal Storage"
			   	echo -e "${ANSWER}  - External Storage"
				echo -e "${ANSWER} "
			fi

	echo ""
	rm -rf apk	# delete decompiled apk files

	echo -en "\n ${BYellow}[+] Lets install the app on a device and test it out!${Off}"
	echo -e "\n adb install ${apk_file}"

	echo -e "\n adb push ${apk_file} /data/local/tmp/ && adb shell -t su -c \"pm install -t -r -g /data/local/tmp/${apk_file}\""


else
	echo -e "${BWhite}${APK}${Off}${BRed} File Not Found!${Off}"
fi
