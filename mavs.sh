#! /bin/bash

# Reset
Color_Off='\033[0m'       # Text Reset

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

scriptVersion='1.0'

banner='
                                   ╓
                        ╕         ╒╣╕                     ╣╣╣─    ╦╣╣
                ╓      ║╬         ╣╣╣      ╒             ╣╣╣─  ╒╣╣╩╙╣╬║╣
                ╣╕     ╣╣        ╫╣ ╫╣     ╡  ╔         ╣╣╣   ╦╣╩   ║╣╬
               ╣╣╣    ║╣╣╬      ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣   ╣╣╬    ╞╩
             ╒╣╣╩╣╣╖ ╔╣╬╣╣╕    ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣     ╙╣╣╣╦╗╖
            ╔╣╣╜  ╝╣╣╣╜ ╙╣╣═╩╜║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣          ╠╜╝╣╣╣╣╗╖
          ╓╣╣╩           ╚╣╣ ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖
        ╒╣╣╬╗╗╗           ╚╣╣╖           ╙╣╣╗   ╙╣╣╣╣╩    ╓╣╣╩╙ ║╣             ╙╣╣╣╖
      ╓╣╣╝╜╙╙╙             ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╩    ├╣╣╖    ╬           ╓╓╗╣╣╣╩
                       ╣╣╣╣╣╣╣╣╣╖           ╓╣╣╣╣╣╣╩      ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙
                             └╙╙╨╝╝╝╝╝╝╝╝╝╨╜╜╙╙╙
'
# code from: https://natelandau.com/boilerplate-shell-script-template/

usage() {
  echo -e "${banner}
Please pass a APK file for scanning through either -f or --file 
Usage: $0 [OPTIONS]

 Options:
  -f <file.apk>		Andorid APK file to decompile and run static analysis

"
}

if [ $# -eq 0 ]; then
	usage >&2;
    exit 0
else
	while getopts ":fh" option; do
	  case ${option} in
		f ) APK=$2
			echo -ne "\n"
			info=($(apkinfo $APK 2> /dev/null))
			echo -e " App Name: \t${BWhite}${info[4]}${Color_Off}"
			echo -e " APK File: \t${BWhite}${info[1]}${Color_Off}"
			echo -e " Package Name: \t${BWhite}${info[6]}${Color_Off}"
			echo -e " Version Name: \t${BWhite}${info[9]}${Color_Off}"
			echo -e " Version Code: \t${BWhite}${info[12]}${Color_Off}"

			echo -e "\n${UWhite} Checking JAR File Misconfigurations ${Color_Off}\n"
			d2j-dex2jar $APK -o apk.jar > /dev/null 2>&1	# create jar file from apk

				# Check is SSL is broken 

					echo -n " Checking SSL Pinning (Hostname Verification): "
					location="$(zipgrep -al ALLOW_ALL_HOSTNAME_VERIFIER	apk.jar 2>&1)"
					if [ -z "$location" ]; then
						echo -e "\t${Yellow}ALLOW_ALL_HOSTNAME_VERIFIER not found! Manual texting needed.${Color_Off}"
					else
						echo -ne "\t${BRed}Vulnerable ${Color_Off}"
						echo "ALLOW_ALL_HOSTNAME_VERIFIER found! :-> ${location}"
					fi

					echo -n " Checking SSL Pinning (Hostname Verification): "
					location="$(zipgrep -al canAuthenticateAgainstProtectionSpace apk.jar 2>&1)"
					if [ -z "$location" ]; then
						echo -e "\t${Yellow}canAuthenticateAgainstProtectionSpace not found! Manual texting needed.${Color_Off}"
					else
						echo -ne "\t${BRed}Vulnerable ${Color_Off}"
						echo "canAuthenticateAgainstProtectionSpace found! :-> ${location}"
					fi

				# Check if application logs stuff

				echo -n " Checking app for logging (Log.e calls): "
					location="$(zipgrep -al Log.e apk.jar 2>&1)"
					if [ -z "$location" ]; then
						echo -e "\t${Green}No calls to Log.e found${Color_Off}"
					else
						echo -ne "\t${BRed}Vulnerable ${Color_Off}"
						echo -e "Log.e found! :-> check logs"
						#echo -e " Verify Commands: \n\t${Cyan}adb logcat${Collor_Off}"
						#echo "Log.e found! :-> ${location}" # list all affected files
					fi

			rm apk.jar	# clean up jar file
	
			echo -e "\n${UWhite} Checking androidManifest.xml For Misconfigurations ${Color_Off}\n"
			# decompile apk file to examin androidManifest.xml file
			apktool d $APK -f -o apk > /dev/null 2>&1

				# Check if app allows backups.

					echo -ne " Checking ${BWhite}Backups Allowed:${Color_Off} "
					backup="$(grep 'android:allowBackup="false"' apk/AndroidManifest.xml)"
					if [ -z "$backup" ]; then 	# true if string is empty
						backup="$(grep 'android:allowBackup="true"' apk/AndroidManifest.xml)"
						echo -ne "\t\t${BRed}Vulnerable ${Color_Off}"
						if [ -n "$backup" ]; then
							echo "android:allowBackup=\"true\" found! :-> in apk/AndroidManifest.xml"
						else
							echo "android:allowBackup=\"false\" not explicitly set to prevent backups"
						fi
					else
						echo -e "\t\t${Green}Disabled${Color_Off}"
					fi
				
				# Check if app allows auto backups.

					echo -ne " Checking ${BWhite}Auto Backups Allowed:${Color_Off} "
					backup="$(grep 'android:fullBackupOnly="true"' apk/AndroidManifest.xml)"
					if [ -n "$backup" ]; then
						echo -ne "\t${BRed}Vulnerable ${Color_Off}"
						echo "android:fullBackupOnly=\"true\" found! :-> in apk/AndroidManifest.xml"
					else
						echo -e "\t${Green}Disabled${Color_Off}"
					fi

				# Check if app allows Key/Value backups.

					echo -ne " Checking ${BWhite}Key/Value Backups Allowed:${Color_Off} "
					backup="$(grep 'android:backupAgent="true"' apk/AndroidManifest.xml)"
					if [ -n "$backup" ]; then
						echo -ne "\t${BRed}Vulnerable ${Color_Off}"
						echo "android:backupAgent=\"true\" found! :-> in apk/AndroidManifest.xml"
					else
						echo -e "\t${Green}Disabled${Color_Off}"
					fi

				# Check if app allows debugging.

					echo -ne " Checking ${BWhite}Debugging Enabled:${Color_Off} "
					backup="$(grep 'android:debuggable="true"' apk/AndroidManifest.xml)"
					if [ -n "$backup" ]; then
						echo -ne "\t\t${BRed}Vulnerable ${Color_Off}"
						echo "android:debuggable=\"true\" found! :-> in apk/AndroidManifest.xml"
					else
						echo -e "\t\t${Green}Disabled${Color_Off}"
					fi

			echo ""
            rm -rf apk	# delete decompiled apk files
			;;
		h ) echo "Usage: $0 -f file.apk [-h]"
			;;
		*)
			echo "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
	  esac
	done
fi


