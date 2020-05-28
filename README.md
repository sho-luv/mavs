<p align="center">
<img width="459" alt="notify" src="https://user-images.githubusercontent.com/1679089/83109222-deee5300-a075-11ea-890e-5588f347ce8d.png">

<h4 align="center">Mobile Application Vulnerability Scanner</h4>
<p align="center">
  <a href="https://twitter.com/sho_luv">
  <img src="https://img.shields.io/badge/Twitter-%40sho_luv-blue.svg">
  </a>
</p>


# mavs.sh

This is a shell script to perform static analysis on mobile applications. Currently it only works for android apk files. 

## Required Dependencies
```
apkinfo       # sudo apt-get install apkinfo
d2j-dex2jar   # sudo apt-get install openjdk-7-jre
apktool       # https://ibotpeaches.github.io/Apktool/install/
```

## Usage mavs.sh
```
./mavs.sh 

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

Please pass a APK file for scanning through either -f or --file 
Usage: ../../../mydev/mavs/mavs.sh [OPTIONS]

 Options:
  -f <file.apk>		Andorid APK file to decompile and run static analysis
 

```
## Example Output
<img width="1035" alt="Screen Shot 2020-05-28 at 1 17 24 AM" src="https://user-images.githubusercontent.com/1679089/83118103-c46ea680-a082-11ea-9a0c-0d2d35617f20.png">

