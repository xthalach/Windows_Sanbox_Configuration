REM Modification of mouse click
reg add HKCU\ControlPanel\Mouse\ /v SwapMouseButtons /t REG_SZ /d 1

REM Download Visual Studio Code
curl -L "https://update.code.visualstudio.com/latest/win32-x64-user/stable" --output C:\users\WDAGUtilityAccount\Downloads\vscode.exe
curl -L "https://download.mozilla.org/?product=thunderbird-102.8.0-SSL&os=win64&lang=es-ES" --output C:\users\WDAGUtilityAccount\Downloads\Thunderbird.exe
curl -L "https://portswigger-cdn.net/burp/releases/download?product=community&version=2023.1.3&type=WindowsX64" --output C:\users\WDAGUtilityAccount\Downloads\burpsuite_community_windows-x64_v2023_1_3.exe
curl -L "https://1.eu.dl.wireshark.org/win64/Wireshark-win64-4.0.3.exe" --output C:\users\WDAGUtilityAccount\Downloads\Wireshark-win64-4.0.3.exe
curl -L "https://www.winitor.com/tools/pestudio/current/pestudio.zip" --output C:\users\WDAGUtilityAccount\Documents\pestudio.zip
curl -L "https://kumisystems.dl.sourceforge.net/project/processhacker/processhacker2/processhacker-2.39-setup.exe" --output C:\users\WDAGUtilityAccount\Downloads\processhacker.exe
curl -L "https://download.sysinternals.com/files/ProcessMonitor.zip" --output C:\users\WDAGUtilityAccount\Documents\ProcessMonitor.zip
curl -L "https://www.procdot.com/download/procdot/binaries/procdot_1_22_57_windows.zip" --output C:\users\WDAGUtilityAccount\Documents\procdot.zip
curl -L "https://download.sysinternals.com/files/Autoruns.zip" --output C:\users\WDAGUtilityAccount\Documents\autoruns.zip
curl -L "https://netix.dl.sourceforge.net/project/x64dbg/snapshots/snapshot_2023-03-04_02-26.zip" --output C:\users\WDAGUtilityAccount\Documents\x64dbg.zip
curl -L "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip" --output C:\users\WDAGUtilityAccount\Documents\Ghidra.zip

REM Install and run Visual Studio Code
C:\users\WDAGUtilityAccount\Downloads\vscode.exe /verysilent /suppressmsgboxes
C:\users\WDAGUtilityAccount\Downloads\Thunderbird.exe -ms
C:\users\WDAGUtilityAccount\Downloads\burpsuite_community_windows-x64_v2023_1_3.exe -q 
C:\users\WDAGUtilityAccount\Downloads\Wireshark-win64-4.0.3.exe /S
C:\users\WDAGUtilityAccount\Downloads\processhacker.exe /VERYSILENT
C:\Users\WDAGUtilityAccount\Documents\Windows\ChromeSetup.exe /silent /install

REM Open browser with phishing analising tools 
"C:\Program Files\Google\Chrome\Application\chrome.exe" --new-window https://www.howtogeek.com/437513/what-should-you-do-if-you-receive-a-phishing-email/ https://www.browserling.com/ https://www.phishtool.com/ https://www.virustotal.com/gui/home/search https://urlscan.io/ https://www.talosintelligence.com/ https://ipinfo.io/ https://checkphish.ai/ https://www.abuseipdb.com/ https://mxtoolbox.com/EmailHeaders.aspx https://mha.azurewebsites.net/ https://mailheader.org/ https://any.run/ https://www.hybrid-analysis.com/ https://www.joesandbox.com/#windows https://cuckoo.cert.ee/ https://centralops.net/co/
