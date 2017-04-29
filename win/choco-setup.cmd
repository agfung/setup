:: https://chocolatey.org/docs/installation
@powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

choco upgrade chocolatey

:: will cause reboot
choco install -y vmware-tools

choco install -y 7zip.install
choco install -y adobereader
choco install -y git.install
choco install -y googlechrome
choco install -y jdk8
choco install -y notepadplusplus.install
choco install -y putty.install
choco install -y sysinternals

choco install -y dejavufonts
choco install -y sourcecodepro
choco install -y noto

powercfg -h off

:: https://community.futuremark.com/forum/showthread.php?106691-windows-7-how-do-i-disable-SLEEP-mode-via-command-line
powercfg -change -monitor-timeout-ac 0
powercfg -change -monitor-timeout-dc 0
powercfg -change -disk-timeout-ac 0
powercfg -change -disk-timeout-dc 0
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -hibernate-timeout-dc 0
