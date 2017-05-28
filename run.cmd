mode con cols=80 lines=20
cd "C:\Users\Public\Documents\CustomScript"
start /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\Documents\CustomScript\InstallDependencies.ps1"
REM This CMD is for use by the Microsoft App-V AutoSequencer for launching the installation of prerequisites prior to sequencing of the application.
REM The Autosequencer assumes that a file by this name is included in a folder referenced in the XML configuration, and the AUtoSequencer will copy this file, 
REM along with all others in the same folder to the virtualam machine into the CustomScript folder and then run this cmd file.
REM We are simply using this as a wrapper to get the InstallDependencies.ps1 script launched.