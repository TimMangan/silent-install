# SilentInstall.ps1
#
# Copyright 2017 TMurgent Technologies, LLP 
#
#
# PURPOSE:
#    Automates a custom installation of an application.
#    This script can be further modified to add registry settings or add dependencies.
# REQUIREMENTS:
#    The following should all be placed in a folder together.
#         This script, which you customize 
#         SilentInstall_Utilities.ps1
#         Vendor installer files
#         .Reg files for import after installs are completed.
#         Generate_AppCapabilities*.ps1 files.
#         PostInstall_ExtraNgen.ps1 files.
#         Any other files you need to explicitly work with.
#
# PRIMARY CUSTOMIZATION:
#    Customize these variables to your needs where it says "Make Modifications HERE".
#      $Installers_x86Hash:
#      $Installers_x64Hash:
#            Entries added are generally a Installer File as key, and command line arguments as the value. 
#            These are OrderedDictionaries one for installation on X86 operating systems, and one for x64. Values are added in pair form key:value.
#            If you are using a 32-bit installer, the x86 and x64 are probably identical, but seperating them allows for apps with different installers for x64.
#            The appropriate dictionary will be used depending on the OS bitness.
#            There is specific support for the filenames ending in .MSI, .MSP, .EXE, and .ZIP
#            Add entries in the list in for form:
#                $variablehash.Add('foo.msi','/qn, TRANSFORM="foo.mst"')
#                Note that it is necessary to separate out arguments into a list by adding in the commons on the second argument. This is because PowerShell's Start-Process requires this.
#            In the case of a key ending in .ZIP, the hash value is the folder to extract files into.
#      $CopyFiles_x86Hash:
#      $CopyFiles_x64Hash:
#            Entries are a file as key, and destination folder (or name) as value.
#            Note: If there are more than 3 files copying to the same folder, autosequencing is MUCH more efficent if you zip them up and add to the Installers hash.
#      $DesktopShortcutsToRemove:
#            Array of zero or more strings, each is the name (without path) of a shortcut on the desktop to be removed. The name may or may not include the '.lnk'
#            Both the Public and Current users desktop will be searched, after all installers have completed.
#      $StartMenuShortcutsToRemove:
#            Array of zero or more strings, each is the relative path+name of a shortcut on the StartMenu to be removed. The name may or may not include the '.lnk'
#            Both the AllUsers and Current users start menus will be checked, after all installers have completed.
#            The relative path+name should be what follows after "...\Start Menu\Programs\"
#      $StartMenuFolderssToRemove:
#            Array of zero or more strings, each is the relative path+name of a folder on the StartMenu to be removed. 
#            Both the AllUsers and Current users start menus will be checked, after all installers have completed.
#            The relative path+name should be what follows after "...\Start Menu\Programs\"
#      $DoFlushNgen:
#            When set to $true, forces completion of NGEN compilation for .Net apps that might still be in the queue at the end of all installations.
#            You may set to false if not needed.
#
# Hints:
#    The common parameter for an MSI install is '/qn'
#    The common parameter for an MSP patch install is also '/qn'
#    The common parameters for Exe Installers may be:
#       '/s'
#       '/S'
#       '/quiet'
#     You may add additional options, such as '/qn, FOO=1, BAR=2, TRANSFORMS="Transform.mst"'
#
# ADDITIONAL CUSTOMIZATION:
#    In addition to the standard things supported by the utility, you may need to make additional post install changes.
#    These changes should be made near the bottom of this file, where it is marked "MAKE ADDITIONAL CUSTOMIZATIONS AS NEEDED HERE"
#    There are several commented out examples given there.
##########################################################################################################################


#----------------------------------------------------------------------------------
# Standard coding starting here (DO NOT MODIFY)

# Get folder that this PS1 file is in so that we can find files correctly from relative references
$executingScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
# Bring in common utility code
Import-Module $executingScriptDirectory\SilentInstall_Utilities.ps1

Set_PSWinSize 80 48 5 5
Set_PSWinColors 'DarkGray' 'White' 'PowerShell - SilentInstall.ps1' $false 

# Ensure we are running elevated
SilentInstall_EnsureElevated $PSCommandPath

Set_PSWinSIze 48 80 10 10
Set_PSWinColors 'DarkGray' 'White' 'PowerShell - SilentInstall.ps1' $true 

Write-host 'Starting - SilentInstall.ps1'

#If here, we are (now) running as an admin!
#---------------------------------------------------------------------------------


#==================================================================================
#                    MAKE PRIMARY CUSTOMIZATIONS HERE
$Installers_x64Hash.Add( '7z1604-x64.exe', '/S' )
$Installers_x86Hash.Add( '7z1604.exe',     '/S' )

#$Installers_x64Hash.Add( 'xxx_x64.zip', $env:APPDATA )
#$Installers_x86Hash.Add( 'xxx_.zip', $env:APPDATA )

#$CopyFiles_x64Hash.Add( $executingScriptDirectory+'\xxx_x64.dll', 'C:\Program Files\xxx\PlugIns' )
#$CopyFiles_x86Hash.Add( $executingScriptDirectory+'\xxx_x32.dll', 'C:\Program Files\xxx\PlugIns' )

# note: This file contains output of this script and gets copyied to the base folder for packages by the autosequencer, so
#       you should use the package name as part of name as it will overwrite.
$InstallerLogFile = $InstallerLogFolder+'\Log_7Zip.txt'

#$DesktopShortcutsToRemove = "xxx.lnk, yyy.lnk"
$StartMenuShortcutsToRemove = '7-Zip\7-Zip Help'
#$StartMenuFoldersToRemove = ""


$FilesToRemove_x64 = "C:\Program Files\7-Zip\Uninstall.exe"
$FilesToRemove_x86 = "C:\Program Files\7-Zip\Uninstall.exe"

$DoFlushNgen = $true

# Optional msi debug logging, uncomment the next line. You may need to manually copy the msi log file back out!
#SilentInstall_EnableMSIDebugging "voicewarmupx"

#                   end of PRIMARY CUSTOMIZATION area
#=================================================================================


#---------------------------------------------------------------------------------
#                          Main Processing area, do not modify
# This function installs the Hash entries, 
#   This includes:
#        Installers hashes (from variables)
#        CopyFile hashes  (from variables)
#        Reg files discovered the primary install folder
#        Application_Capabilies scripts discovered in the primary install folder
#        Shortcut removals (from variables)
#        File removals (from variables)
#        NGen scripts discovered in the primary install folder.
SilentInstall_PrimaryInstallations
#                         end of Main Processing area
#--------------------------------------------------------------------------------



#========================================================================
#  MAKE ADDITIONAL CUSTOMIZATIONS NOT SUPPORTED BY TOOLING AS NEEDED HERE
#if ([Environment]::Is64BitOperatingSystem -eq $true ) 
#{
#    New-Shortcut "$($env:ProgramData)\Microsoft\Windows\Start Menu\Programs\Folder\App.lnk" "C:\Program Files\installflder\app.exe"
#}
#else
#{
#    New-Shortcut "$($env:ProgramData)\Microsoft\Windows\Start Menu\Programs\Folder\App.lnk" "C:\Program Files (x86)\installfolder\app.exe"
#}
#                   end of ADDITIONAL CUSTOMIZATION AREA
#========================================================================





#---------------------------------------------------------------
#                  Standard wrapup area (DO NOT MODIFY)
#Ngen final flush (Do Not modify)
if ($DoFlushNgen -eq $true) {
    SilentInstall_FlushNGensQueues
}
write-host -ForegroundColor "Green"  "Done."
Start-Sleep 5
#                    end
#---------------------------------------------------------------


