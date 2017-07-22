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
#         ShortcutFixes*.ps1 files
#         PostInstall_ExtraNgen.ps1 files.
#         Any other files you need to explicitly work with.
#
# PRIMARY CUSTOMIZATION:
#    Customize these variables to your needs where it says "Make Modifications HERE".
#      $Installers_x86Hash:
#      $Installers_x64Hash:
#            Entries are OrderedDictionaries one for installation on X86 operating systems, and one for x64. Values are added in pair form key,value.
#            Generally, the key is an Installer File, and command line arguments as the value. 
#            If you are using a 32-bit installer, the x86 and x64 are probably identical, but seperating them into individual variables allows for apps with different installers for x64.
#            The appropriate dictionary will be used depending on the OS bitness.
#            There is specific support for the filenames ending in .MSI, .MSP, .EXE, and .ZIP
#            Add entries in the list in for form:
#                $variablehash.Add('foo.msi','/qn, TRANSFORM="foo.mst"')
#                Note that the value field may also be a comma separated list or arguments (the commas are removed) when it is necessary to separate out arguments as in the case above. This is because PowerShell's Start-Process requires this.
#            In the case of a key ending in .ZIP, the hash value is the folder to extract files onto.
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
#      $FilesToRemove_x86:
#      $FiesToRemove_x64:
#            Entries are a comma separated list of file paths (both directories and files may be listed for removal)
#      $EnvsToRemove_x86:
#      $EnvsToRemove_x64:
#            Entries are a comma separated list of environment variable names, without the $ or %
#      $ServicesToDisable_x86
#      $ServicesToDisable_x64
#            Entries are a comma separated list of services to be disabled.
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
Set_PSWinColors 'Black' 'White' 'PowerShell - SilentInstall.ps1' $false 

# Ensure we are running elevated
SilentInstall_EnsureElevated $PSCommandPath

Set_PSWinSize 80 48 10 10
Set_PSWinColors 'DarkGray' 'White' 'PowerShell - SilentInstall.ps1' $true 

Write-host 'Starting - SilentInstall.ps1'

#If here, we are (now) running as an admin!
#---------------------------------------------------------------------------------


#==================================================================================
#                    MAKE PRIMARY CUSTOMIZATIONS HERE
$Installers_x64Hash.Add( 'xxx_x64.exe', '/S' )
$Installers_x86Hash.Add( 'xxx_.exe', '/S' )

#$Installers_x64Hash.Add( 'xxx_x64.zip', $env:APPDATA )
#$Installers_x86Hash.Add( 'xxx_.zip', $env:APPDATA )

#$CopyFiles_x64Hash.Add( $executingScriptDirectory+'\xxx_x64.dll', 'C:\Program Files\xxx\PlugIns' )
#$CopyFiles_x86Hash.Add( $executingScriptDirectory+'\xxx_x32.dll', 'C:\Program Files\xxx\PlugIns' )
#$CopyFiles_x64Hash.Add( $executingScriptDirectory+'\foo.ini', $env:LOCALAPPDATA+'\xxx' )
#$CopyFiles_x86Hash.Add( $executingScriptDirectory+'\foo.ini', $env:LOCALAPPDATA+'\xxx' )

# note: This file contains output of this script and gets copyied to the base folder for packages by the autosequencer, so
#       you should use the package name as part of name as it will overwrite.
$InstallerLogFile = $InstallerLogFolder+'\Log_xxx.txt'

#$DesktopShortcutsToRemove = "xxx.lnk, yyy.lnk"
#$StartMenuShortcutsToRemove = ""
#$StartMenuFoldersToRemove = ""

#$FilesToRemove_x64 = "'C:\Program Files (x86)\Folder\uninstall.exe', 'C:\Windows\Installers\foo.msi'"
#$FilesToRemove_x86 = "'C:\Program Files\Folder\uninstall.exe', 'C:\Windows\Installers\foo.msi'"

#$EnvsToRemove_x64 = "'ONEDRIVE', 'SOMETHINGELSE'"
#$EnvsToRemove_x86 = "'ONEDRIVE'"

#$ServicesToDisable_x64 = "'Service Name'"
#$ServicesToDisable_x86 = "'Service Name'"

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
#    New_Shortcut "$($env:ProgramData)\Microsoft\Windows\Start Menu\Programs\Folder\App.lnk" "C:\Program Files\installflder\app.exe"
#    Move_Key 'HKLM' 'SOFTWARE\Microsoft\Internet Explorer\Extensions' '{29e5421f-6f05-4a76-938f-d7e5884f23d8}' 'HKCU'
#else
#{
#    New_Shortcut "$($env:ProgramData)\Microsoft\Windows\Start Menu\Programs\Folder\App.lnk" "C:\Windows\Systemre\cmd.exe" -Arguments "/k" -WorkDir "c:\Python36" -Icon "C:\Python36\python.exe"
#    Move_Key 'HKLM' 'SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions' '{29e5421f-6f05-4a76-938f-d7e5884f23d8}' 'HKCU'

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




