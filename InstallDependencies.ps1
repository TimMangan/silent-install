﻿#InstallDepencies.ps1


#----------------------------------------------------------------------------------
# Standard coding starting here (DO NOT MODIFY)

# Get folder that this PS1 file is in so that we can find files correctly from relative references
$executingScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
# Bring in common utility code
Import-Module $executingScriptDirectory\SilentInstall_Utilities.ps1

Set_PSWinSize 80 48
Set_PSWinColors 'DarkGray' 'White' 'PowerShell - InstallDependencies.ps1' $false 

# Ensure we are running elevated
SilentInstall-EnsureElevated $PSCommandPath

Set_PSWinColors 'DarkGray' 'White' 'PowerShell - InstallDependencies.ps1' $true 

Write-host 'Starting - InstallDependencies.ps1'

#If here, we are (now) running as an admin!
#---------------------------------------------------------------------------------



##########  Install Dependencies (make modifications here) #######################
#
##################################################################################



##########
# Pre installation Ngen Flushing
Write-Host "Flushing NGEN Queues"
SilentInstall-FlushNGensQueues
write-host -ForegroundColor "Green"  "Done."
Sleep 5

