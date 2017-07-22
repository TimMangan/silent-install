#######################################################################################################################
#  SilentInstall_Utilities.ps1
#
#  Attributions: 
#       Original code from TMurgent Technologies, LLP
#       New_Shortcut portion was adapted from https://gallery.technet.microsoft.com/scriptcenter/New-Shortcut-4d6fb3d8
#
# This powershell module consists of a set of functions that are useful as part of a "Silent Installation" framework.
# 
#
#  To use:
#     Import-Module {pathto\}SilentInstall_Utilities.ps1
#     Call SilentInstall_EnsureElevated
#     (Optional) Call Set_PSWinSize
#     (Optional) Call Set_PSWinColors
#     Update variables listed in the Declarations section below
#     (optional) Call SilentInstall_EnableMSIDebugging 
#     Call SilentInstall_PrimaryInstallations
#     Perform additional customizations supported by this module, including but not limited to
#                 (optional) Move_Key 
#                 (optional) New_Shortcut  
#                 (optional) SilentInstall_FixShortcutToCmdBat
#                 (optional) SilentInstall_SaveLogFile 
#     (optional) Call SilentInstall_FlushNGensQueues 
#######################################################################################################################

#--------------------------------------------------------------------------------------------------
# Declarations
#   To simplify the use of this module, it declares a set of variables here that will be 
#   modified by the caller prior to calling the SilentInstall_PrimaryInstallations function.
#   If left null or empty, the actions associated with this item will be skipped. 
$Installers_x64Hash = new-object System.Collections.Specialized.OrderedDictionary
$Installers_x86Hash = new-object System.Collections.Specialized.OrderedDictionary
$CopyFiles_x64Hash = new-object System.Collections.Specialized.OrderedDictionary
$CopyFiles_x86Hash = new-object System.Collections.Specialized.OrderedDictionary
[string[]] $DesktopShortcutsToRemove = ""
[string[]] $StartMenuShortcutsToRemove = ""
[string[]] $StartMenuFoldersToRemove = ""
[string[]] $FilesToRemove_x64 = ""
[string[]] $FilesToRemove_x86 = ""
[string[]] $EnvsToRemove_x64 = ""
[string[]] $EnvsToRemove_x86 = ""
[string[]] $ServicesToDisable_x64 = ""
[string[]] $ServicesToDisable_x86 = ""
$InstallerLogFolder = "c:\Users\Public\Documents\SequencedPackage"
$InstallerLogFile   = "logfile.log"

#--------------------------------------------------------------------------------------------------


#######################################################################################################################
<# 
.SYNOPSIS
SilentInstall_PrimaryInstallations

erforms primary installations specified by pre-established variables and located files.

.Description
Utility to perform the primary installation activity.
This includes:
    Installers hashes (from variables)
    CopyFile hashes  (from variables)
    Reg files discovered the primary install folder
    Application_Capabilies scripts discovered in the primary install folder
    AppPathFixes scripts discovered in the primary install folder
    ShortcutFixes scripts discovered in the primary install folder
    Shortcut removals (from variables)
    File Removals (from variables)
    Environment Variable Removals (from variables)
    Disable Services
    NGen scripts discovered in the primary install folder.

.PARAMETER
None

.EXAMPLE
SilentInstall_PrimaryInstallations

#>
Function SilentInstall_PrimaryInstallations
{
  [CmdletBinding()]
  param()
  Process {
    #---------------------------------------------------------------
    # Make sure folder for log file is present
    if (!(Test-Path -Path $InstallerLogFolder))
    {
        New-Item -ItemType Directory -Path $InstallerLogFolder
    }
    #---------------------------------------------------------------

    #---------------------------------------------------------------
    # Run Installers
    Run_Installers $Installers_x86Hash $Installers_x64Hash 
    #---------------------------------------------------------------

    #---------------------------------------------------------------
    # Run CopyFiles
    Run_CopyFiles $CopyFiles_x86Hash $CopyFiles_x64Hash   
    #---------------------------------------------------------------

    #--------------------------------------------------------------
    # Run located reg files (if any)
    Run_RegFiles $executingScriptDirectory  
    #---------------------------------------------------------------

    #--------------------------------------------------------------
    # Run located Generate_AppCapabilities files (if any)
    Run_AppCapabilitiesFiles $executingScriptDirectory  
    #---------------------------------------------------------------


    #--------------------------------------------------------------
    # Run located Generate_AppPathFixes files (if any)
    Run_AppPathFixesFiles $executingScriptDirectory  
    #---------------------------------------------------------------


    #--------------------------------------------------------------
    # Run located Generate_ShortcutFixes files (if any)
    Run_ShortcutFixesFiles $executingScriptDirectory  
    #---------------------------------------------------------------

    #---------------------------------------------------------------
    # Things like Remove Desktop & StartMenu Shortcuts, and Folders
    foreach ($DesktopShortcutToRemove in $DesktopShortcutsToRemove) 
    { 
        Remove_DesktopShortcut $DesktopShortcutToRemove 
    }
    foreach ($StartMenuShortcutToRemove in $StartMenuShortcutsToRemove) 
    { 
        Remove_StartMenuShortcut $StartMenuShortcutToRemove 
    }
    foreach ($StartMenuFolderToRemove in $StartMenuFoldersToRemove) 
    { 
        Remove_StartMenuFolder $StartMenuFolderToRemove 
    }
    #-------------------------------------------------------------

    #-------------------------------------------------------------
    # Remove listed files
    Run_RemoveFiles $FilesToRemove_x64 $FilesToRemove_x86
    #------------------------------------------------------------


    #-------------------------------------------------------------
    # Remove listed Environment Variables
    Run_RemoveEnvs $EnvsToRemove_x64 $EnvsToRemove_x86
    #------------------------------------------------------------
    

    #-------------------------------------------------------------
    # Disable listed Services
    Run_DisableServices $ServicesToDisable_x64 $ServicesToDisable_x86
    #------------------------------------------------------------


    #------------------------------------------------------------
    # Run located rngen scripts (if any)
    Run_PostInstallNGenScripts $executingScriptDirectory  
    #------------------------------------------------------------
  }
}



#######################################################################################################################
<#
.SYNOPSIS
SilentInstall_EnsureElevated
Checks to see if the script is running elevated, and if not restarts the script requesting the elevation.

.DESCRIPTION
SilentInstall-EnsureElevated is used to make sure that the script was called in an elevated powershell window.
If not, it will restart the script using "runas" with the administrator account.

This will result in a UAC prompt.  But it is faster to right click on a PS1 script and run it this way.

The original call does not return if elevation is needed as that copy of the script is terminated.

.PARAMETER OriginalCmdline
String containing the original command line and arguments, to be run if elevation is needed.
Mandatory string

.PARAMETER SleepSeconds
String containing the number of seconds to keep the old window open if elevation is needed.
Optional string that defaults to 60

.EXAMPLE
SilentInstall_EnsureElevated $PSCommandPath

#>
Function SilentInstall_EnsureElevated
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True, Position=0)]
    [string]$OriginalCmdline,

    [Parameter(Mandatory=$False, Position=1)]
    [string]$SleepSeconds = 60
  )
  Process {
    # Find PowerShell
    ##$psexeX86 = Get_PowerShellx86Path
    $psexeNative = Get_PowerShellNativePath

    # Ensure we are running as an admin, if not relaunch
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() ) 
    if (!$currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) 
    { 
        # User is not an admin and does not have rights to install, so let's elevate (there will be a prompt).
	    (get-host).UI.RawUI.Backgroundcolor="LightGray" 
	    clear-host 
        write-host -ForegroundColor DarkYellow "Notice: Relaunching because PowerShell is NOT running as an Administrator (elevated)."
        Start-Process $psexeNative "-NoProfile -ExecutionPolicy Bypass -File `"$OriginalCmdline`"" -Verb RunAs; 
        Start-Sleep $SleepSeconds; 
        exit 
    }
  }
}

#######################################################################################################################
<#
.SYNOPSIS
SilentInstall_EnableMSIDebugging
Turns on MSI debugging

.DESCRIPTION
Sets registry to ensure that both 32-bit and 64-bit MSI installers will log.
Msiexec will log the activity to files in the user's temp folder by default.

By default, all logging is enabled, otherwise you can specify the logging that you want.
See http://support.microsoft.com/en-us/help/223300/how-to-enable-windows-installer-logging for details on logging
specification.

MSI Debugging may be needed if you installing using MSI based installers and are having issues with the silent 
installation and need to debug the issue.

.PARAMETER LogVals
String configuring logging details.  When not specified it defaults to all known details ("voicewarmupx")
Optional string.

.EXAMPLE
SilentInstall_EnableMSIDebugging 'voicewarmupx'

#>
Function SilentInstall_EnableMSIDebugging
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True, Position=0)]
    [string]$LogVals ="voicewarmupx"
  )
  Process {
    Make_KeyIfNotPresent "HKLM" "Software\Policies\Microsoft\Windows\Installer"
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "Logging" -Value $LogVals


    Make_KeyIfNotPresent "HKLM" "Software\Wow6432Node\Policies\Microsoft\Windows\Installer"
    Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\Installer" -Name "Logging" -Value $LogVals
  }
}


#######################################################################################################################
<#
.SYNOPSIS
SilentInstall_SaveLogFile
Copies output from a saved log file into the pre-established utility log file.

.Description
The utilities establish a central log file, however the caller may run independent commands
and pipe the output to independent log files.  This function may be called to concatenate that
log information into the central log.

This function is also used internally by the utilities.

.PARAMETER logfile2save
String path to log file to be concatenated into the central log file.
mandaroty string

.EXAMPLE
Start-Process -FilePath msiexec -ArgumentList /i, """$installer""", $InstallerFileHash.Value -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
SilentInstall_SaveLogFile redir_error.log 
SilentInstall_SaveLogFile redir_out.log

#>
Function SilentInstall_SaveLogFile
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True, Position=0)]
    [string]$logfile2save 
  )
  Process {
    
    $logheader  =  "------->INSTALLER LOG: "+$logfile2save 
    LogMe_AndDisplay $logheader $InstallerLogFile
    if (Test-Path $logfile2save)
    {
        $l1 = Get-Content $logfile2save
        LogMe_AndDisplay $l1 $InstallerLogFile 
    }
    else
    {
        LogMe_AndDisplay "No such file(s) present. " $InstallerLogFile
    }
    LogMe_AndDisplay "<-------INSTALLER LOG " $InstallerLogFile
  }
}



#######################################################################################################################
<# 
.SYNOPSIS
SilentInstall_FlushNGensQueues
Function to flush the various ngen queues.

.DESCRIPTION
Many installers of .NET apps set up to perform .net compilation optimization in the background in an ngen queue.
This function will force completion so that you have it in your package.  

   NOTE: You should also ensure that this has been done to your base image before the snapshot so that you don't pick 
         up other stuff.

.PARAMETER 
None

.EXAMPLE
SilentInstall_FlushNGensQueues

#>
Function SilentInstall_FlushNGensQueues
{
  [CmdletBinding()]
  param()
  Process {
    Flush_NGensQueues $InstallerLogFile
  }
}


####################################################################################################################### 
<#
.SYNOPSIS
Move_Key
This script is used to move a registry key between hives (e.g: HKLM to HKCU)

.PARAMETER FromHive
Registry Hive to move from.  Example 'HKLM'

.PARAMETER  ParentKey
String for the full name of the parent key without hive

.PARAMETER  RelativeKey
String for the relative name of the key

.PARAMETER ToHive
Registry Hive to move to.  Example 'HKCU'

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Move_Key 'HKLM' 'Software\Wow6432Node\Microsoft\Internet Explorer\Extensions' '{29e5421f-6f05-4a76-938f-d7e5884f23d8}' 'HKCU'

#>
Function Move_Key
{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True, Position=0)]
    [string]$FromHive,
    
    [Parameter(Mandatory=$True, Position=1)]
    [string]$ParentKey,
    
    [Parameter(Mandatory=$True, Position=2)]
    [string]$RelativeKey,
    
    [Parameter(Mandatory=$True, Position=3)]
    [string]$ToHive
  )
  Process {
    LogMe_AndDisplay "Move_Key: $FromHive $ParentKey $RelativeKey $ToHive"  $InstallerLogFile

    if (!($FromHive -eq 'HKLM' -or $FromHive -eq 'HKCU' ))
    {
        LogMe_AndDisplay "$FromHive is not a valid registry hive designation."  $InstallerLogFile
        return
    } 
    if (!($ToHive -eq 'HKLM' -or $ToHive -eq 'HKCU'))
    {
        LogMe_AndDisplay "$ToHive is not a valid registry hive designation."  $InstallerLogFile
        return
    }
    if ($ParentKey.Length -eq 0 -or $RelativeKey.Length -eq 0)
    {
        LogMe_AndDisplay "Parameters -ParentKey or -RelativeKey may not be empty or null." $InstallerLogFil
        return
    }


    if ($ParentKey.StartsWith('\')) { $useParKey = $ParentKey }
    else { $useParKey = "\$ParentKey" }
    if (!($ParentKey.EndsWith('\'))) { $useFullKey = $useParKey+'\' }
    $useFullKey = $useFullkey + $RelativeKey


    $FullFrom = "$FromHive"+':'+$UseFullKey
    $FullTo = "$ToHive"+':'+$UseParKey
    #LogMe_AndDisplay "FullFrom = $FullFrom" $InstallerLogFile
    #LogMe_AndDisplay "FullTo = $FullTo" $InstallerLogFile

    if ( !(Test-Path "$FullTo" )) 
    {
        New-Item -Path "$FullTo" -Force
    }

    Copy-Item -Path "$FullFrom" -Destination "$FullTo"  -Recurse
    Remove-Item -Path "$FullFrom" -Recurse
    #LogMe_AndDisplay "done moving the key" $InstallerLogFile
  }
}



####################################################################################################################### 
<#
.SYNOPSIS
This script is used to create a shortcut.

.DESCRIPTION
This script uses a Com Object to create a shortcut.

.PARAMETER Path
The path to the shortcut file.  .lnk will be appended if not specified.  If the folder name doesn't exist, it will 
be created.

.PARAMETER TargetPath
Full path of the target executable or file. 

.PARAMETER Arguments
Arguments for the executable or file. 

.PARAMETER Description
Description of the shortcut. 

.PARAMETER HotKey
Hotkey combination for the shortcut.  Valid values are SHIFT+F7, ALT+CTRL+9, etc.  An invalid entry will cause the  
function to fail. 

.PARAMETER WorkDir
Working directory of the application.  An invalid directory can be specified, but invoking the application from the  
shortcut could fail. 

.PARAMETER WindowStyle
Windows style of the application, Normal (1), Maximized (3), or Minimized (7).  Invalid entries will result in Normal 
behavior. 

.PARAMETER Icon
Full path of the icon file.  Executables, DLLs, etc with multiple icons need the number of the icon to be specified,  
otherwise the first icon will be used, i.e.:  c:\windows\system32\shell32.dll,99 

.PARAMETER admin 
Used to create a shortcut that prompts for admin credentials when invoked, equivalent to specifying runas. 

.NOTES
Author       : Rhys Edwards 
Email        : powershell@nolimit.to   

.INPUTS
Strings and Integer 

.OUTPUTS
True or False, and a shortcut 

.LINK
Adapted from https://gallery.technet.microsoft.com/scriptcenter/New-Shortcut-4d6fb3d8  

.EXAMPLE
New_Shortcut -Path c:\temp\notepad.lnk -TargetPath c:\windows\notepad.exe     
Creates a simple shortcut to Notepad at c:\temp\notepad.lnk 

.EXAMPLE
New_Shortcut "$($env:Public)\Desktop\Notepad" c:\windows\notepad.exe -WindowStyle 3 -admin 
Creates a shortcut named Notepad.lnk on the Public desktop to notepad.exe that launches maximized after prompting for  
admin credentials. 

.EXAMPLE
New_Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe -icon "c:\windows\system32\shell32.dll,99" 
Creates a shortcut named Notepad.lnk on the user`s desktop to notepad.exe that has a pointy finger icon (on Windows 7). 

.EXAMPLE
New_Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe C:\instructions.txt 
Creates a shortcut named Notepad.lnk on the user`s desktop to notepad.exe that opens C:\instructions.txt  

.EXAMPLE
New_Shortcut "$($env:USERPROFILE)\Desktop\ADUC" %SystemRoot%\system32\dsa.msc -admin  
Creates a shortcut named ADUC.lnk on the user`s desktop to Active Directory Users and Computers that launches after  
prompting for admin credentials 

#>
Function New_Shortcut
{
  [CmdletBinding()] 
  param( 
    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=0)]  
    [Alias("File","Shortcut")]  
    [string]$Path, 
 
    [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=1)]  
    [Alias("Target")]  
    [string]$TargetPath, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=2)]  
    [Alias("Args","Argument")]  
    [string]$Arguments, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=3)]   
    [Alias("Desc")] 
    [string]$Description, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=4)]   
    [string]$HotKey, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=5)]   
    [Alias("WorkingDirectory","WorkingDir")] 
    [string]$WorkDir, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=6)]   
    [int]$WindowStyle, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True,Position=7)]   
    [string]$Icon, 
 
    [Parameter(ValueFromPipelineByPropertyName=$True)]   
    [switch]$admin 
  ) 
 
  Process 
  { 
 
    If (!($Path -match "^.*(\.lnk)$")) 
    { 
        $Path = "$Path`.lnk" 
    } 
    [System.IO.FileInfo]$Path = $Path 
    Try 
    { 
        If (!(Test-Path $Path.DirectoryName)) 
        { 
            mkdir $Path.DirectoryName -ErrorAction Stop | Out-Null 
        } 
    } 
    Catch 
    { 
        Write-Verbose "Unable to create $($Path.DirectoryName), shortcut cannot be created" 
        Return $false 
        Break 
    } 
 
 
    # Define Shortcut Properties 
    $WshShell = New-Object -ComObject WScript.Shell 
    $Shortcut = $WshShell.CreateShortcut($Path.FullName) 
    $Shortcut.TargetPath = $TargetPath 
    $Shortcut.Arguments = $Arguments 
    $Shortcut.Description = $Description 
    $Shortcut.HotKey = $HotKey 
    $Shortcut.WorkingDirectory = $WorkDir 
    $Shortcut.WindowStyle = $WindowStyle 
    If ($Icon)
    { 
        $Shortcut.IconLocation = $Icon 
    } 
 
    Try 
    { 
        # Create Shortcut 
        $Shortcut.Save() 
        # Set Shortcut to Run Elevated 
        If ($admin) 
        {      
            $TempFileName = [IO.Path]::GetRandomFileName() 
            $TempFile = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName) 
            $Writer = New-Object System.IO.FileStream $TempFile, ([System.IO.FileMode]::Create) 
            $Reader = $Path.OpenRead() 
            While ($Reader.Position -lt $Reader.Length) 
            { 
                $Byte = $Reader.ReadByte() 
                If ($Reader.Position -eq 22) 
                {
                    $Byte = 34
                } 
                $Writer.WriteByte($Byte) 
            } 
            $Reader.Close() 
            $Writer.Close() 
            $Path.Delete() 
            Rename-Item -Path $TempFile -NewName $Path.Name | Out-Null 
        } 
        Return $True 
    } 
    Catch 
    { 
        Write-Verbose "Unable to create $($Path.FullName)" 
        Write-Verbose $Error[0].Exception.Message 
        Return $False 
    } 
  } 
} 



#######################################################################################################################
<#
.SYNOPSIS
SilentInstall_FixShortcutToCmdBat
Modified a .lnk file with target of Bat or CMD to point to cmd.exe with /c to file.

.DESCRIPTION
Some instllers add shortcuts to BAT or CMD files, and these don't work in App-V.  This function will
modify the shortcut to call cmd.exe /c BatOrCmdFile and any additional arguments (normally none). 

.PARAMETER LinkPath
The fully qualified path to the .lnk file to adjust.

.PARAMETER InstallerLogFile
Full path to a log file to generate/append to.

#>
function SilentInstall_FixShortcutToCmdBat {
  [CmdletBinding()] 
  param( 
    [Parameter(Mandatory=$True, Position=0)]
    [string] $LinkPath = $null,
    [Parameter(Mandatory=$True, Position=1)]  
    [string]$InstallerLogFile
  )
  Process
  {
      LogMe_AndDisplay "Editing Shortcut: $LinkPath" $InstallerLogFile 
    $obj = New-Object -ComObject WScript.Shell
    $link = $obj.CreateShortcut($LinkPath)
    if ($link) 
    {
        $tmp = "Oringial Shortcut found with target " + $link.TargetPath + " and Arguments " + $link.Arguments
        LogMe_AndDisplay "$tmp" $InstallerLogFile 
        $wdir = ($link.TargetPath).Replace("\"+(Split-Path ($link.TargetPath) -Leaf),"")
        $link.Arguments = "-c '" + $link.TargetPath + "' " + $link.Arguments
        $link.TargetPath = 'C:\Windows\System32\cmd.exe'
        $link.WorkingDirectory = $wdir
        $link.Save()
        $tmp = "Saved new shortcut with target " + $link.TargetPath + " and Arguments " + $link.Arguments
        LogMe_AndDisplay "$tmp" $InstallerLogFile 
    }
    else
    {
        LogMe_AndDisplay "Failed to find shortcut file."  $InstallerLogFile 
    }
  }
}




#######################################################################################################################
<#
.SYNOPSIS
Funtion to sets the powershell window size and optionaly position

.DESCRIPTION
This utility may be used to set the size and position of the powershell window.

.PARAMETER MaxWidth   
Mandatory int
Width of the window, in columns.

.PARAMETER MaxHeight
Mandatory int
Height of the window, in rows.

.PARAMETER PosX
Optional int
Left position on the screen in pixels, if both PosX and PosY are specified.

.PARAMETER PosY
Optional int
Top position on the screen in picels, if both PosX and PosY are specified.

#>  
Function Set_PSWinSize
{ 
  [CmdletBinding()] 
  param( 
    [Parameter(Mandatory=$True, Position=0)]  
    [int]$MaxWidth,
    [Parameter(Mandatory=$True, Position=1)]  
    [int]$MaxHeight,
    [Parameter(Mandatory=$False, Position=2)]  
    [int]$PosX = (0),
    [Parameter(Mandatory=$False, Position=3)]  
    [int]$PosY = (0)
  )
  Process 
  {     
    if ($Host.Name -match "console") 
    { 
        $MyWindowSize = $Host.UI.RawUI.WindowSize 
        $MyWindowSize.Height = ($MaxHeight) 
        $MyWindowSize.Width = ($Maxwidth)

        $host.UI.RawUI.set_windowSize($MyWindowSize)
        if ($PosX -gt 0 -and $PosY -gt 0)
        {
            $MyWindowPos = $Host.UI.RawUI.WindowPosition
            $MyWindowPos.X = ($PosX)
            $MyWindowPos.Y = ($PosY)
            $host.UI.RawUI.set_windowPosition($MyWindowPos)
        } 
    } 
  }
}


#######################################################################################################################
<#
.SYNOPSIS
Set_PSWinColors
A function to set powershell colors and window title

.DESCRIPTION
This function sets the background and foreground color of the current powershell window. It also sets the window
title, and clears the screen.

The requested window title in enhanced with the following infomration:
    Elevation
    Username
    DateStamp

.PARAMETER Background
Mandatory string Parameter 
Color for the background of the powershell window.

.PARAMETER Foreground
Mandatory string Parameter 
Color for text in the powershell window.

.PARAMETER WinTitle
Mandatory string Parameter
Title string for the window.  This will be "enhanced".

.PARAMETER Elevated
Mandatory bool Parameter
Indicates if the window is elevated.  This will be indicated in the enhanced title.

.EXAMPLE
Set_PSWinColors 'Black' 'White' "My purpose" $True

#>
function Set_PSWinColors
{
  [CmdletBinding()] 
  param( 
    [Parameter(Mandatory=$True, Position=0)]  
    [string]$Background,
    [Parameter(Mandatory=$True, Position=1)]  
    [string]$Foreground,
    [Parameter(Mandatory=$True, Position=2)]  
    [string]$WinTitle,
    [Parameter(Mandatory=$True, Position=3)]  
    [bool]$Elevated
  )
  Process 
  {         
        $host.ui.RawUI.BackgroundColor = $Background
        $host.ui.RawUI.ForegroundColor = $Foreground
        Clear-Host

        If ($Elevated)
        {
            $Elevatedstr = "[Elevated]"
        }
        else
        {
            $Elevatedstr = ""   
        }
        $Title = $Elevatedstr + " $ENV:USERNAME".ToUpper() + ": $($Host.Name) " + " - " + (Get-Date).toshortdatestring() + $WinTitle  
        $Host.UI.RawUI.set_WindowTitle($Title) 
  }
} 


#------------ The remaining functions are intended for internal consumption only --------------------------------------



###################################################################################################
# Function to run the installers list (OrderedDictionary) as appropriate for the bitness of the OS
#
# The OrderedDictionaries have entries as follows:
#     Hash Name: Path to Installer 
#     Hash Value: Paramaters
#
# Several types of installers are understood:
#      .ZIP:  The zip file is extracted to the file folder listed in the hash value.
#      .MSI:  MSIEXEC is run with -I and the MSI filename with parameters.
#      .MSP:  MSIEXEC is run with -P and the MSP filename with parameters.
#      else:  The named file is run with parameters.
#
# Except for Zip, individual arguments must be seperated by commas, as in:
#            /qn, INSTALLFOLDER="C:\foo"
#
# The x64 list is run on x64 OSs, the x86 on 32-bit OS.
Function Run_Installers(
    [System.Collections.Specialized.OrderedDictionary] $Installers_x86Hash, 
    [System.Collections.Specialized.OrderedDictionary] $Installers_x64Hash)
{
    LogMe_AndDisplay "Starting installations." $InstallerLogFile 
    $psexeNative = Get_PowerShellNativePath
    $InstallerFiles_Hash = New-Object System.Collections.Specialized.OrderedDictionary
    if ([Environment]::Is64BitOperatingSystem -eq $true ) 
    { 
        $InstallerFiles_Hash = $Installers_x64Hash 
    }
    else 
    { 
        $InstallerFiles_Hash = $Installers_x86Hash 
    }

    foreach ($InstallerFileHash in $InstallerFiles_Hash.GetEnumerator()) 
    {
        $tmpNoWait = $false
        if ($InstallerFileHash.Key.Contains(':\'))
        {
            $installer = $InstallerFileHash.Key
            if ($installer.StartsWith('-')) 
            { 
                #Used to solve issue with Paint.Net installer that rolls back using the normal method for an unknown reason.
                $installer = $installer.Substring(1) 
                $tmpNoWait = $true;        
            }
        }
        else
        {
            $installer = $executingScriptDirectory + '\' + $InstallerFileHash.Key
            if ($InstallerFileHash.Key.StartsWith('-')) 
            { 
                #Used to solve issue with Paint.Net installer that rolls back using the normal method for an unknown reason.
                $installer =$executingScriptDirectory + '\' + $InstallerFileHash.Key.Substring(1)         
                $tmpNoWait = $true;        
            }
        }

        if ($installer.ToLower().EndsWith(".msi")) 
        { 
            $log = '    running process -FilePath msiexec -ArgumentList /i, '+$installer+', '+$InstallerFileHash.Value+' -Wait'
            LogMe_AndDisplay $log   $InstallerLogFile 
            Start-Process -FilePath msiexec -ArgumentList /i, """$installer""", $InstallerFileHash.Value -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile  
        }
        elseif ($installer.ToLower().EndsWith(".msp")) 
        {
            $log = '    running process -FilePath msiexec -ArgumentList /update, '+$installer+', '+$InstallerFileHash.Value+' -Wait'  
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -FilePath msiexec -ArgumentList /update, """$installer""", $InstallerFileHash.Value -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile       
        }
        elseif ($installer.ToLower().EndsWith(".zip"))
        {
            $log = '    extracting files from '+$installer+' to '+$InstallerFileHash.Value
            LogMe_AndDisplay $log $InstallerLogFile
            Add-Type -AssemblyName "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory($installer,$InstallerFileHash.Value) 
        }
        elseif ($installer.ToLower().EndsWith(".ps1")) 
        {
            $log = '    running process -FilePath ' +$psexeNative+ ' -ArgumentList -NoProfile, -ExecutionPolicy, Bypass, -File '+$installer+', '+$InstallerFileHash.Value+' -Wait'  
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$installer""",  $InstallerFileHash.Value -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile       
        }
        else
        {
            if ($tmpNoWait)
            { 
                #Used to solve issue with Paint.Net installer that rolls back using the normal method for an unknown reason.
                $xx = '/c '+$installer+' '+$InstallerFileHash.Value 
                $log = '    running c:\windows\system32\cmd.exe ' + $xx 
                LogMe_AndDisplay $log $InstallerLogFile
                c:\windows\system32\cmd.exe $xx
                Start-Sleep 90
            }
            else
            {
                $log = '    running process -FilePath '+"""$installer"""+' -ArgumentList '+$InstallerFileHash.Value+' -Wait' 
                LogMe_AndDisplay $log $InstallerLogFile
                Start-Process  -FilePath """$installer""" -ArgumentList $InstallerFileHash.Value   -Wait   -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log -LoadUserProfile 
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile $false $true
            } 
        }
    }
    LogMe_AndDisplay "Installations Completed." $InstallerLogFile
}


###################################################################################################
# Function to copy files from the copy list
#
# The OrderedDictionaries have entries as follows:
#     Hash Name: Path to source file 
#     Hash Value: Path to destination folder
#
# The x64 list is processed on x64 OSs, the x86 on 32-bit OS.
function Run_CopyFiles(
    [System.Collections.Specialized.OrderedDictionary] $CopyFiles_x86Hash, 
    [System.Collections.Specialized.OrderedDictionary] $CopyFiles_x64Hash)
{
    LogMe_AndDisplay "Starting CopyFiles."  $InstallerLogFile
    $CopyFiles_Hash = New-Object System.Collections.Specialized.OrderedDictionary
    if ([Environment]::Is64BitOperatingSystem -eq $true ) 
    { 
        $CopyFiles_Hash = $CopyFiles_x64Hash 
    }
    else 
    { 
        $CopyFiles_Hash = $CopyFiles_x86Hash 
    }

    foreach ($CopyFileHash in $CopyFiles_Hash.GetEnumerator()) 
    {
        $log = 'Adding '+$CopyFileHash.Key+' to folder '+$CopyFileHash.Value 
        LogMe_AndDisplay $log $InstallerLogFile

        if (!(Test-Path $CopyFileHash.Value))
        {
            $err1 = new-item -ItemType Directory -Force $CopyFileHash.Value
            $serr1 = "Create Directory "+$CopyFileHash.Value+": "+$err1
            LogMe_AndDisplay $serr1 $InstallerLogFile
        } 
        $err = Copy-Item  $CopyFileHash.Key -Destination $CopyFileHash.Value *>&1
        $serr = "Copy file result: "+$err 
        LogMe_AndDisplay $serr  $InstallerLogFile 
    }
    LogMe_AndDisplay "CopyFiles Completed." $InstallerLogFile 
}


###################################################################################################
# Function to find/run reg imports
#    This will find all .reg files in the given folder
#    Those whose base names end in x86 or x64 will only be run on the same bitness as the OS,
#    All others will just be run.
#    No control over the order of running is provided.
function Run_RegFiles([string]$executingScriptDirectory)
{
    LogMe_AndDisplay "Starting any registration imports." $InstallerLogFile 
    $cnt = 0
    #---------------------------------------------------------------
    #Look for a .reg file to import
    Get-ChildItem $executingScriptDirectory | Where-Object { $_.Extension -eq '.reg' } | ForEach-Object {
        if ($_.FullName -like "*x64.reg") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $true) 
            {
                $log = '    importing for x64 '+ $_.FullName
                LogMe_AndDisplay $log $InstallerLogFile 
                reg import $_.FullName
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*x86.reg") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $false) 
            {
                $log =  '    importing for x86 '+ $_.FullName 
                LogMe_AndDisplay $log $InstallerLogFile 
                reg import $_.FullName
                $cnt = $cnt + 1
            }
        }
        else 
        {
            $log = '    importing '+$_.FullName  
            LogMe_AndDisplay $log $InstallerLogFile
            reg import $_.FullName
                $cnt = $cnt + 1
        }
    }
    if ($cnt -eq 0) 
    { 
        LogMe_AndDisplay "    No valid registry files were located."  $InstallerLogFile 
    }
    LogMe_AndDisplay "Registration imports complete." $InstallerLogFile 
}



###################################################################################################
# Function to find/run Post-Install Application Capabilities script files
#    This will find all ps1 files with names matchine "*Generate_AppCapabilities*" in the given 
#    folder.
#    Those whose base names end in x86 or x64 will only be run on the same bitness as the OS,
#    All others will just be run.
#    No control over the order of running is provided.
function Run_AppCapabilitiesFiles([string]$executingScriptDirectory)
{

    LogMe_AndDisplay "Starting any Post-Install App Capabilities scripts." $InstallerLogFile 
    $cnt = 0
    $psexeNative = Get_PowerShellNativePath
    #---------------------------------------------------------------
    #Look for a .ps1 file to import
    Get-ChildItem $executingScriptDirectory | Where-Object { $_.Extension.ToLower() -eq '.ps1' } | ForEach-Object {
        $xtmp = $_.FullName
        if ($_.FullName -like "*Generate_AppCapabilities_x64.ps1" -or
            $_.FullName -like "*x64OSGenerate_AppCapabilities.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $true) 
            {
                $log = '    running script for x64 '+ $xtmp
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_AppCapabilities_x86.ps1" -or
                $_.FullName -like "*x86OSGenerate_AppCapabilities.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $false) 
            {
                $log = '    running script for x86 '+ $xtmp 
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_AppCapabilities.ps1") 
        {
            $log = '    running script '+ $xtmp 
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
            $cnt = $cnt + 1
        }
    }
    if ($cnt -eq 0) 
    { 
        LogMe_AndDisplay "    No valid ps1 files were located."  $InstallerLogFile 
    }
    LogMe_AndDisplay "Post-Install App Capabilities scripts complete." $InstallerLogFile  
}



###################################################################################################
# Function to find/run Post-Install Application AppPathFixes script files
#    This will find all ps1 files with names matchine "*Generate_AppCapabilities*" in the given 
#    folder.
#    Those whose base names end in x86 or x64 will only be run on the same bitness as the OS,
#    All others will just be run.
#    No control over the order of running is provided.
function Run_AppPathFixesFiles([string]$executingScriptDirectory)
{

    LogMe_AndDisplay "Starting any Post-Install App Path Fixes scripts." $InstallerLogFile 
    $cnt = 0
    $psexeNative = Get_PowerShellNativePath
    #---------------------------------------------------------------
    #Look for a .ps1 file to import
    Get-ChildItem $executingScriptDirectory | Where-Object { $_.Extension.ToLower() -eq '.ps1' } | ForEach-Object {
        $xtmp = $_.FullName
        if ($_.FullName -like "*Generate_AppPathFixes_x64.ps1" -or
            $_.FullName -like "*x64OSGenerate_AppPathFixes.ps1" ) 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $true) 
            {
                $log = '    running script for x64 '+ $xtmp
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_AppPathFixes_x86.ps1" -or
                $_.FullName -like "*x86OSGenerate_AppPathFixes.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $false) 
            {
                $log = '    running script for x86 '+ $xtmp 
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_AppPathFixes.ps1") 
        {
            $log = '    running script '+ $xtmp 
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
            $cnt = $cnt + 1
        }
    }
    if ($cnt -eq 0) 
    { 
        LogMe_AndDisplay "    No valid ps1 files were located."  $InstallerLogFile 
    }
    LogMe_AndDisplay "Post-Install App Path Fixes scripts complete." $InstallerLogFile  
}




###################################################################################################
# Function to find/run Post-Install Shortcut Fixus script files
#    This will find all ps1 files with names matchine "*Generate_ShortcutFixes" in the given 
#    folder.
#    Those whose base names end in x86 or x64 will only be run on the same bitness as the OS,
#    All others will just be run.
#    No control over the order of running is provided.
function Run_ShortcutFixesFiles([string]$executingScriptDirectory)
{

    LogMe_AndDisplay "Starting any Post-Install Shortcut Fixup scripts." $InstallerLogFile 
    $cnt = 0
    $psexeNative = Get_PowerShellNativePath
    #---------------------------------------------------------------
    #Look for a .ps1 file to import
    Get-ChildItem $executingScriptDirectory | Where-Object { $_.Extension.ToLower() -eq '.ps1' } | ForEach-Object {
        $xtmp = $_.FullName
        if ($_.FullName -like "*Generate_ShortcutFixes_x64.ps1" -or
            $_.FullName -like "*x64OSGenerate_ShortcutFixes.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $true) 
            {
                $log = '    running script for x64 '+ $xtmp
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_ShortcutFixes_x86.ps1" -or
                $_.FullName -like "*x86OSGenerate_ShortcutFixes.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $false) 
            {
                $log = '    running script for x86 '+ $xtmp 
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
                $cnt = $cnt + 1
            }
        }
        elseif ($_.FullName -like "*Generate_ShortcutFixes.ps1") 
        {
            $log = '    running script '+ $xtmp 
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""   -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile 
            $cnt = $cnt + 1
        }
    }
    if ($cnt -eq 0) 
    { 
        LogMe_AndDisplay "    No valid ps1 files were located."  $InstallerLogFile 
    }
    LogMe_AndDisplay "Post-Install Shortcut Fixess scripts complete." $InstallerLogFile  
}



###################################################################################################
# Function to remove a desktop shortcut link file, if present
# Input is just the name of the shortcut, with or without the .lnk extension.
function Remove_DesktopShortcut([string]$ShortcutName)
{
    if ($ShortcutName.Length -gt 0)
    {
        LogMe_AndDisplay 'Removing Desktop Shortcuts Links' $InstallerLogFile
        $shortcutnamewithlnk = $ShortcutName
        if ( !($ShortcutName -like "*.lnk")) {  $shortcutnamewithlnk = $ShortcutName + '.lnk' }
        #LogMe_AndDisplay 'effective name to match = $shortcutnamewithlnk' $InstallerLogFile

        $testpublicdesktop = $env:PUBLIC + '\Desktop'
        $testuserdesktop =  $env:USERPROFILE + '\Desktop'
    
        Get-ChildItem $testpublicdesktop | Where-Object { $_.Extension -eq '.lnk' } | ForEach-Object {
            #LogMe_AndDisplay 'Checking $_'  $InstallerLogFile
            if ($_.Name -eq $shortcutnamewithlnk ) 
            { 
                $log =  '    Removing '+ $_FullName 
                LogMe_AndDisplay $log $InstallerLogFile
                $err = Remove-Item $_.FullName *>&1
                LogMe_AndDisplay $err  $InstallerLogFile
            }
        }
    
        Get-ChildItem  $testuserdesktop | Where-Object { $_.Extension -eq '.lnk' } | ForEach-Object {
            #write-host 'checking' $_ '.name=' $_.Name 
            if ($_.Name -eq $shortcutnamewithlnk  ) 
            { 
                $log = '    Removing'+$_.FullName  
                LogMe_AndDisplay $log $InstallerLogFile
                $err = Remove-Item $_.FullName *>&1
                LogMe_AndDisplay $err  $InstallerLogFile
            }
        }
        LogMe_AndDisplay 'Desktop Shortcut Link removals complete.' $InstallerLogFile 
    }
}



###################################################################################################
# Function to remove a startmenu shortcut link file, if present
# Input is just the name of the shortcut, relative from 'start menu\Programs\', with or without 
# the .lnk extension.
function Remove_StartMenuShortcut([string]$RelativeName)
{
    if ($RelativeName.Length -gt 0)
    {
        LogMe_AndDisplay 'Removing StartMenu Shortcuts Links' $InstallerLogFile
        $relativenamewithlnk = $RelativeName
        if ( !($RelativeName -like "*.lnk")) {  $relativenamewithlnk = $RelativeName + '.lnk' }
        LogMe_AndDisplay "    Effective name to match =  $relativenamewithlnk " $InstallerLogFile

        $testpublicstartmenu = $env:ALLUSERSPROFILE + '\Microsoft\Windows\Start Menu\Programs\' + $relativenamewithlnk
        $testuserstartmenu   = $env:APPDATA +  '\Microsoft\Windows\Start Menu\Programs\' + $relativenamewithlnk

        if (Test-Path -Path $testpublicstartmenu ) 
        { 
            $log = '    Removing '+ $testpublicstartmenu 
            LogMe_AndDisplay $log $InstallerLogFile 
            $err = Remove-Item $testpublicstartmenu *>&1
            LogMe_AndDisplay $err  $InstallerLogFile
        }
        #else { LogMe_AndDisplay "    No such $testpublicstartmenu " $InstallerLogFile }
        if (Test-Path -Path $testuserstartmenu ) 
        { 
            $log = '    Removing '+$testuserstartmenu 
            LogMe_AndDisplay $log $InstallerLogFile 
            $err = Remove-Item $testuserstartmenu *>&1
            LogMe_AndDisplay $err  $InstallerLogFile
        }
        #else { LogMe_AndDisplay "    No such $testuserstartmenu " $InstallerLogFile }
        LogMe_AndDisplay 'StartMenu Shortcut Link removals complete.' $InstallerLogFile
    }
}



###################################################################################################
# Function to remove a startmenu shortcut folder, if present
# Input is just the name of the shortcut folder, relative from 'start menu\Programs\'
function Remove_StartMenuFolder([string]$FolderName)
{
    if ($FolderName.Length -gt 0)
    {
        LogMe_AndDisplay 'Removing StartMenu Folders' $InstallerLogFile
        $testpublicstartmenu = $env:ALLUSERSPROFILE + '\Microsoft\Windows\Start Menu\Programs\' + $FolderName
        $testuserstartmenu   = $env:APPDATA +  '\Microsoft\Windows\Start Menu\Programs\' + $FolderName

        if (Test-Path -Path $testpublicstartmenu ) 
        { 
            $log = '    Removing '+$testpublicstartmenu 
            LogMe_AndDisplay $log $InstallerLogFile 
            $err = Remove-Item -Force -Recurse $testpublicstartmenu  *>&1
            LogMe_AndDisplay $err  $InstallerLogFile
        }
        if (Test-Path -Path $testuserstartmenu ) 
        { 
            $log = '    Removing '+$testuserstartmenu 
            LogMe_AndDisplay $log $InstallerLogFile
            $err = Remove-Item -Force -Recurse $testuserstartmenu  *>&1
            LogMe_AndDisplay $err  $InstallerLogFile
        }
        LogMe_AndDisplay 'StartMenu Folder removals complete.' $InstallerLogFile
    }
}



###################################################################################################
# Function to remove listed files and folders
function Run_RemoveFiles(
                        [string[]]$FilesToRemove_x64,
                        [string[]]$FilesToRemove_x86)
{
    LogMe_AndDisplay "Starting RemoveFiles."  $InstallerLogFile
    if ([Environment]::Is64BitOperatingSystem -eq $true ) 
    {
        foreach ($RemFile in $FilesToRemove_x64)
        {
            if ($RemFile.Length -gt 0)
            {
                $log = '    Removing ' + $RemFile
                LogMe_AndDisplay $log $InstallerLogFile
                $err = Remove-Item -Force -Recurse $RemFile *>&1
                LogMe_AndDisplay $err  $InstallerLogFile
            }
        }
    }
    else 
    {
        foreach ($RemFile in $FilesToRemove_x86)
        {
            if ($RemFile.Length -gt 0)
            {
                $log = '    Removing ' + $RemFile
                LogMe_AndDisplay $log $InstallerLogFile
                $err = Remove-Item -Force -Recurse $RemFile *>&1
                LogMe_AndDisplay $err  $InstallerLogFile
            }
        }
    }
    LogMe_AndDisplay "RemoveFiles Completed." $InstallerLogFile 
}



###################################################################################################
# Function to remove listed Environment Variables
function Run_RemoveEnvs(
                        [string[]]$EnvsToRemove_x64,
                        [string[]]$EnvsToRemove_x86)
{
    LogMe_AndDisplay "Starting RemoveEnvs."  $InstallerLogFile
    if ([Environment]::Is64BitOperatingSystem -eq $true ) 
    {
        foreach ($RemEnv in $EnvsToRemove_x64)
        {
            if ($RemEnv -ne "")
            {
                $log = '    Removing ' + $RemEnv
                LogMe_AndDisplay $log $InstallerLogFile
                $envname = 'env:'+$RemEnv
                if (test-path -Path $envname)
                {
                    $err = remove-item -force -path $envname *>&1
                    LogMe_AndDisplay $err  $InstallerLogFile
                }
            }
        }
    }
    else 
    {
        foreach ($RemEnv in $EnvsToRemove_x86)
        {
            if ($RemEnv -ne "")
            {
                $log = '    Removing ' + $RemEnv
                LogMe_AndDisplay $log $InstallerLogFile
                $envname = 'env:'+$RemEnv
                if (test-path -Path $envname)
                {
                    $err = remove-item -force -path $envname *>&1
                    LogMe_AndDisplay $err  $InstallerLogFile
                }
            }
        }
    }
    LogMe_AndDisplay "RemoveEnvs Completed." $InstallerLogFile 
}



###################################################################################################
# Function to Disable listed Services
function Run_DisableServices(
                        [string[]]$ServicesToDisble_x64,
                        [string[]]$ServicesToDisble_x86)
{
    LogMe_AndDisplay "Starting DisableServices."  $InstallerLogFile
    if ([Environment]::Is64BitOperatingSystem -eq $true ) 
    {
        foreach ($DisabSvc in $ServicesToDisble_x64)
        {
            if ($DisabSvc -ne "")
            {
                $log = '    Disabling ' + $DisabSvc
                LogMe_AndDisplay $log $InstallerLogFile
                if ( get-service -name $DisabSvc)
                {
                    $err = set-service -name $DisabSvc -StartupType Disabled *>&1
                    LogMe_AndDisplay $err $InstallerLogFile
                }
                else
                {
                    LogMe_AndDisplay "    *** Service not found?" $InstallerLogFile
                }
            }
        }
    }
    else 
    {
        foreach ($DisabSvc in $ServicesToDisble_x86)
        {
            if ($DisabSvc -ne "")
            {
                $log = '    Disabling ' + $DisabSvc
                LogMe_AndDisplay $log $InstallerLogFile
                if ( get-service -name $DisabSvc)
                {
                    $err = set-service -name $DisabSvc -StartupType Disabled *>&1
                    LogMe_AndDisplay $err $InstallerLogFile
                }
                else
                {
                    LogMe_AndDisplay "    *** Service not found?" $InstallerLogFile
                }
            }
        }
    }
    LogMe_AndDisplay "DisableServices Completed." $InstallerLogFile 
}



###################################################################################################
# Function to find/run Post-Install NGen script files
#    This will find all ps1 files with names matchine "*Post_Install_ExtraNGEN*" in the given folder
#    Those whose base names end in x86 or x64 will only be run on the same bitness as the OS,
#    All others will just be run.
#    No control over the order of running is provided.
function Run_PostInstallNGenScripts([string]$executingScriptDirectory)
{
    LogMe_AndDisplay "Starting any Post-Install NGEN scripts." $InstallerLogFile 
    $cnt = 0
    $psexeNative = Get_PowerShellNativePath
    #---------------------------------------------------------------
    #Look for a .ps1 file to import
    Get-ChildItem $executingScriptDirectory | Where-Object { $_.Extension.ToLower() -eq '.ps1' } | ForEach-Object {
        $xtmp = $_.FullName
        if ($xtmp -like "*x64OSPostInstall_ExtraNgen.ps1" -or $xtmp -like "*PostInstall_ExtraNgen_x64.ps1" ) 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $true) 
            {
                $log = '    Running script for x64'+ $xtmp
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile $false $true
                $cnt = $cnt + 1
            }
        }
        elseif ($xtmp -like "*x86OSPostInstall_ExtraNgen.ps1" -or $xtmp -like "*PostInstall_ExtraNgen_x86.ps1") 
        {
            if ([Environment]::Is64BitOperatingSystem -eq $false) 
            {
                $log = '    Running script for x86'+ $xtmp 
                LogMe_AndDisplay $log $InstallerLogFile 
                Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
                ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile $false $true
                $cnt = $cnt + 1
            }
        }
        elseif ($xtmp -like "*_PostInstall_ExtraNgen.ps1") 
        {
            $log = '    Running script'+ $xtmp 
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -Wait -FilePath "$psexeNative"  -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$xtmp`""      -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile $false $true
            $cnt = $cnt + 1
        }
    }
    if ($cnt -eq 0) 
    { 
        LogMe_AndDisplay "    No valid ps1 files were located."  $InstallerLogFile 
    }
    LogMe_AndDisplay "Post-Install NGEN scripts complete." $InstallerLogFile  
}










####################################################################################################
# Function to get native-bit Powershell path, meaning the path to the PowerShell.exe file for the 
# same bitness as that of the underlying OS.
# 
# We typically do not use this function, as most installers are 32-bit, but sometimes we want 64-bit
# registry access to set non-wow locations.
function Get_PowerShellNativePath {
    return $env:windir + "\system32\WindowsPowerShell\v1.0\powershell.exe"
}



###################################################################################################
# Function to get 32-bit Powershell path.
#
# Most installers are 32-bit, so we always want to be launching the 32-bit version in case we
# directly set some stuff in the windows registry.
function Get_PowerShellx86Path {
    if ([Environment]::Is64BitOperatingSystem -eq $true ) {
        if ([Environment]::Is64BitProcess -eq $false) {
            return $env:windir + "\syswow64\WindowsPowerShell\v1.0\powershell.exe"
        }
        else {
            return $env:windir + "\system32\WindowsPowerShell\v1.0\powershell.exe"
        }
    }
    else {
            return $env:windir + "\system32\WindowsPowerShell\v1.0\powershell.exe"
    }
}


###################################################################################################
# Function to create a registry key, but only if not already present
function Make_KeyIfNotPresent([string]$HKwhich, [string]$rkey ) {
    if (Test-Path "$($HKwhich):\$($rkey)") { } else {
        LogMe_AndDisplay "Creating key $($HKwhich):\$($rkey)"
        New-Item -Path "$($HKwhich):\$($rkey)" -Force
    }
}


###################################################################################################
# Function to create a registry key, but only if not already present
function Make_FolderIfNotPresent( [string]$folder ) {
    if (Test-Path "$($folder)") { } else {
        LogMe_AndDisplay "Creating folder $($folder)"
        New-Item -ItemType Directory -Path "$($folder)" -Force
    }
}



#######################################################################################################################
<#
.SYNOPSIS
Flush_NGensQueues
Function to flush the various ngen queues.

.DESCRIPTION
Many installers of .NET apps set up to perform .net compilation optimization in the background in an ngen queue.
This function will force completion so that you have it in your package.  

    NOTE: You should ensure that this has been done to your base image before the snapshot so that 
    you don't pick up other stuff!

.PARAMETER InstallerLogFile
Full path to a log file to generate/append to.

#>
Function Flush_NGensQueues
{
  [CmdletBinding()] 
  param( 
    [Parameter(Mandatory=$True, Position=0)]  
    [string]$InstallerLogFile
  )
  Process 
  {

    [string[]]$NgenPotentials =  "C:\Windows\Microsoft.NET\Framework\v2.0.50727\ngen.exe","C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe","C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ngen.exe","C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe"
    
    LogMe_AndDisplay "Flushing NGen Queues" $InstallerLogFile 
    foreach ($ng in $NgenPotentials)
    {
        if(Test-Path $ng )
        {
            $log =  "    Flushing queue with"+$ng
            LogMe_AndDisplay $log $InstallerLogFile 
            Start-Process -Filepath $ng executeQueuedItems  -Wait  -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
            ProcessLogMe_AndDisplay 'redir_error.log' 'redir_out.log'  $InstallerLogFile
        }
    }
    LogMe_AndDisplay "NGen queue flusing complete." $InstallerLogFile
  } 
}


###################################################################################################
# Function to log something to the end of the named text-based log file.
#
# Note: This function does not timestamp the entry.
function LogMe_AndDisplay([string]$string, [string]$InstallerLogFile, [bool]$DoDisplay = $true)
{
    if ($DoDisplay) { Write-Output $string }
    Write-Output $string >> $InstallerLogFile
}


###################################################################################################
# Function to process captured logs from external processes.
#
# When PowerShell calls external processes, it is harder to capture the output.
# Powershell added some tracing capability, but you can't nest those.  
# Capture the output into a variable, like 
#        Start-Process [parameters] -RedirectStandardError redir_error.log -RedirectStandardOutput redir_out.log
# and then call this function with the two log files and the intended log file.  
# This function will optionally display the logs out to the screen,
# Then the function will append these two logs to the end of the text-based InstallerLogFile.
function ProcessLogMe_AndDisplay([string]$errorlogfile, [string]$outlogfile, [string]$InstallerLogFile, [bool]$DeleteAfter = $true, [bool]$DoDisplay = $true)
{
  if ($DoDisplay)
  {
      Get-Content $errorlogfile 
      Get-Content $outlogfile
  }
  Get-Content $errorlogfile >> $InstallLogFile
  Get-Content $outlogfile >> $InstallLogFile
  if ($DeleteAfter)
  {
    remove-item $errorlogfile
    remove-item $outlogfile
  }
}

