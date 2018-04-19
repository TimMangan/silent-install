
# silent-install
A PowerShell framework for desktop application installations.

We wish to have a PowerShell based framework that may be used to easily install and configure a desktop software application. 

This would allow an IT Administrator to automate the preparataion of these applications, typically as part of a larger system for desktop image building and instantiation.

For example, the Microsoft AutoSequencer (from the ADK) is a system that automates creation of virtual applciation packages for dynamic delivery using a virtual machine for the process of capturing and packaging up the appliction. A PowerShell script that uses this framework would be an ideal way for the IT Administrator to describe the installation and customization steps.

A PowerShell module would contain the common functions and data structures that would be used.  A sample PowerShell script is also included in the project to provide a shell that may be copied and modified as needed on a per-application basis.

## More Info
Please see the Wiki on the github project (http://github.com/TimMangan/silent-install ) for more information about the project.

## Deprication Notice
I intend to abbandon this project.  It was usefull, but without sufficient interest it has now been replaced by a non-open source PowerShell packaged called "PassiveInstall".  The new PassiveInstall PowerShell modules are free for download at http://www.tmurgent.com. They represent a complete re-write of this effort, and are easier for IT Pros to use, and supports both passive and silent installations.  There is also a free online training module at http://www.tmurgent.com/educate. 
