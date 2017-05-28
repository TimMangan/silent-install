# silent-install
A powershell framework for desktop application installations.

We wish to have a powershell based framework that may be used to eastily install and configure a desktop software application. 

This would allow an IT Administrator to automate the preparataion of these applications, typically as part of a larger system for desktop image building and instantiation.

For example, the Microsoft AutoSequencer (from the ADK) is a system that automates creation of virtual applciation packages for dynamic delivery using a virtual machine for the process of capturing and packaging up the appliction. A powershell script that uses this framework would be an ideal way for the IT Administrator to describe the installation and customization steps.

A PowerShell module would contain the common functions and data structures that would be used.  A sample powershell script is also included in the project to provide a shell that may be copied and modified as needed on a per-application basis.
