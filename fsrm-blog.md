# FSRM via DSC

Sometimes a solution comes from scratch, inventing from the ground up.  Other times, it's just a matter of puting the pieces together.  So what do you get when you combine dscottraynsford's cFSRM DSC Resource, and Experiant.ca's anti ransomware list? One more brick in the wall against ransomware!

Certainly, a full defense includes end user education, proper application of user rights to file and folder resources, and a good anti-malware application.  But preventing, or at least hampering, a ransomware attack from doing what it is trying to do, is a significant defense.

 After one such attack, in which the attack itself was disrupted by forcibly powering down the infected PC, I was able to identify some of the temporary files, as well as the ransom notes themselves that this attack was using.  From this it occured to me that I could leverage File Server Resource Manager (FSRM) to block anything from writing (or reading) any files with those names and extensions. Ha! Passing 70-410 was worth something!

As is so often the case, I started out by installing the FSRM Feature on one of my Windows Servers, and configuring an FSRM File Screen using the in box GUI tool. At least with RSAT, I was able to do it without RDP-ing to the server.  Doing so gave me a feel for what I was setting up: A **File Group**, containing the list of files that I wanted to block; A **File Screen Template**; and an **Action** for the File Screen to take.

In this case, I wanted to "actively" block the listed files from being written or read, and I wanted FSRM to write an event log entry, which I would have SCOM alert on.  That worked fine for a few file names on one server, but was never going to scale at all.

One last piece of the puzzle before we get to the code: I wasn't naive enough to think that a few names and extensions was all it would take to proide any sort of protection.  I did a few Google searches and found that fsrm.experiant.ca was curating a list of filenames and extensions that had been involved in ransomware attacks.  To top it off, that list was available in json form.

To give credit where it's due, I also found that Experiant has posted a script-based solution to configure FSRM.

From my viewpoint, however, this seemed like a job for Desired State Configuration, even if only in push form.

Starting with the Configuration declaration
```powershell
Configuration FSRMAntiRansomware
{
...
}
```

The first part is to get the list names and extensions:

```powershell
$Uri = "https://fsrm.experiant.ca/api/v1/combined"
$Filters = @((Invoke-WebRequest -Uri $Uri -UseBasicParsing).content `
            | convertfrom-json `
            | Select-object -ExpandProperty Filters
```

As an aside, Experiant's script breaks the the filelist string into 4K chunks, but doesn't provide an explanation for it, nor do I see any technical need.
Now that we have the list of files and extensions, we can move to building the DSC Configuration.

```powershell
Node $AllNodes.NodeName
    {
        FSRMFileGroup FSRMFileGroupRansomwareFiles
        {
            Name = 'Experiant Ransomware Files'
            Description = 'files and extenstions associated with Ransomware attacks'
            Ensure = 'Present'
            IncludePattern = $Filters
        }

        FSRMFileGroup FSRMFileGroupExceptions
        {
            Name = 'Exceptions'
            Description = 'Files and extensions that we agree should not trigger an alert'
            Ensure = 'Present'
            IncludePattern = '*.key', 'readme.txt'
        }

        FSRMFileScreenTemplate FileScreenRansomware
        {
            Name = "Block Ransomware Files"
            Description = "File Screen to block Ransomware files and extenstions"
            Ensure = 'Present'
            Active = $true
            IncludeGroup = 'Experiant Ransomware Files'
            DependsOn = "[FSRMFileGroup]FSRMFileGroupRansomwareFiles"
        }

        FSRMFileScreenTemplateAction FileScreenRansomwareEvent
        {
            Name = "Block Ransomware Files"
            Ensure = 'Present'
            Type = 'Event'
            Body = 'The system detected that user [Source Io Owner] attempted to save [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group which is not permitted on the system.'
            EventType = 'Warning'
            DependsOn = '[FSRMFileScreenTemplate]FileScreenRansomware'
        }

        foreach ($path in $Node.paths)
        {
            $Name = "FSRMFileScreen_$($path.split('\')[1,2] -join(''))"
            FSRMFileScreen $Name
            {
                Path = $path
                Description = 'File Screen blocking Ransomware files'
                Ensure = 'Present'
                Template = "Block Ransomware Files"
                MatchesTemplate = $true
                DependsOn = "[FSRMFileScreenTemplate]FileScreenRansomware", "[FSRMFileScreenTemplateAction]FileScreenRansomwareEvent"
            }

            # add an exception item here
            $Name = "FileScreenExceptions_$($path.split('\')[1,2] -join(''))"
            FSRMFileScreenException $Name
            {
                Path = $path
                Description = "Exceptions to the downloaded File Group"
                Ensure = 'Present'
                IncludeGroup = 'Exceptions'
                DependsOn = '[FSRMFileGroup]FSRMFileGroupExceptions'
            }
        }
    }
```

The last block, where we actually create the filescreen allows for multiple paths to be defined for a given node, but a single path, such as a drive letter is perfectly acceptable.  As written, this configuration will cause the FileScreen to block access to the filtered files, and create an event log entry.  In my case, we used SCOM to monitor for, and alert on that event log entry.  If you don't have SCOM, you could have FSRM send the email message itself, from the affected server.

Now we need a PowerShell data file (.psd1) to provide the node information.

```powershell
@{
    AllNodes =
    @(
        #All Nodes
        @{
            NodeName = "*"
            # Anything all the nodes would have in common
            # Not used if a node explicitly defines this property
            Paths = @("T:\")
        },
        @{
            NodeName = "FileServerA"
            Paths = @("H:\some\path","G:\some\other")
        },
        @{
            NodeName = 'FileServerB'
        }
    );
}
```

This defines a default Paths value of "T:\", but for any given nodename, you can define one or more values for Paths.  For this example, we'll save the data file as "FSRMFileScreen-DSC.psd1"

The thing about this application of DSC is that it isn't appropriate for Pull.  Since the dynamic component is in the configuration definition, and the resultant MOF is static, we need to generate the mof any time we want to apply these settings.

To apply this configuration:

```powershell
$DSCPath = "."

TestFileGroupAndTemplate -OutputPath "$DSCPath\FSRM" -ConfigurationData "$DSCPath\FSRM\FSRMFileScreen-DSC.psd1" -verbose

Start-DscConfiguration -Force -Wait -Path "$DSCPath\FSRM"  -Verbose -computername Server A
```

You may find it worthwhile to still use a scheduled task to rebuild the MOFs and re-push the configuration on a regular basis, such as once a week, or once a day.
