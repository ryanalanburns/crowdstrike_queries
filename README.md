# crowdstrike_queries
Quick Win and Obscure Queries

Identify users logging in outside of the US.
-

  The neat trick with this is we're using the
  sensor's IP to identify where the user is located. This bypasses users who may be logging
  in from a remote area but using a VPN to bypass this identification.

```
#repo=base_sensor #event_simpleName=SensorHeartbeat
| in(aid, values=[*], ignoreCase=true)
| ipLocation(aip)
| aip.country!="US"
| table([timestamp,ComputerName,aip.city,aip.country])
```

also consider endpoints that you exect to log in remotely. You can exclude those
by doing a 
```
ComputerName!="exampe"
```

If youre into visuals, you can map it out with

```
| worldMap(ip=aip)
```

Find a computers external IP over a time period:
- 
```
#event_simpleName = NetworkConnectIP4
|ComputerName = "MacBook-Pro-3.local"
|groupBy([aip,ComputerName])
```

Identify Brute Force Network Logon Attempts
-
```
#event_simpleName = UserLogonFailed2
| Technique = "Brute Force"
| LogonType = 3
```
Also consider type 2 is interactive, or directly on the endpoint. Here we
are also identifying users who are admin. This will output the Username | Endpoint
and the count, which you can then sort it on. If no enduser is admin, you can omit
the UserIsAdmin portion.

```
#event_simpleName = UserLogonFailed2
| LogonType = 2
| UserIsAdmin = 1
| groupBy([UserName, ComputerName])
```

This is an alternative that will help prioritize your remediation or scope out what is most impactful.
```
#event_simpleName=UserLogonFailed2
| groupBy([UserName, ComputerName], function=count(as="FailedLoginCount"))
| test(FailedLoginCount > 10)
| sort(FailedLoginCount, order=desc)
| table([UserName, ComputerName, FailedLoginCount])
```
Identify events where an executable file has been renamed and then run.
-
This query helps in identifying potential malicious activity where an executable is renamed (possibly to evade detection) and then executed.
```
#event_simpleName=NewExecutableRenamed OR #event_simpleName=ProcessRollup2
| join(
    query={
        #event_simpleName=NewExecutableRenamed
    },
    include=[SourceFileName, TargetFileName, SHA256HashData],
    field=[aid, TargetFileName],
    key=[aid, ImageFileName],
    mode=inner
)
| table([@timestamp, aid, ComputerName, SourceFileName, TargetFileName, ImageFileName, CommandLine, SHA256HashData])
```
Here's how it works:

The query starts by filtering for events of type NewExecutableRenamed (indicating an executable file was renamed) and ProcessRollup2 (indicating a process was executed).

A join operation is used to correlate the NewExecutableRenamed events with ProcessRollup2 events. 
The join is performed on the aid (sensor ID) and the TargetFileName from the NewExecutableRenamed event with the ImageFileName from the ProcessRollup2 event. This ensures that only renamed executables that were subsequently executed are included.

The include parameter in the join specifies that fields such as SourceFileName, TargetFileName, and SHA256HashData from the NewExecutableRenamed event should be included in the result.
The table function is used to display relevant fields, including the timestamp, sensor ID (aid), computer name, source file name (original name of the executable), target file name (new name of the executable), image file name (name of the executed file), command line, and SHA256 hash data.

Suspicious Network Connections from Processes
-
```
(#event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkConnectIP6)
| join(query={
    #event_simpleName=ProcessRollup2
    | select([aid, TargetProcessId, ImageFileName, CommandLine])
}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], mode=inner)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"])
| table([@timestamp, ComputerName, ImageFileName, CommandLine, RemoteAddressIP4, RemoteAddressIP6, RemotePort, LocalPort, Protocol])
```

This identifies suspicious network connections by correlating network connection events (NetworkConnectIP4 and NetworkConnectIP6) with the processes responsible for those connections (ProcessRollup2). It filters out connections to private IP ranges (RFC1918 addresses) to focus on external connections, which are more likely to be suspicious. The query outputs relevant fields such as the timestamp, computer name, process details (ImageFileName and CommandLine), and connection details (remote and local IPs, ports, and protocol) for further analysis.

Additionally, we can filter out some traffic by removing connections to Google, Microsoft, and Cloudflare with the following:
```
| !in(RemoteAddressIP4, values=["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]) // Exclude common IPs like Google and Cloudflare
| !in(RemoteAddressIP6, values=["2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"])
```

So an updated query might look like:
```
#event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkConnectIP6
| !in(RemoteAddressIP4, values=["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]) // Exclude common IPs like Google and Cloudflare
| !in(RemoteAddressIP6, values=["2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001"]) // Exclude common IPv6 addresses
| join(query={
#event_simpleName=ProcessRollup2
| rename(field="TargetProcessId", as="ConnectionProcessId")
| rename(field="ImageFileName", as="ProcessImageFileName")},
field=[aid, ContextProcessId],
key=[aid, ConnectionProcessId],
mode=inner,
include=[ProcessImageFileName],
limit=200000)
| table([@timestamp, ComputerName, RemoteAddressIP4, RemoteAddressIP6, RemotePort, LocalPort, Protocol, ProcessImageFileName], limit=20000)
```
And this will output the full path to the application making the connection.

Suspicious Processes based on Activity
-
```
#event_simpleName=ProcessRollup2
| in(ImageFileName, values=["powershell.exe", "cmd.exe"])
| CommandLine=/(-enc|-encodedcommand|Invoke-WebRequest|Net.WebClient|Start-BitsTransfer|IEX|DownloadString)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, @timestamp], limit=20000)
```
This is aimed at identifying suspicious processes by focusing on specific processes known to be used in malicious activities, such as powershell.exe and cmd.exe. It also filters for unusual or potentially malicious command-line arguments, such as encoded commands (-enc, -encodedcommand), web requests (Invoke-WebRequest, Net.WebClient, Start-BitsTransfer), and other suspicious patterns (IEX, DownloadString).

Process creation with Unusal Paths
-
```
#event_simpleName=ProcessRollup2
| regex(field=ImageFileName, "^(?!.*\\\\(Windows|Program Files|Program Files \(x86\)|System32|SysWOW64)\\\\).*\\\\.*\.exe$")
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
```
The output should pretty quickly tell you what process/parent application is running and where. For me, I get a lot of activity for my MDM solution and developer's python envs.

Search for Process Hollowing or Injection
-
```
#event_simpleName=ProcessInjection
| in(ThreadExecutionControlType, values=[3, 5])
| table([@timestamp, ComputerName, InjectorImageFileName, InjecteeImageFileName, ThreadExecutionControlType, MemoryDescriptionFlags, WellKnownTargetFunction])
```
In my env, management has allowed users to run games on their corporate laptops. Kind of sucks, but the big thing here is game engines often have anti-cheat engines that inject processes into what feels like everything. Also, youll find a few things like Acrobat_Set-Up will inject Explorer and your printer drivers/apps will also do crazy stuff. All that to say, this is typically a good starting point and dont be intimidated by the results.

Search for Ransomware file extensions
-
```
#event_simpleName=*FileWritten*
| TargetFileName=/\.(lock|ransom)$/i
| table([@timestamp, aid, ComputerName, TargetFileName, UserName])
```
Pretty straightforward. Basically, create a file and do a .lock or .ransom and then make sure youre pulling it. From there, I would pivot over to SOAR and make this an automatic quarantine. Realistically, CS should find and stop this first.

Registry Key Modificaiton
- 
These are some most often targeted keys:
```
AsepKeyUpdate: Indicates modifications to Auto Start Execution Point (ASEP) registry keys.
RegGenericValueUpdate: Captures updates to generic registry values.
RegSystemConfigValueUpdate: Tracks changes to registry values associated with system configuration or security settings.
SuspiciousRegAsepUpdate: Highlights suspicious registry auto-start entry point updates.
```

This query will help identify any modifications to those keys:
```
