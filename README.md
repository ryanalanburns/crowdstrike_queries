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

