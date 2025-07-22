# crowdstrike_queries
Quick Win and Obscure Queries

Identify users logging in outside of the US.
-

  The neat trick with this is we're using the
  sensor's IP to identify where the user is located. This bypasses users who may be logging
  in from a remote area but using a VPN to bypass this identification.

```#repo=base_sensor #event_simpleName=SensorHeartbeat
| in(aid, values=[*], ignoreCase=true)
| ipLocation(aip)
| aip.country!="US"
| table([timestamp,ComputerName,aip.city,aip.country])```

  also consider endpoints that you exect to log in remotely. You can exclude those
  by doing a ComputerName!="exampe"

If youre into visuals, you can map it out with
  | worldMap(ip=aip)

Find a computers external IP over a time period:
- 
```#event_simpleName = NetworkConnectIP4
|ComputerName = "MacBook-Pro-3.local"
|groupBy([aip,ComputerName])```

