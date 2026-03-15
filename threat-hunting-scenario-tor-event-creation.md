# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

Steps the Attacker Took to Create Logs and IoCs:
1. Downloaded the TOR browser installer from the official TOR Project website: https://www.torproject.org/download/
2. ilently installed TOR using the following command: tor-browser-windows-x86_64-portable-15.0.7.exe /S
3. Opened the TOR browser from the desktop folder after installation completed
4. Connected to the TOR network and browsed several active .onion sites, including:
   - Current Dread Forum: ```dreadytognbh7m5nlmqsogzzlxjy75iuxkulewbhxcorupbqahact2yd.onion/?```
   - Dark Markets Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

   > [!NOTE]
    > The above links may be outdated. Use ```https://onion.live/``` to find currently active .onion sites for simulation purposes.

6. Created a text file on the desktop named ```tor-shopping-list.txt``` and populated it with several fictitious illicit items to simulate darknet purchasing behavior
7. Deleted the file to attempt to cover tracks

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-15.0.7.exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Sana Jafferi
- **Author Contact**: https://www.linkedin.com/in/sanajafferi/
- **Date**: March 15, 2026

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**     | **Date**         | **Modified By**   |
|-------------|-----------------|------------------|-------------------|
| 1.0         | Initial draft   | `March  15, 2026`| `Sana Jafferi`    |   
