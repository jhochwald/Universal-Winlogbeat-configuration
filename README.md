# Universal Winlogbeat configuration

This repository contains a universal [Winlogbeat](https://www.elastic.co/beats/winlogbeat) configuration.

I use this configuration to push Windows EventLogs to [Graylog](https://www.graylog.org), but it should also work for other Beats compatible systems.

I used [NXLog](https://nxlog.co/products/nxlog-community-edition) and decided to switch to [Winlogbeat](https://www.elastic.co/beats/winlogbeat) now.

The configuration is in a very early beta stage!

## Requirements

[Winlogbeat](https://www.elastic.co/beats/winlogbeat) (tested with 7.10.2)

Optional:

## Info

I did all tests with Windows 10 1809 and 20H2, and Windows Server 2016. in my setup it send everything to a Debian 10 based [Graylog](https://www.graylog.org) Server (4.0.1).

I remove a few fields from each message in my [Graylog](https://www.graylog.org) input via a filter.

## Config

Please be warned: This is a all-in-One solutions, e.g., one size fits all.

```yaml
# Define the output (we use Logstash for Graylog)
output.logstash:
  hosts:
    - "XXX.XXX.XXX.XXX:XXXX"

# Cleanup
path: null

# The amount of time to wait for all events to be published when shutting down.
winlogbeat.shutdown_timeout: 30s

# A list of entries (called dictionaries in YAML) that specify which event logs to monitor.
winlogbeat.event_logs:
  # Application
  - name: Application
    # A list of event levels to include.
    # The value is a comma-separated list of levels.
    level: "critical, error"
    # If this option is specified, Winlogbeat filters events that are older than the specified amount of time.
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 1020
          - equals.winlog.event_id: 8193
          - equals.winlog.event_id: 13

  - name: Security
    level: "critical, error, warning, information"
    # Filter
    processors:
      # Do NOT filter this IDs
      - drop_event.when.not.or:
          - equals.winlog.event_id: 1102
          - equals.winlog.event_id: 4723
          - equals.winlog.event_id: 4624
          - equals.winlog.event_id: 4624
          - equals.winlog.event_id: 4625
          - equals.winlog.event_id: 4728
          - equals.winlog.event_id: 4729
          - equals.winlog.event_id: 4732
          - equals.winlog.event_id: 4733
          - equals.winlog.event_id: 4740
          - equals.winlog.event_id: 4743
          - equals.winlog.event_id: 4746
          - equals.winlog.event_id: 4747
          - equals.winlog.event_id: 4751
          - equals.winlog.event_id: 4752
          - equals.winlog.event_id: 4756
          - equals.winlog.event_id: 4757
          - equals.winlog.event_id: 4761
          - equals.winlog.event_id: 4762
          - equals.winlog.event_id: 4767
          - equals.winlog.event_id: 4771
      - drop_event.when.or:
          # Filter this IDs
          - equals.winlog.event_id: 4688
    ignore_older: 24h

  - name: System
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 7000
          - equals.winlog.event_id: 7001
          - equals.winlog.event_id: 10016
          - equals.winlog.event_id: 24629

  - name: Microsoft-Windows-Windows Defender/Operational
    level: "critical, error"
    ignore_older: 24h
    # Boolean option that controls if the raw XML representation of an event is included in the data sent by Winlogbeat.
    include_xml: true

  - name: Microsoft-Windows-AAD/Operational
    level: "critical, error"
    ignore_older: 24h
    include_xml: true
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 1104
          - equals.winlog.event_id: 1025
          - equals.winlog.event_id: 1097
          - equals.winlog.event_id: 1098
          - equals.winlog.event_id: 7361

  - name: Microsoft-Windows-BitLocker/BitLocker Operational
    level: "critical, error, warning"
    ignore_older: 24h

  - name: Microsoft-Windows-BitLocker/BitLocker Management
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-BitLocker-DrivePreparationTool/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-BitLocker-DrivePreparationTool/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-DeviceGuard/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-DSC/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-PowerShell/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 4104
          - equals.winlog.event_id: 4100

  - name: Microsoft-Windows-PowerShell/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Shell-Core/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Shell-Core/LogonTasksChannel
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Shell-Core/AppDefaults
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Shell-Core/ActionCenter
    level: "critical, error"
    ignore_older: 24h

  - name: PowerShellCore/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: OpenSSH/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: OpenSSH/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: HardwareEvents
    level: "critical, error"
    ignore_older: 24h

  - name: Windows PowerShell
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Security-Mitigations/KernelMode
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 10

  - name: Microsoft-Windows-Kernel-WHEA/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-WHEA/Errors
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-WDI/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-StoreMgr/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-ShimEngine/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-Power/Thermal-Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-PnP/Driver Watchdog
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-PnP/Configuration
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-LiveDump/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-IO/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Kernel-EventTracing/Admin
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 1569
          - equals.winlog.event_id: 1570
          - equals.winlog.event_id: 2
          - equals.winlog.event_id: 28

  - name: Microsoft-Windows-Kernel-Boot/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 124

  - name: Microsoft-Windows-WinRM/Operational
    level: "critical, error, warning"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 142
          - equals.winlog.event_id: 161

  - name: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 227

  - name: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
    level: "critical, error"
    ignore_older: 24h
    include_xml: true

  - name: Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity
    level: "critical, error"
    ignore_older: 24h
    include_xml: true

  - name: Windows Networking Vpn Plugin Platform/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-VPN/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-VPN-Client/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-RasAgileVpn/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-TCPIP/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-LiveId/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 2028
          - equals.winlog.event_id: 6113

  - name: Microsoft-Windows-ReFS/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-TaskScheduler/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 103
          - equals.winlog.event_id: 202
          - equals.winlog.event_id: 322
          - equals.winlog.event_id: 324

  - name: Microsoft-Windows-TaskScheduler/Maintenance
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storsvc/Diagnostic
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Store/Operational
    level: "critical"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 8002

  - name: Microsoft-Windows-StorageSpaces-SpaceManager/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-StorageSpaces-SpaceManager/Diagnostic
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-StorageSpaces-ManagementAgent/WHC
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-StorageSpaces-Driver/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-StorageSpaces-Driver/Diagnostic
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-StorageManagement/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storage-Tiering/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storage-Storport/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 549
          - equals.winlog.event_id: 523
          - equals.winlog.event_id: 500

  - name: Microsoft-Windows-Storage-Storport/Health
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storage-Storport/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storage-Disk/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Storage-Disk/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-SMBServer/Security
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-SMBServer/Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 1024

  - name: Microsoft-Windows-SMBServer/Connectivity
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-SMBServer/Audit
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-SmbClient/Security
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 8464
          - equals.winlog.event_id: 31001

  - name: Microsoft-Windows-SMBClient/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-SmbClient/Connectivity
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 30800
          - equals.winlog.event_id: 30803

  - name: Microsoft-Windows-SmbClient/Audit
    level: "critical, error"
    ignore_older: 24h

  - name: Win Device Agent
    level: "critical, error"
    ignore_older: 24h

  - name: ScriptLaunch
    level: "critical, error"
    ignore_older: 24h

  - name: Operations Manager
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 4502
          - equals.winlog.event_id: 26002

  - name: OneApp_IGCC
    level: "critical, error"
    ignore_older: 24h

  - name: Key Management Service
    level: "critical, error"
    ignore_older: 24h

  - name: Internet Explorer
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-DNS-Client/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Dhcpv6-Client/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Dhcpv6-Client/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Dhcp-Client/Operational
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-Dhcp-Client/Admin
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-AppLocker/Packaged app-Execution
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-AppLocker/Packaged app-Deployment
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-AppLocker/MSI and Script
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-AppLocker/EXE and DLL
    level: "critical, error"
    ignore_older: 24h

  - name: Microsoft-Windows-CodeIntegrity/Operational
    level: "critical"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 3033

  # Server only
  - name: Microsoft-Windows-DNSServer/Audit
    level: "critical, error"
    ignore_older: 24h

  # Server only
  - name: Microsoft-Windows-Dhcp-Server/Operational
    level: "critical, error"
    ignore_older: 24h

  # Microsoft Skype for Business Rooms System and Microsoft Teams Rooms System only
  - name: Skype Room System
    level: "critical, error, warning"
    ignore_older: 24h

  # Hp Tooling
  - name: HPNotifications Application
    level: "critical, error"
    ignore_older: 24h

  - name: HP Sure Start
    level: "critical, error"
    ignore_older: 24h

  - name: HP Diagnostics
    level: "critical, error"
    ignore_older: 24h

  - name: HP Analytics
    level: "critical, error"
    ignore_older: 24h

  # Hyper-V only
  - name: Microsoft-Windows-Hyper-V-Hypervisor-Operational
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 41

  - name: Microsoft-Windows-Hyper-V-Hypervisor-Admin
    level: "critical, error"
    ignore_older: 24h
    processors:
      - drop_event.when.or:
          - equals.winlog.event_id: 41
```

You will find this minimal config as [winlogbeat.yml](assets/winlogbeat.yml) in the [assets](assets) directory!

![GitHub](https://img.shields.io/github/license/jhochwald/Universal-Winlogbeat-configuration) [![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)
