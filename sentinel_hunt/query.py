"""Translate a constrained search plan into a single Log Analytics query."""
import json
from dataclasses import dataclass

COLUMNS = {
    "DeviceProcessEvents": "TimeGenerated AccountName ActionType DeviceName InitiatingProcessCommandLine ProcessCommandLine",
    "DeviceFileEvents": "TimeGenerated ActionType DeviceName FileName FolderPath InitiatingProcessAccountName SHA256",
    "DeviceLogonEvents": "TimeGenerated AccountName DeviceName ActionType RemoteIP RemoteDeviceName",
    "DeviceNetworkEvents": "TimeGenerated ActionType DeviceName RemoteIP RemotePort",
    "AzureActivity": "TimeGenerated OperationNameValue ActivityStatusValue ResourceGroup Caller CallerIpAddress Category",
    "SigninLogs": "TimeGenerated UserPrincipalName OperationName Category ResultSignature ResultDescription AppDisplayName IPAddress LocationDetails",
    "AzureNetworkAnalytics_CL": "TimeGenerated FlowType_s SrcPublicIPs_s DestIP_s DestPort_d VM_s AllowedInFlows_d AllowedOutFlows_d DeniedInFlows_d DeniedOutFlows_d",
}
SCOPE = {"AzureActivity": "Caller", "SigninLogs": "UserPrincipalName", "AzureNetworkAnalytics_CL": "VM_s"}
ROW_LIMIT = 250


@dataclass(frozen=True)
class Search:
    table: str
    hours: int
    target: str

    def __post_init__(self):
        if self.table not in COLUMNS:
            raise ValueError("Unsupported table")
        if type(self.hours) is not int or not 1 <= self.hours <= 168:
            raise ValueError("Choose a lookback between 1 and 168 hours")
        if not isinstance(self.target, str) or len(self.target) > 255 or not self.target.isprintable() and self.target:
            raise ValueError("Invalid target")

    def kql(self):
        lines = [self.table]
        if self.target:
            column = SCOPE.get(self.table, "DeviceName")
            literal = json.dumps(self.target, ensure_ascii=False)
            # Match the first DNS label so lab-01 includes lab-01.example.org but excludes lab-010.
            if column == "DeviceName" and "." not in self.target:
                lines.append(f'| where tostring(split(DeviceName, ".")[0]) =~ {literal}')
            else:
                lines.append(f"| where {column} =~ {literal}")
        if self.table == "AzureNetworkAnalytics_CL":
            lines.append('| where FlowType_s == "MaliciousFlow"')
        lines += [f"| top {ROW_LIMIT} by TimeGenerated desc",
                  "| project " + ", ".join(COLUMNS[self.table].split())]
        return "\n".join(lines)
