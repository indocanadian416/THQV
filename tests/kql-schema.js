/*
 * Table schemas used to type-check KQL in tests. Column names and types come
 * from the Microsoft Learn table references:
 *   https://learn.microsoft.com/azure/azure-monitor/reference/tables/<table>
 *   https://learn.microsoft.com/defender-xdr/advanced-hunting-<table>-table
 * Only the columns these queries could plausibly use are listed; a query that
 * references a column missing here fails the test, which is the point - add the
 * column only after confirming it exists in the documentation.
 */
'use strict';

const initiatingProcess = [
  'InitiatingProcessAccountDomain:string', 'InitiatingProcessAccountName:string', 'InitiatingProcessAccountSid:string',
  'InitiatingProcessAccountUpn:string', 'InitiatingProcessAccountObjectId:string', 'InitiatingProcessSHA1:string',
  'InitiatingProcessSHA256:string', 'InitiatingProcessMD5:string', 'InitiatingProcessFileName:string',
  'InitiatingProcessFileSize:long', 'InitiatingProcessId:long', 'InitiatingProcessCommandLine:string',
  'InitiatingProcessCreationTime:datetime', 'InitiatingProcessFolderPath:string', 'InitiatingProcessParentId:long',
  'InitiatingProcessParentFileName:string', 'InitiatingProcessParentCreationTime:datetime',
  'InitiatingProcessIntegrityLevel:string', 'InitiatingProcessTokenElevation:string'
];

// Defender XDR tables appear in Sentinel with TimeGenerated as well as Timestamp.
const xdrBase = ['Timestamp:datetime', 'TimeGenerated:datetime', 'DeviceId:string', 'DeviceName:string', 'ActionType:string', 'ReportId:long', 'AdditionalFields:dynamic'];

const cols = (...groups) => '(' + [].concat(...groups).join(', ') + ')';

module.exports = {
  SigninLogs: cols([
    'TimeGenerated:datetime', 'ResultType:string', 'ResultDescription:string', 'UserPrincipalName:string', 'UserDisplayName:string',
    'UserId:string', 'IPAddress:string', 'Location:string', 'LocationDetails:dynamic', 'AppDisplayName:string', 'AppId:string',
    'ClientAppUsed:string', 'UserAgent:string', 'ConditionalAccessStatus:string', 'AuthenticationRequirement:string',
    'Status:dynamic', 'DeviceDetail:dynamic', 'RiskLevelDuringSignIn:string', 'RiskState:string', 'CorrelationId:string'
  ]),
  SecurityEvent: cols([
    'TimeGenerated:datetime', 'EventID:int', 'Activity:string', 'Computer:string', 'Account:string', 'AccountType:string',
    'AccountName:string', 'AccountDomain:string', 'LogonType:int', 'LogonTypeName:string', 'IpAddress:string', 'IpPort:string',
    'WorkstationName:string', 'TargetUserName:string', 'TargetDomainName:string', 'TargetAccount:string',
    'SubjectUserName:string', 'SubjectDomainName:string', 'SubjectAccount:string', 'ServiceName:string', 'ShareName:string',
    'ShareLocalPath:string', 'RelativeTargetName:string', 'ObjectName:string', 'ObjectType:string', 'Properties:string',
    'AccessMask:string', 'Status:string', 'SubStatus:string', 'FailureReason:string', 'CommandLine:string',
    'NewProcessName:string', 'ParentProcessName:string', 'Process:string', 'EventData:string', 'ServiceFileName:string'
  ]),
  CommonSecurityLog: cols([
    'TimeGenerated:datetime', 'DeviceVendor:string', 'DeviceProduct:string', 'DeviceAction:string', 'Activity:string',
    'SourceIP:string', 'SourceHostName:string', 'SourceUserName:string', 'DestinationIP:string', 'DestinationHostName:string',
    'DestinationPort:int', 'RequestURL:string', 'RequestMethod:string', 'RequestClientApplication:string',
    'SentBytes:long', 'ReceivedBytes:long', 'ApplicationProtocol:string', 'CommunicationDirection:string'
  ]),
  DnsEvents: cols([
    'TimeGenerated:datetime', 'ClientIP:string', 'Computer:string', 'EventId:int', 'IPAddresses:string', 'Name:string',
    'QueryType:string', 'Result:string', 'ResultCode:int', 'SubType:string', 'MaliciousIP:string', 'IndicatorThreatType:string'
  ]),
  DeviceProcessEvents: cols(xdrBase, initiatingProcess, [
    'FileName:string', 'FolderPath:string', 'SHA1:string', 'SHA256:string', 'MD5:string', 'FileSize:long',
    'ProcessId:long', 'ProcessCommandLine:string', 'ProcessIntegrityLevel:string', 'ProcessTokenElevation:string',
    'ProcessCreationTime:datetime', 'AccountDomain:string', 'AccountName:string', 'AccountSid:string', 'AccountUpn:string',
    'AccountObjectId:string', 'LogonId:long'
  ]),
  DeviceNetworkEvents: cols(xdrBase, initiatingProcess, [
    'RemoteIP:string', 'RemotePort:int', 'RemoteUrl:string', 'LocalIP:string', 'LocalPort:int', 'Protocol:string',
    'LocalIPType:string', 'RemoteIPType:string'
  ]),
  DeviceRegistryEvents: cols(xdrBase, initiatingProcess, [
    'RegistryKey:string', 'RegistryValueType:string', 'RegistryValueName:string', 'RegistryValueData:string',
    'PreviousRegistryKey:string', 'PreviousRegistryValueName:string', 'PreviousRegistryValueData:string'
  ]),
  DeviceFileEvents: cols(xdrBase, initiatingProcess, [
    'FileName:string', 'FolderPath:string', 'SHA1:string', 'SHA256:string', 'MD5:string', 'FileSize:long',
    'FileOriginUrl:string', 'FileOriginReferrerUrl:string', 'FileOriginIP:string', 'PreviousFileName:string',
    'PreviousFolderPath:string', 'RequestAccountName:string', 'RequestSourceIP:string'
  ]),
  DeviceEvents: cols(xdrBase, initiatingProcess, [
    'FileName:string', 'FolderPath:string', 'SHA1:string', 'SHA256:string', 'MD5:string', 'FileSize:long',
    'AccountDomain:string', 'AccountName:string', 'AccountSid:string', 'RemoteUrl:string', 'RemoteDeviceName:string',
    'ProcessId:long', 'ProcessCommandLine:string', 'ProcessTokenElevation:string', 'RegistryKey:string',
    'RegistryValueName:string', 'RegistryValueData:string', 'RemoteIP:string', 'RemotePort:int', 'LocalIP:string',
    'LocalPort:int', 'FileOriginUrl:string', 'FileOriginIP:string', 'LogonId:long'
  ]),
  DeviceTvmSoftwareVulnerabilities: cols([
    'DeviceId:string', 'DeviceName:string', 'OSPlatform:string', 'OSVersion:string', 'OSArchitecture:string',
    'SoftwareVendor:string', 'SoftwareName:string', 'SoftwareVersion:string', 'CveId:string',
    'VulnerabilitySeverityLevel:string', 'RecommendedSecurityUpdate:string', 'RecommendedSecurityUpdateId:string',
    'CveTags:dynamic', 'CveMitigationStatus:string'
  ]),
  EmailEvents: cols([
    'Timestamp:datetime', 'TimeGenerated:datetime', 'NetworkMessageId:string', 'InternetMessageId:string',
    'SenderMailFromAddress:string', 'SenderFromAddress:string', 'SenderDisplayName:string', 'SenderFromDomain:string',
    'SenderMailFromDomain:string', 'SenderIPv4:string', 'RecipientEmailAddress:string', 'Subject:string',
    'EmailDirection:string', 'DeliveryAction:string', 'DeliveryLocation:string', 'ThreatTypes:string',
    'DetectionMethods:string', 'UrlCount:int', 'AttachmentCount:int', 'ReportId:long'
  ]),
  EmailAttachmentInfo: cols([
    'Timestamp:datetime', 'TimeGenerated:datetime', 'NetworkMessageId:string', 'SenderFromAddress:string',
    'SenderDisplayName:string', 'RecipientEmailAddress:string', 'RecipientObjectId:string', 'FileName:string',
    'FileType:string', 'SHA256:string', 'FileSize:long', 'ThreatTypes:string', 'ThreatNames:string',
    'DetectionMethods:string', 'ReportId:long'
  ]),
  IdentityQueryEvents: cols([
    'Timestamp:datetime', 'ActionType:string', 'Application:string', 'QueryType:string', 'QueryTarget:string',
    'Query:string', 'Protocol:string', 'AccountName:string', 'AccountDomain:string', 'AccountUpn:string',
    'AccountSid:string', 'AccountObjectId:string', 'AccountDisplayName:string', 'DeviceName:string', 'IPAddress:string',
    'Port:int', 'DestinationDeviceName:string', 'DestinationIPAddress:string', 'DestinationPort:int',
    'TargetDeviceName:string', 'TargetAccountUpn:string', 'TargetAccountDisplayName:string', 'Location:string',
    'ReportId:string', 'AdditionalFields:dynamic'
  ]),
  IdentityDirectoryEvents: cols([
    'Timestamp:datetime', 'ActionType:string', 'Application:string', 'TargetAccountUpn:string',
    'TargetAccountDisplayName:string', 'TargetDeviceName:string', 'DestinationDeviceName:string',
    'DestinationIPAddress:string', 'DestinationPort:int', 'Protocol:string', 'AccountName:string',
    'AccountDomain:string', 'AccountUpn:string', 'AccountSid:string', 'AccountObjectId:string',
    'AccountDisplayName:string', 'DeviceName:string', 'IPAddress:string', 'Port:int', 'Location:string', 'ISP:string',
    'ReportId:string', 'AdditionalFields:dynamic'
  ])
};
