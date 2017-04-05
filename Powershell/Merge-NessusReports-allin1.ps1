<#

.SYNOPSIS
This powershell script merges Nessus scans. Updated 4 April 2017

.DESCRIPTION
This powershell script downloads all Nessus scans in the folder specified, merge the downloaded scans and uploads a consolidated report to the root of the Nessus host.

.EXAMPLE
./Merge-NessusReport.ps1 -server 192.168.1.1 -folder Test

.NOTES
The server argument defaults to 127.0.0.1 and is optional.

.LINK
https://github.com/dtctd/Scripts/blob/master/Powershell/Merge-NessusReports-allin1.ps1

#>
#Requires -Version 3.0

param (
    [string]$Server = "127.0.0.1",
    [Parameter(Mandatory=$true)][string]$Folder
 )

# Start Posh Nessus Functions
if (!(Test-Path variable:Global:NessusConn ))
{
    $Global:NessusConn = New-Object System.Collections.ArrayList
}
# Variables
$PermissionsId2Name = @{
    16 = 'Read-Only'
    32 = 'Regular'
    64 = 'Administrator'
    128 = 'Sysadmin'
 }
$PermissionsName2Id = @{
    'Read-Only' = 16
    'Regular' = 32
    'Administrator' = 64
    'Sysadmin' = 128
 }
$severity = @{
    0 ='Info'
    1 ='Low'
    2 ='Medium'
    3 ='High'
    4 ='Critical'
 } 
Function InvokeNessusRestRequest {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        $SessionObject,

        [Parameter(Mandatory=$false)]
        $Parameter,

        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [String]$Method,

        [Parameter(Mandatory=$false)]
        [String]$OutFile,

        [Parameter(Mandatory=$false)]
        [String]$ContentType,

        [Parameter(Mandatory=$false)]
        [String]$InFile

    )

    

    $RestMethodParams = @{
        'Method'        = $Method
        'URI'           =  "$($SessionObject.URI)$($Path)"
        'Headers'       = @{'X-Cookie' = "token=$($SessionObject.Token)"}
        'ErrorVariable' = 'NessusUserError'
    }

    if ($Parameter)
    {
        $RestMethodParams.Add('Body', $Parameter)
    }

    if($OutFile)
    {
        $RestMethodParams.add('OutFile', $OutFile)
    }

    if($ContentType)
    {
        $RestMethodParams.add('ContentType', $ContentType)
    }

    if($InFile)
    {
        $RestMethodParams.add('InFile', $InFile)
    }

    try
    {
        #$RestMethodParams.Uri
        $Results = Invoke-RestMethod @RestMethodParams
   
    }
    catch [Net.WebException] 
    {
        [int]$res = $_.Exception.Response.StatusCode
        if ($res -eq 401)
        {
            # Request failed. More than likely do to time-out.
            # Re-Authenticating using information from session.
            write-verbose -Message 'The session has expired, Re-authenticating'
            $ReAuthParams = @{
                'Method' = 'Post'
                'URI' =  "$($SessionObject.URI)/session"
                'Body' = @{'username' = $SessionObject.Credentials.UserName; 'password' = $SessionObject.Credentials.GetNetworkCredential().password}
                'ErrorVariable' = 'NessusLoginError'
                'ErrorAction' = 'SilentlyContinue'
            }

            $TokenResponse = Invoke-RestMethod @ReAuthParams

            if ($NessusLoginError)
            {
                Write-Error -Message 'Failed to Re-Authenticate the session. Session is being Removed.'
                $FailedConnection = $SessionObject
                [void]$Global:NessusConn.Remove($FailedConnection)
            }
            else
            {
                Write-Verbose -Message 'Updating session with new authentication token.'

                # Creating new object with updated token so as to replace in the array the old one.
                $SessionProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                $SessionProps.add('URI', $SessionObject.URI)
                $SessionProps.Add('Credentials',$SessionObject.Credentials)
                $SessionProps.add('Token',$TokenResponse.token)
                $SessionProps.Add('SessionId', $SessionObject.SessionId)
                $Sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $Sessionobj.pstypenames[0] = 'Nessus.Session'
                [void]$Global:NessusConn.Remove($SessionObject)
                [void]$Global:NessusConn.Add($Sessionobj)

                # Re-submit query with the new token and return results.
                $RestMethodParams.Headers = @{'X-Cookie' = "token=$($Sessionobj.Token)"}
                $Results = Invoke-RestMethod @RestMethodParams
            }
        }
        else
        {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    $Results
}
Function New-NessusSession {
    [CmdletBinding()]
    Param
    (
        # Nessus Server IP Address or FQDN to connect to.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$ComputerName,

        # Port number of the Nessus web service. Default 8834
        [int]
        $Port = 8834,


        # Credentials for connecting to the Nessus Server
        [Parameter(Mandatory=$true,
        Position=1)]
        [Management.Automation.PSCredential]$Credentials
    )

    Begin
    {
        
    }
    Process
    {
        if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -ne 'IgnoreCerts')
        {
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
            $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
            $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
            $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
            $ILGen = $MethodBuilder.GetILGenerator()
            $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
            $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
            $TypeBuilder.CreateType() | Out-Null

            # Disable SSL certificate validation
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts
        }

        $SessionProps = New-Object -TypeName System.Collections.Specialized.OrderedDictionary

        foreach($computer in $ComputerName)
        {
            $URI = "https://$($computer):$($Port)"
            $RestMethodParams = @{
                'Method' = 'Post'
                'URI' =  "$($URI)/session"
                'Body' = @{'username' = $Credentials.UserName; 'password' = $Credentials.GetNetworkCredential().password}
                'ErrorVariable' = 'NessusLoginError'
            }

            $TokenResponse = Invoke-RestMethod @RestMethodParams
            if ($TokenResponse)
            {
                $SessionProps.add('URI', $URI)
                $SessionProps.Add('Credentials',$Credentials)
                $SessionProps.add('Token',$TokenResponse.token)
                $SessionIndex = $Global:NessusConn.Count
                $SessionProps.Add('SessionId', $SessionIndex)
                $sessionobj = New-Object -TypeName psobject -Property $SessionProps
                $sessionobj.pstypenames[0] = 'Nessus.Session'
                
                [void]$Global:NessusConn.Add($sessionobj) 

                $sessionobj
            }
        }
    }
    End
    {
    }
}
Function Get-NessusFolder {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @()
    )

    Begin
    {
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Connection in $ToProcess)
        {
            $Folders =  InvokeNessusRestRequest -SessionObject $Connection -Path '/folders' -Method 'Get'

            if ($Folders -is [psobject])
            {
                foreach ($folder in $Folders.folders)
                {
                    $FolderProps = [ordered]@{}
                    $FolderProps.Add('Name', $folder.name)
                    $FolderProps.Add('FolderId', $folder.id)
                    $FolderProps.Add('Type', $folder.type)
                    $FolderProps.Add('Default', $folder.default_tag)
                    $FolderProps.Add('Unread', $folder.unread_count)
                    $FolderProps.Add('SessionId', $Connection.SessionId)
                    $FolderObj = New-Object -TypeName psobject -Property $FolderProps
                    $FolderObj.pstypenames[0] = 'Nessus.Folder'
                    $FolderObj
                }
            }
        }
    }
    End
    {
    }
}
Function Get-NessusScan {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$false,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $FolderId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Completed', 'Imported', 'Running', 'Paused', 'Canceled')]
        [string]
        $Status
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($FolderId)
        {
            $Params.Add('folder_id', $FolderId)
        }

        foreach($Connection in $ToProcess)
        {
            $Scans =  InvokeNessusRestRequest -SessionObject $Connection -Path '/scans' -Method 'Get' -Parameter $Params

            if ($Scans -is [psobject])
            {
                
                if($Status.length -gt 0)
                {
                    $Scans2Process = $Scans.scans | Where-Object {$_.status -eq $Status.ToLower()}
                }
                else
                {
                    $Scans2Process = $Scans.scans
                }
                foreach ($scan in $Scans2Process)
                {
                    $ScanProps = [ordered]@{}
                    $ScanProps.add('Name', $scan.name)
                    $ScanProps.add('ScanId', $scan.id)
                    $ScanProps.add('Status', $scan.status)
                    $ScanProps.add('Enabled', $scan.enabled)
                    $ScanProps.add('FolderId', $scan.folder_id)
                    $ScanProps.add('Owner', $scan.owner)
                    $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                    $ScanProps.add('Rules', $scan.rrules)
                    $ScanProps.add('Shared', $scan.shared)
                    $ScanProps.add('TimeZone', $scan.timezone)
                    $ScanProps.add('Scheduled', $scan.control)
                    $ScanProps.add('DashboardEnabled', $scan.use_dashboard)
                    $ScanProps.Add('SessionId', $Connection.SessionId)                 
                    $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                    $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())

                    if ($scan.starttime -cnotlike "*T*")
                    {
                        $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                    }
                    else
                    {
                        $StartTime = [datetime]::ParseExact($scan.starttime,"yyyyMMddTHHmmss",
                                     [System.Globalization.CultureInfo]::InvariantCulture,
                                     [System.Globalization.DateTimeStyles]::None)
                        $ScanProps.add('StartTime', $StartTime)
                    }
                    $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                    $ScanObj.pstypenames[0] = 'Nessus.Scan'
                    $ScanObj
                }
            }
        }
    }
    End
    {
    }
}
Function Show-NessusScanHost {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryId 
    )

    Begin{}
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {
                foreach ($Target in $ScanDetails.hosts)
                {
                    $HostProps = [ordered]@{}
                    $HostProps.Add('HostName', $Target.hostname)
                    $HostProps.Add('HostId', $Target.host_id)
                    $HostProps.Add('Critical', $Target.critical)
                    $HostProps.Add('High',  $Target.high)
                    $HostProps.Add('Medium', $Target.medium)
                    $HostProps.Add('Low', $Target.low)
                    $HostProps.Add('Info', $Target.info)
                    $HostProps.Add('ScanId', $ScanId)
                    $HostProps.Add('SessionId', $Connection.SessionId)
                    $HostObj = New-Object -TypeName psobject -Property $HostProps
                    $HostObj.pstypenames[0] = 'Nessus.Scan.Host'
                    $HostObj
                } 
            }
        }
    }
    End{}
}
Function Show-NessusScanHistory {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId
    )

    Begin
    {
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }
        $Params = @{}

        if($HistoryId)
        {
            $Params.Add('history_id', $HistoryId)
        }

        foreach($Connection in $ToProcess)
        {
            $ScanDetails =  InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)" -Method 'Get' -Parameter $Params

            if ($ScanDetails -is [psobject])
            {
                foreach ($History in $ScanDetails.history)
                {
                    $HistoryProps = [ordered]@{}
                    $HistoryProps['HistoryId'] = $History.history_id
                    $HistoryProps['UUID'] = $History.uuid
                    $HistoryProps['Status'] = $History.status
                    $HistoryProps['Type'] = $History.type
                    $HistoryProps['CreationDate'] = $origin.AddSeconds($History.creation_date).ToLocalTime()
                    $HistoryProps['LastModifiedDate'] = $origin.AddSeconds($History.last_modification_date).ToLocalTime()
                    $HistoryProps['SessionId'] = $Connection.SessionId
                    $HistObj = New-Object -TypeName psobject -Property $HistoryProps
                    $HistObj.pstypenames[0] = 'Nessus.Scan.History'
                    $HistObj
                } 
            }
        }
    }
    End{}
}
Function Export-NessusScan {
    [CmdletBinding()]
    Param
    (
       # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Nessus', 'HTML', 'PDF', 'CSV', 'DB')]
        [string]
        $Format,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [String]
        $OutFile,

        [Parameter(Mandatory=$false,
                   Position=3,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Vuln_Hosts_Summary', 'Vuln_By_Host', 
                     'Compliance_Exec', 'Remediations', 
                     'Vuln_By_Plugin', 'Compliance', 'All')]
        [string[]]
        $Chapters,

        [Parameter(Mandatory=$false,
                   Position=4,
                   ValueFromPipelineByPropertyName=$true)]
        [Int32]
        $HistoryID,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [securestring]
        $Password

    )

    Begin
    {
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        $ExportParams = @{}

        if($Format -eq 'DB' -and $Password)
        {
            $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $Password
            $ExportParams.Add('password', $Credentials.GetNetworkCredential().Password)
        }

        if($Format)
        {
            $ExportParams.Add('format', $Format.ToLower())
        }

        if($Chapters)
        {
            if ($Chapters -contains 'All') 
            {
                $ExportParams.Add('chapters', 'vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin;compliance')
            }
            else
            {           
                $ExportParams.Add('chapters',$Chapters.ToLower())
            }       
        }

        foreach($Connection in $ToProcess)
        {
            $path =  "/scans/$($ScanId)/export"
            Write-Verbose -Message "Exporting scan with Id of $($ScanId) in $($Format) format."
            $FileID = InvokeNessusRestRequest -SessionObject $Connection -Path $path  -Method 'Post' -Parameter $ExportParams
            if ($FileID -is [psobject])
            {
                $FileStatus = ''
                while ($FileStatus.status -ne 'ready')
                {
                    try
                    {
                        $FileStatus = InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/export/$($FileID.file)/status"  -Method 'Get'
                        Write-Verbose -Message "Status of export is $($FileStatus.status)"
                    }
                    catch
                    {
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                if ($FileStatus.status -eq 'ready')
                {
                    Write-Verbose -Message "Downloading report to $($OutFile)"
                    InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/export/$($FileID.file)/download" -Method 'Get' -OutFile $OutFile
                }
            }
        }
    }
    End
    {
    }
}
Function Remove-NessusScanHistory {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $ScanId,

		[Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [int32]
        $HistoryId
    )

    Begin{}
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Connection in $ToProcess)
        {
            Write-Verbose -Message "Removing history Id ($HistoryId) from scan Id $($ScanId)"
            
            $ScanHistoryDetails = InvokeNessusRestRequest -SessionObject $Connection -Path "/scans/$($ScanId)/history/$($HistoryId)" -Method 'Delete' -Parameter $Params

            if ($ScanHistoryDetails -eq '')
            {
                Write-Verbose -Message 'History Removed'
            }
            
            
        }
    }
    End{}
}
Function Import-NessusScan {
    [CmdletBinding()]
    Param
    (
        # Nessus session Id
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Index')]
        [int32[]]
        $SessionId = @(),

        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $File,

        [Parameter(Mandatory=$false,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [switch]
        $Encrypted,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [securestring]
        $Password
    )

    Begin
    {
        if($Encrypted)
        {
            $ContentType = 'application/octet-stream'
            $URIPath = 'file/upload?no_enc=1'
        }
        else
        {
            $ContentType = 'application/octet-stream'
            $URIPath = 'file/upload'
        }

        $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

        if($netAssembly)
        {
            $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
            $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

            $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

            if($instance)
            {
                $bindingFlags = "NonPublic","Instance"
                $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

                if($useUnsafeHeaderParsingField)
                {
                  $useUnsafeHeaderParsingField.SetValue($instance, $true)
                }
            }
        }

        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    }
    Process
    {
        $ToProcess = @()

        foreach($i in $SessionId)
        {
            $Connections = $Global:NessusConn
            
            foreach($Connection in $Connections)
            {
                if ($Connection.SessionId -eq $i)
                {
                    $ToProcess += $Connection
                }
            }
        }

        foreach($Conn in $ToProcess)
        {
            $fileinfo = Get-ItemProperty -Path $File
            $FilePath = $fileinfo.FullName
            $RestClient = New-Object RestSharp.RestClient
            $RestRequest = New-Object RestSharp.RestRequest
            $RestClient.UserAgent = 'Posh-SSH'
            $RestClient.BaseUrl = $Conn.uri
            $RestRequest.Method = [RestSharp.Method]::POST
            $RestRequest.Resource = $URIPath
            
            [void]$RestRequest.AddFile('Filedata',$FilePath, 'application/octet-stream')
            [void]$RestRequest.AddHeader('X-Cookie', "token=$($Connection.Token)")
            $result = $RestClient.Execute($RestRequest)
            if ($result.ErrorMessage.Length -gt 0)
            {
                Write-Error -Message $result.ErrorMessage
            }
            else
            {
                $RestParams = New-Object -TypeName System.Collections.Specialized.OrderedDictionary
                $RestParams.add('file', "$($fileinfo.name)")
                if ($Encrypted)
                {
                    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $Password
                    $RestParams.Add('password', $Credentials.GetNetworkCredential().Password)
                }

                $impParams = @{ 'Body' = $RestParams }
                $ImportResult = Invoke-RestMethod -Method Post -Uri "$($Conn.URI)/scans/import" -header @{'X-Cookie' = "token=$($Conn.Token)"} -Body (ConvertTo-Json @{'file' = $fileinfo.name;} -Compress) -ContentType 'application/json'
                if ($ImportResult.scan -ne $null)
                {
                    $scan = $ImportResult.scan
                    $ScanProps = [ordered]@{}
                    $ScanProps.add('Name', $scan.name)
                    $ScanProps.add('ScanId', $scan.id)
                    $ScanProps.add('Status', $scan.status)
                    $ScanProps.add('Enabled', $scan.enabled)
                    $ScanProps.add('FolderId', $scan.folder_id)
                    $ScanProps.add('Owner', $scan.owner)
                    $ScanProps.add('UserPermission', $PermissionsId2Name[$scan.user_permissions])
                    $ScanProps.add('Rules', $scan.rrules)
                    $ScanProps.add('Shared', $scan.shared)
                    $ScanProps.add('TimeZone', $scan.timezone)
                    $ScanProps.add('CreationDate', $origin.AddSeconds($scan.creation_date).ToLocalTime())
                    $ScanProps.add('LastModified', $origin.AddSeconds($scan.last_modification_date).ToLocalTime())
                    $ScanProps.add('StartTime', $origin.AddSeconds($scan.starttime).ToLocalTime())
                    $ScanProps.add('Scheduled', $scan.control)
                    $ScanProps.add('DashboardEnabled', $scan.use_dashboard)
                    $ScanProps.Add('SessionId', $Conn.SessionId)
                    
                    $ScanObj = New-Object -TypeName psobject -Property $ScanProps
                    $ScanObj.pstypenames[0] = 'Nessus.Scan'
                    $ScanObj
               }
            }
        }
    }
    End{}
}
# End Posh Nessus Fucntions
Function Export-Reports() {
    Write-host($(Get-Date -Format HH:mm) + " - Starting export")
    $session = New-NessusSession -ComputerName $Server -Credentials $Cred

    $folder = Get-NessusFolder -SessionId $session.SessionId | Where-Object {$_.name -eq $Folder}

    $scans = Get-NessusScan -SessionId $session.SessionId -FolderId $folder[0].FolderId | Where-Object {$_.Status -eq "completed" }

    $scans  | ForEach-Object{ 
        $scan = $_ 
        $name = $scan.Name -replace "[\\\/]", "_"
        $histories = Show-NessusScanHistory -SessionId $session.SessionId -ScanId $scan.ScanId | Where-Object {$_.Status -eq "completed"} 
        if ($histories) {
            if ($histories -eq 1 ) {
                $hist = $histories[0]
                $hosts = Show-NessusScanHost -SessionId $session.SessionId -ScanId $scan.ScanId -HistoryId $hist.HistoryId
                if ($hosts.Count  -gt 0) {
                    Write-host($(Get-Date -Format HH:mm) + " - Exporting $name")
                    Export-NessusScan -SessionId $session.SessionId -ScanId $scan.ScanId  -Format "nessus" -OutFile "$TargetDir\$name.nessus" -HistoryID $hist.HistoryId    
                }
            } else {
            $hist = $histories[$($histories.Count-1)]
            $hosts = Show-NessusScanHost -SessionId $session.SessionId -ScanId $scan.ScanId -HistoryId $hist.HistoryId
            if ($hosts.Count -gt 0) {
                Write-host($(Get-Date -Format HH:mm) + " - Exporting $name")
                Export-NessusScan -SessionId $session.SessionId -ScanId $scan.ScanId  -Format "nessus" -OutFile "$TargetDir\$name.nessus" -HistoryID $hist.HistoryId
                }
            }
        }
    }
    Write-host($(Get-Date -Format HH:mm) + " - Exports finished.") -ForegroundColor Green
}
Function Initialize() {
    Write-host($(Get-Date -Format HH:mm) + " - Initialising...")
    if((Test-Path -Path "$TargetDir\output\") -eq $True) {
        Debug "Output folder allready exists"
    }
    else {
        New-Item -ItemType Directory -Force -Path $TargetDir\Output\| out-null
    }
    if((Test-Path -Path "$TargetDir\Processed\") -eq $True ) {
        Debug "Processed folder allready exists"
    }
    else {
        New-Item -ItemType Directory -Force -Path $TargetDir\Processed\| out-null
        Debug "Processed folder created"
    }
        
    if((Test-Path -Path "$TargetDir\Output\consolidated.nessus") -eq $True) {
        Write-host($(Get-Date -Format HH:mm) + " - Removing old merge file...") -ForegroundColor Yellow
        Remove-Item -Path "$TargetDir\Output\consolidated.nessus" -Force
        Debug "Consolidated.nessus removed"
    }
}
Function Merge-Reports() {
    Write-host($(Get-Date -Format HH:mm) + " - Starting merge, please be patient it takes a while...")
    $First = Get-ChildItem $TargetDir -Filter *.nessus | Select -First 1
    $Last = Get-ChildItem $TargetDir -Filter *.nessus | Select -Last 1
    Debug "Firstfile is $First and the last file is $last"
       
    Get-ChildItem $TargetDir -Filter *.nessus | %{

        If($_.Name -ne $First.Name){
            $SkipLines = (Select-String -Path $_.FullName -SimpleMatch "<Report name=" | select -expand LineNumber)
        }
        else {
            $SkipLines = 0
        }
        
        If($_.Name -ne $Last.Name){
        $RemoveLines = 2
        }
        else {
        $RemoveLines = 0
        }

        Debug "$SkipLines lines skipped for $_.name length of file is $EndLine"
        
        StreamEdit $_.FullName $SkipLines $RemoveLines
        Move-Item $_.FullName $TargetDir\Processed -Force
    }
}
Function CountLines($InputFile){
    $count = 0
    $reader = New-Object System.IO.StreamReader ($InputFile)
    while ($reader.ReadLine() -ne $null){$count++}
    $reader.Close()
    return [int]$count
}
Function StreamEdit($InputFile,[int]$SkipLines,[int]$RemoveLines) {
    $TotalLines = CountLines($InputFile)
   
    $LinesToProcessCount = ($TotalLines - $RemoveLines)
    Debug "The total is $TotalLines and the lines to process is $LinesToProcessCount for $InputFile"
    $Curcount = 0
    $ins = New-Object System.IO.StreamReader ($InputFile)
    try {
        # skip the first N lines
        for( $s = 1; $s -le $SkipLines; $s++ ) {
            $ins.ReadLine() > $null
            
        }
        $Curcount = $Curcount + $SkipLines
        while( $Curcount -ne $LinesToProcessCount -and $Curcount -lt $TotalLines) {
            Debug "current: $curcount, to process: $LinesToProcessCount"
            $outs.WriteLine( $ins.ReadLine() )
            $Curcount++
        }
        Debug "Written $Curcount lines."
    }
    
    finally {
        Debug "Finished with $InputFile"
        $ins.Close()
    }
}
Function Debug($DebugMessage){
    if ($debug -eq 1) {
        write-host $DebugMessage
    }
        
}
Function Rename-Report($ReportName) {
    $InputFile = "$TargetDir\Output\consolidated.nessus"
    $stringToReplace = '\<Report name=\".*\"\sxmlns\:cm=\"http\:\/\/www\.nessus\.org\/cm\">'
    $replaceWith = '<Report name="' + $ReportName + ' ' + (get-date -format dd/MM/yyyy) +'" xmlns:cm="http://www.nessus.org/cm">'
    
    try {
    $reader = [System.IO.StreamReader] $InputFile
    $data = $reader.ReadToEnd()
    $reader.close()
    }
    
    finally {
        if ($reader -ne $null) {
            $reader.dispose()
        }
    }

    $data = $data -replace $stringToReplace, $replaceWith

    try {
        $writer = [System.IO.StreamWriter] $InputFile
        $writer.write($data)
        $writer.close()
    }

    finally {
        if ($writer -ne $null) {
            $writer.dispose()
        }
    }
}
Function Import-Report() {
    #Import-Module -Name Posh-Nessus
    Write-host($(Get-Date -Format HH:mm) + " - Starting import.")
    $session = New-NessusSession -ComputerName $Server -Credentials $Cred
    Import-NessusScan -SessionId $session.SessionId -File "$TargetDir\Output\consolidated.nessus" > $null
    Write-host($(Get-Date -Format HH:mm) + " - Import finished.") -ForegroundColor Green
}
Function Wait-FileRead($file) {
    While ($True) {
        Try { 
            [IO.File]::OpenWrite($file).Close() 
            Break
        }
        Catch { 
            Start-Sleep -Seconds 1 }
        }
}
Function Main() {
    $path = $PSScriptRoot
    $TargetDir = "$Path\Nessus"
    if(!(Test-Path -Path $TargetDir)) {
        Write-host($(Get-Date -Format HH:mm) + " - Creating $TargetDir") -ForegroundColor Yellow
        New-Item -ItemType directory -Path $TargetDir
    }

    $Cred = Get-Credential
    $ReportName = "Consolidated $Folder"
    Initialize
    Export-Reports
    try {
        $outs = New-Object System.IO.StreamWriter -ArgumentList ([IO.File]::Open(($TargetDir + "\Output\consolidated.nessus"),"Append"))
        Merge-Reports
    }
    finally {
        $outs.Close()
    }
    Rename-Report $ReportName
    Wait-FileRead($outs)
    Import-Report
    Write-host($(Get-Date -Format HH:mm) + " - Main finished") -ForegroundColor Green
}
# End Functions
Main
