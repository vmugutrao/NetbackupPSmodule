###################################################################################
# Netbackup Powershell Module                   
#
# Vishal Mugutrao
###################################################################################


# Release Notes
# 1.0 - Initial Release

# Define Global variables
$Global:content_type = 'application/vnd.netbackup+json;version=2.0'
$Global:port = '1556'

Function Set-NBcertrequirement
    {
    # Allow self-signed certificates
    if ([System.Net.ServicePointManager]::CertificatePolicy -notlike 'TrustAllCertsPolicy') 
        {
        Add-Type -TypeDefinition @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
	    public bool CheckValidationResult(
	        ServicePoint srvPoint, X509Certificate certificate,
	        WebRequest request, int certificateProblem) {
	        return true;
	    }
    }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy


    }
    }

Function Connect-NBSession
    {
    [CmdletBinding()]
    [Alias('nbconnect')]
    [OutputType([PSObject])]
    Param(
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $server,
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    Begin
        {
        # Force TLS v1.2
        Set-NBcertrequirement
        If(!(Test-Connection $server -Quiet -Count 2)){Throw "$server is not in network !!!"}
        $uri = "https://" + $server + ":" + $Global:port + "/netbackup/login"
        $body = @{
        userName=$($Credential.GetNetworkCredential().domain+'\'+$Credential.GetNetworkCredential().Username)
        password=$($Credential.GetNetworkCredential().Password)
        }
       }
    Process
        {
        $Global:NBSession = @()
        Try {
            $response = Invoke-RestMethod -Uri $uri -Method POST -ContentType $Global:content_type -Body (ConvertTo-Json -InputObject $body)
            $Status = 'Success'
            Write-Host "Session established with $server !!!" -ForegroundColor Green
            }
        Catch
            {
            $Status = 'Failed'
            Write-Host "Failed to setup session with $server !!!" -ForegroundColor Red            
            }
        $Properties = @{'Server'=$server;'Status'=$Status;'Token'=$($response.token)}
        $Global:NBSession = New-Object -TypeName psobject -Property $Properties
        }
    End
        {
        Return $NBSession | Select-Object Server,Status,Token
        }
    }

Function Disconnect-NBSession
    {
    [CmdletBinding()]
    [Alias('nbclose')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session)
    Begin
        {
        If($Session.Status -ne 'Success') { 
            Write-Information 'No active session found, Skipping ....' 
            Break }
        $response = $null
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/logout"
        $headers = @{
        "Authorization" = $Session.token
        }
        }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method POST -ContentType $Global:content_type -Headers $headers
            $Global:NBSession = $null
            Write-Host "Disconnected from $server !!!" -ForegroundColor Green
            }
        Catch
            {
            Write-Host "Failed to logout from Netbackup or session is already logout !!!" -ForegroundColor Red
            }
        }
    End
        {
        
        }

    }

Function Get-NBErrors
    {
    [CmdletBinding()]
    [Alias('nbalerts')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = $null
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/manage/alerts"
        $headers = @{
        "Authorization" = $Session.token
        }
        }
    Process
        {
        $query_params = @{
#  "page[limit]" = 100                   # This changes the default page size to 100
#  "filter" = "subCategory eq 'VMWARE'"  # This adds a filter to only show the alerts for job failures of VMWARE policy type
}
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get Netbackup alerts !!!" -ForegroundColor Red
            }
        $Output = @()
        Foreach($item in $response.data.attributes)
            {
            $Obj = @()
            $properties = @{NBServer="$server";Client="$($item.params.clientName)";JobID="$($item.params.jobId)";
            Status="$($item.params.status)";GeneratedAt=$($item.createdDateTime);
            PolicyName=$($item.params.policyName);Policytype=$($item.params.policyType);
            Error=$($item.params.errorMsg)}
            $Obj = New-Object -TypeName psobject -Property $Properties
            $Output += $Obj
            }
         
        }
    End
        {
        Return $Output | Select-Object NBServer,JobID,Client,PolicyName,Policytype,Status,Error,Generatedat | Format-Table -AutoSize
        }
    
    }

Function Get-NBJobs
    {
    [CmdletBinding()]
    [Alias('nbjobs')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [String]$Client
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = $null
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/admin/jobs"
        $headers = @{
        "Authorization" = $Session.token
        }
        #$query_params = @{
        #"page[limit]" = 100 }

        }
    Process
        {
        $response = @()
        $offset = 0
        $end = $true
        while(($offset -lt 133900) -and ($end -eq $true))
            {
            $r = @()  
            $query_params = @{
            "page[limit]" = 100;
            "page[offset]" = $offset
                }
            #$query_params
            try { $r += Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers }
            Catch {
                    $end = $false
                    Write-Warning "Maximum jobs has been fetched (Max: 133900)  "
                }
            $response = $response + $r
            $offset=$offset+100
            }

        $Output = $response.data.attributes | Select-Object JobID,clientname,state,policyName,policyType,schedulename,destinationMediaServerName,destinationStorageUnitName,startTime,endTime
        }
    End
        {
        return $Output | Format-Table -AutoSize
        }
    
    }

Function Get-NBPolicy
    {
    [CmdletBinding()]
    [Alias('nbpolicy')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/policies"
        $headers = @{
        "Authorization" = $Session.token
        }
        }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get Netbackup policies !!!" -ForegroundColor Red
            }
        $Output = $response.data | Select Type,ID
        }
    End
        {
        return $Output | Format-Table -AutoSize
        }
    }

Function Remove-NBPolicy
    {
    [CmdletBinding()]
    [Alias('nbpolremove')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    $Policy
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/policies/" + $Policy
        $headers = @{
        "Authorization" = $Session.token
        }
        }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method DELETE -ContentType $Global:content_type -Headers $headers
            Write-Host "$Policy deleted successfully.`n" -ForegroundColor Green
            }
        Catch
            {
            Write-Host "Failed to get deleted $Policy !!!" -ForegroundColor Red
            }
        }
    End
        {
        }
    }

Function Add-NBPolicy #Need to work on this
    {
    
    }
   
Function Get-NBStorageunits
    {
    [CmdletBinding()]
    [Alias('nbspolicy')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/storage/storage-units"
        $headers = @{
        "Authorization" = $Session.token
        }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get Storage units !!!" -ForegroundColor Red
            }
        }
    End
        {
        Return $response.data.attributes
        }

  }

Function Get-NBSLP
    {
    [CmdletBinding()]
    [Alias('nbslp')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/slps"
        $headers = @{
        "Authorization" = $Session.token
        }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get lifecycle policy (SLP) !!!" -ForegroundColor Red
            }
        Foreach($item in $response.data.attributes)
            {
            $Obj = @()
            $properties = @{NBServer="$server";StoragePolicy="$($item.slpName)";SLP_Window="$($item.OperationList.slpWindowName)";
            OperationType="$($item.OperationList.operationType)";TargetImportSLP=$($item.OperationList.targetImportSLP);
            TargetServer=$($item.OperationList.targetMasterServer)}
            $Obj = New-Object -TypeName psobject -Property $Properties
            $Output += $Obj
            }
        }
    End
        {
        Return $Output | Select-Object NBServer,StoragePolicy,SLP_Window,TargetServer,TargetImportSLP,OperationType | Format-Table -AutoSize
        }

  }

Function Get-NBTrustedServers
    {
    [CmdletBinding()]
    [Alias('nbhosts')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/servers/trusted-master-servers"
        $headers = @{
        "Authorization" = $Session.token
        }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get trusted server information !!!" -ForegroundColor Red
            }
        }
    End
        {
        Return $response.data.attributes
        }
    
    }

Function Get-NBBackupSize #Need to work on this
    {
    [CmdletBinding()]
    [Alias('nbbacksize')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    $Client
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/storage/backup-sizes"
        $headers = @{
        "Authorization" = $Session.token
        }
        $query_params = @{"clientName"=$Client}
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get backup size !!!" -ForegroundColor Red
            }
        }
    End
        {
        Return $response 
        }

  }

Function Get-NBLicense #Need to work on this
    {
    [CmdletBinding()]
    [Alias('nblicense')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/licensing/capacity"
        $headers = @{
        "Authorization" = $Session.token
        }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get license information !!!" -ForegroundColor Red
            }
        }
    End
        {
        Return $response.data.attributes.clientDetails.policyDetails
        }

  }

Function Get-NBHosts
    {
    [CmdletBinding()]
    [Alias('nbhosts')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/hosts/"
        $headers = @{
        "Authorization" = $Session.token
        }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Failed to get Hosts information !!!" -ForegroundColor Red
            }
        }
    End
        {
        Return $response.hosts
        }

  }
  
Function Get-NBClient #Need to work on this
    {
    [CmdletBinding()]
    [Alias('nbclients')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session
    )
    Begin
        {}
    Process
        {}
    End
        {}
    }

Function Remove-NBClientFromPolicy
    {
    [CmdletBinding()]
    [Alias('nbclientremove')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session,
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=1)]
    $policy,
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=3)]
    $Client
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/config/policies/" + $policy + "/clients/" +  $Client
        $headers = @{
        "Authorization" = $Session.token
        }
        }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method DELETE -ContentType $Global:content_type -Headers $headers
            Write-Host "$Client has been removed from $policy !!!" -ForegroundColor Gray
            }
        Catch
            {
            Write-Host "Failed to remove $Client, either its not present or you mentioned wrong policy !!!" -ForegroundColor Red
            }
        }
    End
        {
        
        }
    }

Function Get-NBImages
    {
    [CmdletBinding()]
    [Alias('nbimages')]
    [OutputType([PSObject])]
    Param(
    [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    $Session,
    [Parameter(ValueFromPipelineByPropertyName=$true,
    Position=1)]
    $Client,
    [Parameter(ValueFromPipelineByPropertyName=$true,
    Position=2)]
    $Policy
    )
    Begin
        {
        If($Session.Status -ne 'Success') 
            { Write-Warning 'No active session found, please use Connect-NBSession for new session' 
              Break }
        $response = @()
        $Output = @()
        $uri = $null
        $server = $Session.Server
        $basepath = "https://" + $server + ":" + $Global:port + "/netbackup"
        $uri = $basepath + "/catalog/images"
        $headers = @{
        "Authorization" = $Session.token
        }
        $query_params = @{
        "page[limit]" = 100
         }
        if($Client){
        $query_params = @{
        "page[limit]" = 100;
        "filter" = "clientName eq $($Client)"
         } }
        if($Policy){
        $query_params = @{
        "page[limit]" = 100;
        "filter" = "policyName eq $($Policy)"
         } }
    }
    Process
        {
        Try 
            {
            $response = Invoke-RestMethod -Uri $uri -Method GET -ContentType $Global:content_type -Body $query_params -Headers $headers
            }
        Catch
            {
            Write-Host "Unable to get the list of Netbackup images !!!" -ForegroundColor Red
            }
        }
    End
        {
        return $response.data.attributes | Select-Object JobID,ClientName,policyName,policyType,backupTime | Format-Table
        }
    }
