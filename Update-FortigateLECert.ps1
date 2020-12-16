<#
.SYNOPSIS
This is a simple Powershell Core script to update Fortigate SSL certificate with a LetsEncrypt cert

.DESCRIPTION
This script uses the Posh-Acme module to RENEW a LetsEncrypt certificate, and then adds it to a Fortigate over SSH. This is designed to be ran consistently, and will not update the cert if Posh-Acme hasn't been setup previously.

.EXAMPLE
./Update-FortigateLECert.ps1 -Fortigate 10.0.0.1 -Credential (new-credential admin admin) -MainDomain fg.example.com

.NOTES
This requires Posh-Acme to be preconfigured. The easiest way to do so is with the following command:
    New-PACertificate -Domain fg.example.com,fgt.example.com,vpn.example.com -AcceptTOS -Contact me@example.com -DnsPlugin Cloudflare -PluginArgs @{CFAuthEmail="me@example.com";CFAuthKey='xxx'}

.LINK
https://github.com/SoarinFerret/Posh-FGT-LE

#>



Param(
    [string]$Fortigate,
    [Parameter(ParameterSetName = "SecureCreds")]
    [pscredential]$Credential,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [string]$Username,
    [Parameter(ParameterSetName = "PlainTextPassword")]
    [String]$Password,
    [String]$MainDomain,
    [Switch]$ForceRenew,
    [Switch]$UseExisting
)

function Use-SelfSignedCerts {
    if($PSEdition -ne "Core"){
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class PolicyCert : ICertificatePolicy {
                public PolicyCert() {}
                public bool CheckValidationResult(
                    ServicePoint sPoint, X509Certificate cert,
                    WebRequest wRequest, int certProb) {
                    return true;
                }
            }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object PolicyCert
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    }else{
        Write-Warning -Message "Function not supported in PSCore. Just use the '-SkipCertificateCheck' flag" | Out-File $LogFile -Append
    }
}

function Connect-Fortigate {
    Param(
        $Fortigate,
        $Credential
    )

    $postParams = @{username=$Credential.UserName;secretkey=$Credential.GetNetworkCredential().Password}
    try{
        Write-Verbose "Authenticating to 'https://$Fortigate/logincheck' with username: $($Credential.UserName)" | Out-File $LogFile -Append
        #splat arguments
        $splat = @{
            Uri = "https://$Fortigate/logincheck";
            SessionVariable = "session";
            Method = 'POST';
            Body = $postParams
        }
        if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}

        $authRequest = Invoke-WebRequest @splat
    }catch{
        Write-Verbose "Failed to authenticate to Fortigate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to authenticate to Fortigate with error: `n`t$_"
    }
    Write-Verbose "Authentication successful!" | Out-File $LogFile -Append
    $csrftoken = ($authRequest.Headers['Set-Cookie'] | where {$_ -like "ccsrftoken=*"}).split('"')[1]

    Set-Variable -Scope Global -Name "FgtServer" -Value $Fortigate
    Set-Variable -Scope Global -Name "FgtSession" -Value $session
    Set-Variable -Scope Global -Name "FgtCSRFToken" -Value $csrftoken
}

function Invoke-FgtRestMethod {
    Param(
        $Endpoint,
        [ValidateSet("Default","Delete","Get","Head","Merge","Options","Patch","Post","Put","Trace")]
        $Method = "Get",
        $Body = $null
    )

    Write-Verbose "Building Headers" | Out-File $LogFile -Append
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type','application/x-www-form-urlencoded')
    # Add csrf cookie
    $headers.Add('X-CSRFTOKEN',$FgtCSRFToken)

    $splat = @{
        Headers = $headers;
        Uri = "https://$FgtServer/api/v2/$($Endpoint.TrimStart('/'))";
        WebSession = $FgtSession;
        Method = $Method;
        Body = $body | ConvertTo-Json
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    return Invoke-RestMethod @splat
}

function Disconnect-Fortigate {
    Write-Verbose "Building Headers" | Out-File $LogFile -Append
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Accept','application/json')
    $headers.Add('Content-Type','application/x-www-form-urlencoded')
    # Add csrf cookie
    $headers.Add('X-CSRFTOKEN',$FgtCSRFToken)
    
    # logout
    $splat = @{
        Headers = $headers;
        Uri = "https://$FgtServer/logout";
        WebSession = $fgtSession;
        Method = "GET"
    }
    if($PSEdition -eq "Core"){$splat.Add("SkipCertificateCheck",$true)}
    $logoutRequest = Invoke-RestMethod @splat

    Remove-Variable -Scope Global -Name "FgtServer"
    Remove-Variable -Scope Global -Name "FgtSession" 
    Remove-Variable -Scope Global -Name "FgtCSRFToken"
    return $logoutRequest
}

function Upload-FgtCertificate {
    Param(
        $CertificatePath,
        $CertName,
        $PfxPassword
    )
    $newCertParams = @{
        type = 'pkcs12'
        certname=$CertName
        password=[PSCredential]::new(0, $PfxPassword).GetNetworkCredential().Password
        scope='global'
        file_content = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CertificatePath))
    }
    Write-Verbose "Uploading Certificate" | Out-File $LogFile -Append
    try{
        Invoke-FgtRestMethod -Endpoint "/monitor/vpn-certificate/local/import/" -Body $newCertParams -Method "Post"
    }catch{
        Write-Verbose "Failed to upload certificate with error: `n`t$_" | Out-File $LogFile -Append
        throw "Failed to upload certificate with error:`n`t$_"
    }
}

function Update-FgtAdminCert {
    Param(
        $CertName
    )
    $body = @{'admin-server-cert' = $CertName}
    Invoke-FgtRestMethod -Endpoint "/cmdb/system/global" -Body $body -Method "Put"
}

function Update-FgtSslVpnCert{
    Param(
        $CertName
    )
    $body = @{'servercert' = $CertName}
    Invoke-FgtRestMethod -Endpoint "/cmdb/vpn.ssl/settings" -Body $body -Method "Put"
}

Import-Module Posh-Acme
$LogFile = '.\UpdateFortigate.log'
Get-Date | Out-File $LogFile -Append
Write-Output "Starting Certificate Renewal for $($Fortigate)" | Out-File $LogFile -Append
if($UseExisting){
    $cert = Get-PACertificate -MainDomain $MainDomain
}else{
    $splat = @{
        MainDomain = $MainDomain
    }
    if($ForceRenew){$splat.add("Force",$true)}
    $cert = Submit-Renewal @splat
}
if($cert){
    Write-Output "...Renewal Complete!" | Out-File $LogFile -Append

    if($PSCmdlet.ParameterSetName -eq "PlainTextPassword"){
        Write-Warning "You shouldn't use plaintext passwords on the commandline" | Out-File $LogFile -Append
        $Credential = New-Credential -Username $env:FGT_USER -Password $env:FGT_PASS
    }

    $certname = "LetsEncrypt_$(get-date -Format 'yyyy-MM-dd')"

    Connect-Fortigate -Fortigate $Fortigate -Credential $Credential
    Write-Output "Updating the LetsEncrypt Certificate on the FGT" | Out-File $LogFile -Append
    Upload-FgtCertificate -CertificatePath $cert.PfxFullChain -CertName $certname -PfxPassword ("poshacme" | ConvertTo-SecureString -AsPlainText -Force)
    Write-Output "Updating the Admin certificate on the FGT" | Out-File $LogFile -Append
    ## this command fails every first time with "The response ended prematurely" - no idea why, but it works, so I don't really care
    try{
        Update-FgtAdminCert -CertName $certname
    }catch{}
    Write-Output "Updating the SSLVPN certificate on the FGT" | Out-File $LogFile -Append
    Update-FgtSslVpnCert -CertName $certname
    Disconnect-Fortigate

}else{
    Write-Output "No need to update certificate!" | Out-File $LogFile -Append
}
