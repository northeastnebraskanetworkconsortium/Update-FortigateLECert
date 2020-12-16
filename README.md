# Update-FortigateLECert

This script uses Posh-ACME and Let's Encrypt to update SSL certificate for HTTPS remote access and SSL-VPN access.  
## How To Use:

### Script Platform

This script utilizes the Fortigate API. Therefore, it should be compatible with any current operating system capable in running Powershell.  For testing and it's production use, only Windows machines have actively been used.
If running Windows 7 SP1, 8.1 2008 R2 SP1, 2012, or 2012 R2, you must first install PowerShell 5.1, available at [https://aka.ms/WMF5Download](https://aka.ms/WMF5Download).

#### PowerShell version

This script is designed to run on PowerShell 5.1 or greater.  There have been issues on some PowerShell Core, so it is recommended not to use PowerShell Core at this time.  

#### Install Posh-ACME module

Run command to install Posh-ACME:
```powershell
Install-Module -Name Posh-ACME -Scope AllUsers -AcceptLicense
```

#### Request initial certificate
The script is designed to handle the renewals automatically, so you need to request the initial certificate manually.  (For a list of currently supported DnsPlugins, visit https://github.com/rmbolger/Posh-ACME/wiki/List-of-Supported-DNS-Providers.)  In PowerShell:

```powershell
New-PACertificate -Domain sts.example.com -AcceptTOS -Contact me@example.com -DnsPlugin Cloudflare -PluginArgs @{CFAuthEmail="me@example.com";CFAuthKey='xxx'}

# After the above completes, run the following
$MainDomain = 'fg.example.com'

# the '-UseExisting' flag is useful when the certifcate is not yet expired
./Update-FortigateLECert.ps1 -MainDomain $MainDomain -UseExisting
```
### Normal Use
To normally run it:

```powershell
./Update-FortigateLECert.ps1 -MainDomain $MainDomain
```

### Force Renewals

You can force a renewal with the '-ForceRenew' switch:

```powershell
./Update-FortigateLECert.ps1 -MainDomain $MainDomain -ForceRenew
```
### Other Notes

#### Switch Mutual Exclusivity

The '-ForceRenew' and '-UseExisting' switches are mutually exclusive, with '-UseExisting' superceeding '-ForceRenew'.

#### Logging

This script is set to automatically log the process and create a persistent log file in the same directory the script is located.  The name of the log file is UpdateFortigate.txt

#### Accessing the certificate(s) directly

Upon a successful request, you can directly access the certificates by visiting the following directory

```powershell
# Issue this command to enter into the Let's Encrypt directory
cd ~\appdata\Local\Posh-ACME\acme-v02.api.letsencrypt.org\

# Next, do a 'cd', then press Tab to auto populate the next directory.  This directory represents your account number.
cd [Tab]

# Perform the 'cd' - Tab again, which will enter into the next directory, which should be the name of the certificate you requested.
cd [Tab]

# Open Windows Explorer to access the certificates via GUI, if desired
start .\
```
If needing to manually install the certificate, the password by default is 'poshacme'

### Fortigate-LetsEncrypt-Renewal.xml

This XML file is a sample scheduled task that can be imported into the Windows Task Scheduler to handle the automatic renewal process.  There are a few modifications that will need to be made following the import:
- General Tab
    - Change User or Group
        - Use administrator account, either local or domain
- Triggers
    - Change date / time (optional)
- Actions
    - Edit Task
        - Add arguments
            - Change sts.example.com to FQDN of ADFS server
        - Start in
            - Replace with path of actual location of the script
