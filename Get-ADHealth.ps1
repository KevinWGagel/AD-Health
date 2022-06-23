<#
.SYNOPSIS
    Performs some information gathering and runs some checks on the health of Active Directory
.DESCRIPTION
    Performs some information gathering and runs some checks on the health of Active Directory
.LINK
    https://www.virtuallyshane.com/posts/powershell-script-to-get-active-directory-information-and-health-check-after-upgrade-to-windows-server-2019
.EXAMPLE
    Get-ADHealth.ps1
    Performs some information gathering and runs some checks on the health of Active Directory
#>
<#
Changes from original:
Substituted multiple if/elseif statements with Switch statement
Substituted netdom with multiple PS equivalents for the FSMO info
Removed multiple unused variables and commands saving data to them
Added a logfile to save the output to while keeping the display of output
#>

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
    Write-Host "You must run this script from an elevated PowerShell session." -ForegroundColor Yellow
    Exit
}

#Create Log file
$LogFile = '.\ADHealthLog.txt'
Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue

#start with some statistics
$Computers = (Get-ADComputer -Filter *).Count
$Workstations = (Get-ADComputer -LDAPFilter "(&(objectClass=Computer)(!operatingSystem=*server*))" -Searchbase (Get-ADDomain).distinguishedName).Count
$Servers = (Get-ADComputer -LDAPFilter "(&(objectClass=Computer)(operatingSystem=*server*))" -Searchbase (Get-ADDomain).distinguishedName).Count
$Users = (Get-ADUser -filter *).Count
$FSMO1 = Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
$FSMO2 = Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
$ADForest = (Get-ADForest).ForestMode
$ADDomain = (Get-ADDomain).DomainMode 
$ADVer = Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object objectVersion 
$ADNUM = $ADVer -replace "@{objectVersion=", "" -replace "}", "" 

switch ($ADNUM) {
    30 { $srv = 'Windows Server 2003' }
    31 { $srv = 'Windows Server 2003 R2' }
    44 { $srv = 'Windows Server 2008' }
    47 { $srv = 'Windows Server 2008 R2' }
    56 { $srv = 'Windows Server 2012' }
    69 { $srv = 'Windows Server 2012 R2' }
    87 { $srv = 'Windows Server 2016' }
    88 { $srv = 'Windows Server 2019 & Windows Server 2022' }
    Default { $srv = $ADNUM }
}
Clear-Host
Write-Host ""
Write-Host "For the domain there are;" -ForegroundColor Yellow
Add-Content -Path $LogFile -Value "Started: $(Get-Date)" -Encoding UTF8
Write-Host "Computers =    "$Computers -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Computers: $($Computers)" -Encoding UTF8
Write-Host "Workstations = "$Workstations -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Workstations: $($Workstations)" -Encoding UTF8
Write-Host "Servers =       "$Servers -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Servers: $($Servers)" -Encoding UTF8
Write-Host "Users =        "$Users -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Users: $($Users)" -Encoding UTF8
Write-Host ""
Add-Content -Path $LogFile -Value "" -Encoding UTF8
Write-Host "Active Directory Info" -ForegroundColor Yellow
Add-Content -Path $LogFile -Value "Active Directory Info" -Encoding UTF8
Write-Host "Active Directory Forest Mode = "$ADForest -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Active Directory Forest Mode: $($ADForest)" -Encoding UTF8
Write-Host "Active Direcotry Domain Mode = "$ADDomain -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Active Directory Domain Mode: $($ADDomain)" -Encoding UTF8
Write-Host "Active Directory Schema Version is $ADNUM which corresponds to $Srv"  -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "Active Directory Schema Version is $($ADNUM) which corresponds to $($Srv)" -Encoding UTF8
Write-Host ""
Add-Content -Path $LogFile -Value "" -Encoding UTF8
Write-Host "FSMO Role Owners" -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "FSMO Role Owners" -Encoding UTF8
Write-Host "DomainNamingMaster "$FSMO1.DomainNamingMaster -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "DomainNamingMaster $($FSMO1.DomainNamingMaster)" -Encoding UTF8
Write-Host "SchemaMaster "$FSMO1.SchemaMaster -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "SchemaMaster $($FSMO1.SchemaMaster)" -Encoding UTF8
Write-Host "InfrastructureMaster "$FSMO2.InfrastructureMaster -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "InfrastructureMaster $($FSMO2.InfrastructureMaster)" -Encoding UTF8
Write-Host "PDCEmulator "$FSMO2.PDCEmulator -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "PDCEmulator : $($FSMO2.PDCEmulator)" -Encoding UTF8
Write-Host "RIDMaster "$FSMO2.RIDMaster -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "RIDMaster: $($FSMO2.RIDMaster)" -Encoding UTF8
Write-Host ""
Add-Content -Path $LogFile -Value "" -Encoding UTF8
Write-Host "Active Directory Health Check" -ForegroundColor Yellow
Add-Content -Path $LogFile -Value "Active Directory Health Check" -Encoding UTF8

$GetForest = [system.directoryservices.activedirectory.forest]::GetCurrentForest()
$DCServers = $GetForest.domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }

$Timeout = "60"

ForEach ($DC in $DCServers) {
    $Identity = $DC
    #Ping test
    if ( Test-Connection -ComputerName $Identity -Count 1 -ErrorAction SilentlyContinue) {
        Write-Host $Identity `t Ping `t Success -ForegroundColor Green
        Add-Content -Path $LogFile -Value "$($Identity) Pinged successfully" -Encoding UTF8

        #Netlogon Service Status
        $ServiceStatus = start-job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name "Netlogon" -ErrorAction SilentlyContinue } -ArgumentList $Identity
        Wait-Job $ServiceStatus -Timeout $Timeout | Out-Null
        if ($ServiceStatus.State -like 'Running') {
            Write-Host $Identity `t Netlogon service check timed out. -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "WARNING: Netlogon service check timed out **********" -Encoding UTF8
            Stop-Job $ServiceStatus
        }
        else {
            $ServiceStatus1 = Receive-Job $ServiceStatus
            if ($ServiceStatus1.Status -eq "Running") {
                Write-Host $Identity `t $($ServiceStatus1.Name) `t $($ServiceStatus1.Status) -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status)" -Encoding UTF8
            }
            Else {
                Write-Host $Identity `t $($ServiceStatus1.Name) `t $($ServiceStatus1.Status) -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status) **********" -Encoding UTF8
            }
        }

        #NTDS Service Status
        $ServiceStatus = Start-Job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name "NTDS" -ErrorAction SilentlyContinue } -ArgumentList $Identity
        Wait-Job $ServiceStatus -Timeout $Timeout | Out-Null
        if ($ServiceStatus -like "Running") {
            Write-Host $Identity `t NTDS Service timed out. -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: NTDS Service timed out **********" -Encoding UTF8
            Stop-Job $ServiceStatus
        }
        else {
            $ServiceStatus1 = Receive-Job $ServiceStatus
            if ($ServiceStatus1.Status -eq "Running") {
                Write-Host $Identity `t $ServiceStatus1.Name `t $ServiceStatus1.Status -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status)" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t $ServiceStatus1.Name `t $ServiceStatus1.Status -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status) **********" -Encoding UTF8
            }
        }
        
        #DNS Service Status
        $ServiceStatus = Start-Job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name "DNS" -ErrorAction SilentlyContinue } -ArgumentList $Identity
        Wait-Job $ServiceStatus -Timeout $Timeout | Out-Null
        if ($ServiceStatus -like "Running") {
            Write-Host $Identity `t DNS Service timed out. -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: DNS Service timed out **********" -Encoding UTF8
            Stop-Job $ServiceStatus
        }
        else {
            $ServiceStatus1 = Receive-Job $ServiceStatus
            if ($ServiceStatus1.Status -eq "Running") {
                Write-Host $Identity `t $ServiceStatus1.Name `t $ServiceStatus1.Status -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status)" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t $ServiceStatus1.Name `t $ServiceStatus1.Status -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity): $($ServiceStatus1.Name) - $($ServiceStatus1.Status) **********" -Encoding UTF8
            }
        }

        #Netlogons Status
        add-type -AssemblyName microsoft.visualbasic 
        $cmp = "microsoft.visualbasic.strings" -as [type]
        $sysvol = start-job -scriptblock { dcdiag /test:netlogons /s:$($args[0]) } -ArgumentList $Identity
        wait-job $sysvol -timeout $timeout | Out-Null
        if ($sysvol.state -like "Running") {
            Write-Host $Identity `t Netlogons Test TimeOut -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: Netlogons test timed out **********" -Encoding UTF8
            stop-job $sysvol
        }
        else {
            $sysvol1 = Receive-job $sysvol
            if ($cmp::instr($sysvol1, "passed test NetLogons")) {
                Write-Host $Identity `t Netlogons Test passed -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity) Netlogons test passed" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t Netlogons Test Failed -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity) Netlogons test FAILED **********" -Encoding UTF8
            }
        }

        #Replication Status
        add-type -AssemblyName microsoft.visualbasic 
        $cmp = "microsoft.visualbasic.strings" -as [type]
        $sysvol = start-job -scriptblock { dcdiag /test:Replications /s:$($args[0]) } -ArgumentList $Identity
        wait-job $sysvol -timeout $timeout | Out-Null
        if ($sysvol.state -like "Running") {
            Write-Host $Identity `t Replications Test TimeOut -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: Replication test timed out **********" -Encoding UTF8
            stop-job $sysvol
        }
        else {
            $sysvol1 = Receive-job $sysvol
            if ($cmp::instr($sysvol1, "passed test Replications")) {
                Write-Host $Identity `t Replications Test passed -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity) Replications test passed" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t Replications Test Failed -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity) Replications test FAILED **********" -Encoding UTF8
            }
        }

        #Services Status
        add-type -AssemblyName microsoft.visualbasic 
        $cmp = "microsoft.visualbasic.strings" -as [type]
        $sysvol = start-job -scriptblock { dcdiag /test:Services /s:$($args[0]) } -ArgumentList $Identity
        wait-job $sysvol -timeout $timeout | Out-Null
        if ($sysvol.state -like "Running") {
            Write-Host $Identity `t Services Test TimeOut -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: Services test timed out **********" -Encoding UTF8
            stop-job $sysvol
        }
        else {
            $sysvol1 = Receive-job $sysvol
            if ($cmp::instr($sysvol1, "passed test Services")) {
                Write-Host $Identity `t Services Test passed -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity) Services test passed" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t Services Test Failed -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity) Services test FAILED **********" -Encoding UTF8
            }
        }

        #Advertising Status
        add-type -AssemblyName microsoft.visualbasic 
        $cmp = "microsoft.visualbasic.strings" -as [type]
        $sysvol = start-job -scriptblock { dcdiag /test:Advertising /s:$($args[0]) } -ArgumentList $Identity
        wait-job $sysvol -timeout $timeout | Out-Null
        if ($sysvol.state -like "Running") {
            Write-Host $Identity `t Advertising Test TimeOut -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: Advertising test timed out **********" -Encoding UTF8
            stop-job $sysvol
        }
        else {
            $sysvol1 = Receive-job $sysvol
            if ($cmp::instr($sysvol1, "passed test Advertising")) {
                Write-Host $Identity `t Advertising Test passed -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity) Advertising test passed" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t Advertising Test Failed -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity) Advertising test FAILED **********" -Encoding UTF8
            }
        }

        #FSMOCheck Status
        add-type -AssemblyName microsoft.visualbasic 
        $cmp = "microsoft.visualbasic.strings" -as [type]
        $sysvol = start-job -scriptblock { dcdiag /test:FSMOCheck /s:$($args[0]) } -ArgumentList $Identity
        wait-job $sysvol -timeout $timeout | Out-Null
        if ($sysvol.state -like "Running") {
            Write-Host $Identity `t FSMOCheck Test TimeOut -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$($Identity) WARNING: FSMOCheck test timed out **********" -Encoding UTF8
            stop-job $sysvol
        }
        else {
            $sysvol1 = Receive-job $sysvol
            if ($cmp::instr($sysvol1, "passed test FsmoCheck")) {
                Write-Host $Identity `t FSMOCheck Test passed -ForegroundColor Green
                Add-Content -Path $LogFile -Value "$($Identity) FSMOCheck test passed" -Encoding UTF8
            }
            else {
                Write-Host $Identity `t FSMOCheck Test Failed -ForegroundColor Red
                Add-Content -Path $LogFile -Value "********** $($Identity) FSMOCheck test FAILED **********" -Encoding UTF8
            }
        }
        Write-Host ""
        Add-Content -Path $LogFile -Value "" -Encoding UTF8
    }
    else {
        Write-Host "$Identity Ping FAILED" -ForegroundColor Red
        Add-Content -Path $LogFile -Value "********** $($Identity) Ping test FAILED **********" -Encoding UTF8
    }
}
Add-Content -Path $LogFile -Value "Completed: $(Get-Date)"
