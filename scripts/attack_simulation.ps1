<#
.SYNOPSIS
    Windows PowerShell Attack Simulator for Linux VM SOC Lab
.DESCRIPTION
    Simulates rapid SSH connection attempts from Windows against the Linux VM
    to verify that the SOC Agent automatically isolates the attacker's IP.
.PARAMETER TargetIp
    The IP address of the Linux VM.
.PARAMETER Attempts
    Number of attempts to send (default: 15).
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$TargetIp,

    [int]$Attempts = 15,
    [int]$Port = 22
)

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  ATTACK SIMULATION: SSH Brute Force against $TargetIp" -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan

Write-Host "[*] Checking connectivity to $TargetIp on port $Port..." -ForegroundColor Gray
$tcpTest = Test-NetConnection -ComputerName $TargetIp -Port $Port -WarningAction SilentlyContinue

if (-not $tcpTest.TcpTestSucceeded) {
    Write-Host "[!] ERROR: Cannot reach $TargetIp on port $Port. Ensure the VM is online and network is bridged." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Target is reachable. Starting $Attempts rapid connection attempts..." -ForegroundColor Green

$blocked = $false
for ($i = 1; $i -le $Attempts; $i++) {
    $time = (Get-Date).ToString("HH:mm:ss")
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connectTask = $client.ConnectAsync($TargetIp, $Port)
        $completed = $connectTask.Wait(1500) # 1.5s timeout
        
        if ($completed -and $client.Connected) {
            Write-Host "[$time] [ATTEMPT #$i] -> Connection established to SSH service." -ForegroundColor DarkYellow
            $client.Close()
        } else {
            Write-Host "[$time] [BLOCKED] Attempt #$i -> TIMEOUT! Attacker IP appears to be dropped." -ForegroundColor Red
            $blocked = $true
            break
        }
    } catch {
        Write-Host "[$time] [BLOCKED] Attempt #$i -> CONNECTION REFUSED! Firewall active." -ForegroundColor Red
        $blocked = $true
        break
    }
    Start-Sleep -Milliseconds 400
}

Write-Host ""
Write-Host "[*] Verifying final isolation status..." -ForegroundColor Gray
Start-Sleep -Seconds 2
$finalCheck = Test-NetConnection -ComputerName $TargetIp -Port $Port -WarningAction SilentlyContinue

if (-not $finalCheck.TcpTestSucceeded -or $blocked) {
    Write-Host "=======================================================" -ForegroundColor Green
    Write-Host "  DEFENSE SUCCESSFUL!" -ForegroundColor Green
    Write-Host "  SOC Agent detected the activity and blocked your IP." -ForegroundColor Green
    Write-Host "  Target $TargetIp is now quarantined and unreachable." -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
} else {
    Write-Host "[-] Note: Target is still responding. Verify that sensor_daemon.py is running on the VM." -ForegroundColor Yellow
}
