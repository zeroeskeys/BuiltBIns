function port-scan-tcp {
    param (
        [Parameter(Mandatory=$true)][array]$hosts,
        [Parameter(Mandatory=$true)][array]$ports
    )

    $outFile = ".\scanresults.txt"
    foreach ($targethost in $hosts) {
        foreach ($port in $ports) {
            $existing = Get-Content $outFile -ErrorAction SilentlyContinue | Select-String "^$targethost,tcp,$port,"
            if ($existing) {
                $existing.Line
                continue
            }

            $result = "$targethost,tcp,$port,"
            $client = New-Object System.Net.Sockets.TcpClient
            $connect = $client.ConnectAsync($targethost, $port)

            for ($i = 0; $i -lt 10; $i++) {
                if ($connect.IsCompleted) { break }
                Start-Sleep -Milliseconds 100
            }

            $client.Close()

            if ($connect.IsFaulted -and $connect.Exception.InnerException.Message -match "actively refused") {
                $state = "Closed"
            } elseif ($connect.Status -eq "RanToCompletion") {
                $state = "Open"
            } else {
                $state = "Filtered"
            }

            $line = "$result$state"
            Write-Host $line
            $line | Out-File -Append -FilePath $outFile
        }
    }
}
<#
Examples of usage:

# Scan a single port on a single host
port-scan-tcp 192.168.1.100 445

# Scan multiple ports on a single host
port-scan-tcp 192.168.1.100 (22, 80, 443, 445)

# Scan a single port across multiple hosts
port-scan-tcp (Get-Content .\ips.txt) 3389

# Scan multiple ports across multiple hosts
port-scan-tcp (Get-Content .\ips.txt) (Get-Content .\ports.txt)

# Sweep a subnet for specific ports (e.g., 135, 137, 445)
0..255 | ForEach-Object { port-scan-tcp "192.168.0.$_" (135,137,445) }

# Read non-sequential port list from file and scan one host
port-scan-tcp 10.10.0.1 (Get-Content .\ports.txt)

# Scan a port range
port-scan-tcp 192.168.1.100 (20..25)

# Combine ranges and specific ports
port-scan-tcp 192.168.1.100 @(22, 80, 443) + (1000..1005)


Notes:
- Port list files must be plain text, one port per line.
- IP list files must be plain text, one IP per line.
- Results are saved in scanresults.txt and reused to skip already-scanned ports.
- TCP scanning only; not for UDP or ICMP.

#>
