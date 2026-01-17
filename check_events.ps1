# Check recent system events for driver-related issues
$events = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 30 -ErrorAction SilentlyContinue
$events | Where-Object {
    $_.Message -match 'Sereno' -or
    $_.ProviderName -eq 'Service Control Manager' -or
    $_.Id -in @(7000, 7001, 7045)
} | Format-Table TimeCreated, Id, ProviderName, Message -AutoSize -Wrap
