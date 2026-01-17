# Test TUI as admin - write results to file
$outFile = "C:\Users\Virgil\Desktop\sereno-dev\test_results.txt"
"=== TUI Test Results ===" | Out-File $outFile
"Timestamp: $(Get-Date)" | Out-File $outFile -Append

# First check if device exists
"Testing device access..." | Out-File $outFile -Append
try {
    $devicePath = "\\.\SerenoFilter"
    $fs = [System.IO.FileStream]::new($devicePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $fs.Close()
    "SUCCESS: Device $devicePath is accessible!" | Out-File $outFile -Append
} catch {
    "ERROR: Cannot access device: $($_.Exception.Message)" | Out-File $outFile -Append
}

# Run CLI status
"Running CLI status..." | Out-File $outFile -Append
& "C:\Users\Virgil\Desktop\sereno-dev\target\x86_64-pc-windows-msvc\debug\sereno.exe" status | Out-File $outFile -Append

"=== Test Complete ===" | Out-File $outFile -Append
