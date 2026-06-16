# Script to clean up unnecessary files from the scanning service
# This will remove all files except the essential ones

# Files to keep
$keep = @(
    '.env',
    'requirements.txt',
    'simple_scan_service.py',
    'README.md',
    'cleanup.ps1'  # This script itself
)

# Get all items in the current directory
$items = Get-ChildItem -Path . -Force

foreach ($item in $items) {
    if ($item.Name -notin $keep) {
        try {
            if ($item.PSIsContainer) {
                # Remove directory and all its contents
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "Removed directory: $($item.Name)"
            } else {
                # Remove file
                Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                Write-Host "Removed file: $($item.Name)"
            }
        } catch {
            Write-Warning "Failed to remove $($item.Name): $_"
        }
    }
}

Write-Host "Cleanup complete. The following files remain:"
Get-ChildItem -Path . -Force | Select-Object Name
