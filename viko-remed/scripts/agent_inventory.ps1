$ErrorActionPreference = 'Stop'
$agents = @()
foreach ($root in @('C:\CloudResetPwdAgent', 'C:\CloudResetPwdUpdateAgent')) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $record = @{path=$root; version=''; log4j_files=@(); errors=@(); coverage='standard_directories_only'}
    try {
        $marker = Join-Path $root 'version'
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $version = (Get-Content -LiteralPath $marker -TotalCount 1).Trim()
            if ($version -match '^\d+\.\d+\.\d+$') { $record.version = $version }
            else { $record.errors += 'Version marker not recognized' }
        }
        # Only top-level and lib trees; skip bundled JRE and logs.
        $items = @(Get-ChildItem -LiteralPath $root -File -ErrorAction Stop)
        $lib = Join-Path $root 'lib'
        if (Test-Path -LiteralPath $lib -PathType Container) {
            $items += @(Get-ChildItem -LiteralPath $lib -File -Recurse -Depth 2 -ErrorAction Stop | Select-Object -First 3001)
        }
        if ($items.Count -gt 3000) { $record.errors += 'File budget exceeded' }
        $record.log4j_files = @($items | Select-Object -First 3000 | Where-Object {$_.Name -like '*log4j*.jar'} | ForEach-Object {$_.FullName})
    } catch { $record.errors += $_.Exception.GetType().Name }
    $agents += $record
}
@{agents=@($agents); coverage='standard_directories_only'} | ConvertTo-Json -Depth 6 -Compress
