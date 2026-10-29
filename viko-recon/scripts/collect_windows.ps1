# VIKO Windows collector. Requires Windows PowerShell 5.1 and .NET compression.
# $config is supplied by Ansible. No exploit payloads, service changes or patches.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:Started = [DateTime]::UtcNow
$script:Deadline = $script:Started.AddSeconds([Math]::Max(1, [int]$config.scan_seconds))
$script:Observations = New-Object 'System.Collections.Generic.List[object]'
$script:Errors = New-Object 'System.Collections.Generic.List[object]'
$script:ErrorCount = 0
$script:FileCount = 0
$script:ArchiveCount = 0
$script:NestedBytes = 0L
$script:BudgetExhausted = $false
$script:Completed = New-Object 'System.Collections.Generic.List[string]'
$script:Absent = New-Object 'System.Collections.Generic.List[string]'
$script:Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

function Add-Problem([string]$Location, [string]$Reason) {
    $script:ErrorCount++
    if ($script:Errors.Count -lt 100) { $script:Errors.Add(@{location=$Location; reason=$Reason}) }
}
function Test-Expired {
    if ([DateTime]::UtcNow -ge $script:Deadline) { $script:BudgetExhausted=$true; return $true }
    return $false
}
function Add-Observation([string]$Component, [string]$Path, [string]$Version, [string]$Source, $Jndi=$null) {
    $family = if ($Component -eq 'php') {'php'} elseif ($Component -in @('struts2-core','xwork-core')) {'struts'} else {'log4j'}
    if ($family -notin @($config.checks)) { return }
    if ($script:Observations.Count -ge [int]$config.max_observations) { Add-Problem $Path 'limite_componentes'; return }
    $script:Observations.Add(@{component=$Component; path=$Path; version=$Version; version_source=$Source; jndi_lookup=$Jndi})
}
function Read-ZipEntry($Entry, [long]$Limit) {
    if ($Entry.Length -gt $Limit) { Add-Problem $Entry.FullName 'entrada_excede_limite'; return $null }
    if ($Entry.CompressedLength -gt 0 -and ($Entry.Length / $Entry.CompressedLength) -gt 300) {
        Add-Problem $Entry.FullName 'ratio_compresion_excesivo'; return $null
    }
    $s=$null; $memory=$null
    try {
        $s=$Entry.Open(); $memory=New-Object IO.MemoryStream
        $buffer=New-Object byte[] 8192
        while (($n=$s.Read($buffer,0,$buffer.Length)) -gt 0) {
            if (($memory.Length+$n) -gt $Limit) { Add-Problem $Entry.FullName 'lectura_excede_limite'; return $null }
            if (Test-Expired) { return $null }
            $memory.Write($buffer,0,$n)
        }
        return ,$memory.ToArray()
    } finally {
        if ($s) {$s.Dispose()}; if ($memory) {$memory.Dispose()}
    }
}
function Read-Properties([string]$Text) {
    $result=@{}
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\s*([^#!\s=:]+)\s*[=:]\s*(.*?)\s*$') {$result[$Matches[1]]=$Matches[2]}
    }
    return $result
}
function Inspect-Archive($Stream, [string]$Path, [int]$Depth=0) {
    if (Test-Expired) {return}
    $script:ArchiveCount++
    if ($script:ArchiveCount -gt [int]$config.max_archives) {Add-Problem $Path 'limite_archivos_comprimidos'; return}
    $zip=$null
    try {
        # Bound central-directory allocation before requesting .Entries.
        [void]$Stream.Seek([Math]::Max(0,$Stream.Length-65557),[IO.SeekOrigin]::Begin)
        $tail=New-Object byte[] ([int][Math]::Min(65557,$Stream.Length))
        $offset=0
        while ($offset -lt $tail.Length) {
            $n=$Stream.Read($tail,$offset,$tail.Length-$offset)
            if ($n -le 0) {break}; $offset+=$n
        }
        $index=[Text.Encoding]::GetEncoding(28591).GetString($tail).LastIndexOf(('PK'+[char]5+[char]6),[StringComparison]::Ordinal)
        if ($index -lt 0 -or ($index+22) -gt $tail.Length) {Add-Problem $Path 'zip_sin_directorio_clasico'; return}
        $count=[BitConverter]::ToUInt16($tail,$index+10)
        if ($count -eq 65535 -or [BitConverter]::ToUInt16($tail,$index+4) -ne 0 -or [BitConverter]::ToUInt16($tail,$index+6) -ne 0) {Add-Problem $Path 'zip64_o_multivolumen_no_inspeccionado'; return}
        if ($count -gt [int]$config.max_entries) {Add-Problem $Path 'demasiadas_entradas_zip'; return}
        [void]$Stream.Seek(0,[IO.SeekOrigin]::Begin)
        $zip=[IO.Compression.ZipArchive]::new($Stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        if ($zip.Entries.Count -gt [int]$config.max_entries) {Add-Problem $Path 'demasiadas_entradas_zip'; return}
        $names=@($zip.Entries | ForEach-Object {$_.FullName.Replace('\','/')})
        $core=@($names | Where-Object {$_.EndsWith('org/apache/logging/log4j/core/Logger.class')}).Count -gt 0
        $jndi=@($names | Where-Object {$_.EndsWith('org/apache/logging/log4j/core/lookup/JndiLookup.class')}).Count -gt 0
        $struts=@($names | Where-Object {$_.EndsWith('org/apache/struts2/dispatcher/Dispatcher.class')}).Count -gt 0
        $log1=@($names | Where-Object {$_.EndsWith('org/apache/log4j/Logger.class')}).Count -gt 0
        $found=@{}
        foreach ($entry in $zip.Entries) {
            if (Test-Expired) {return}
            $name=$entry.FullName.Replace('\','/')
            if ($name -notmatch '(^|/)META-INF/maven/.+/pom\.properties$') {continue}
            $data=Read-ZipEntry $entry 131072
            if ($null -eq $data) {continue}
            $p=Read-Properties ([Text.Encoding]::UTF8.GetString($data))
            $artifact=$p['artifactId']; $group=$p['groupId']
            $valid=($group -eq 'org.apache.logging.log4j' -and $artifact -in @('log4j-core','log4j-api')) -or
                   ($group -eq 'org.apache.struts' -and $artifact -eq 'struts2-core') -or
                   ($group -eq 'org.apache.struts.xwork' -and $artifact -eq 'xwork-core') -or
                   ($group -eq 'log4j' -and $artifact -eq 'log4j')
            if ($valid) {
                $component=if ($artifact -eq 'log4j') {'log4j1'} else {$artifact}
                $signal=if ($component -eq 'log4j-core') {$jndi} else {$null}
                Add-Observation $component $Path ([string]$p['version']) 'maven_pom' $signal
                $found[$component]=$true
            }
        }
        $base=($Path -split '!')[-1] -replace '^.*[/\\]',''
        if ($base -match '^(log4j-core|log4j-api|struts2-core|xwork-core|log4j)-(.+)\.jar$') {
            $component=$Matches[1].ToLower(); $version=$Matches[2]; $source='filename'
            if ($component -eq 'log4j') {$component='log4j1'}
            if (-not $found.ContainsKey($component)) {
                $manifest=$zip.GetEntry('META-INF/MANIFEST.MF')
                if ($manifest) {
                    $data=Read-ZipEntry $manifest 131072
                    if ($null -ne $data -and [Text.Encoding]::UTF8.GetString($data) -match '(?m)^Implementation-Version:\s*(\S+)') {
                        if ($Matches[1] -eq $version) {$source='manifest_and_filename'}
                        else {Add-Problem $Path 'version_manifest_y_nombre_discrepan'; $version=''; $source='conflict'}
                    }
                }
                $signal=if ($component -eq 'log4j-core') {$jndi} else {$null}
                Add-Observation $component $Path $version $source $signal
                $found[$component]=$true
            }
        }
        if ($core -and -not $found.ContainsKey('log4j-core')) {Add-Observation 'log4j-core' $Path '' 'embedded_classes' $jndi}
        if ($struts -and -not $found.ContainsKey('struts2-core')) {Add-Observation 'struts2-core' $Path '' 'embedded_classes'}
        if ($log1 -and -not $found.ContainsKey('log4j1')) {Add-Observation 'log4j1' $Path '' 'embedded_classes'}
        foreach ($entry in $zip.Entries) {
            if (Test-Expired) {return}
            if ($entry.FullName -notmatch '\.(jar|war|ear|zip)$') {continue}
            $child=$Path+'!'+$entry.FullName
            if ($Depth -ge [int]$config.archive_depth) {Add-Problem $child 'profundidad_maxima'; continue}
            if (($script:NestedBytes+$entry.Length) -gt ([long]$config.max_total_nested_mb*1048576)) {Add-Problem $child 'presupuesto_total_anidados'; continue}
            $bytes=Read-ZipEntry $entry ([long]$config.max_nested_mb*1048576)
            if ($null -eq $bytes) {continue}
            $script:NestedBytes+=$bytes.Length
            $nested=[IO.MemoryStream]::new($bytes,$false)
            try {Inspect-Archive $nested $child ($Depth+1)} finally {$nested.Dispose()}
        }
    } catch {Add-Problem $Path 'zip_no_legible_o_no_soportado'} finally {if ($zip) {$zip.Dispose()}}
}
function Inspect-File($File) {
    if (-not $script:Seen.Add($File.FullName)) {return}
    $script:FileCount++
    if ($File.Name -match '^php(?:-cgi)?\.exe$' -and 'php' -in @($config.checks)) {
        $version=''
        try {
            $v=$File.VersionInfo.ProductVersion
            if ($v -match '(\d+\.\d+\.\d+(?:[-.]?(?:RC|beta|alpha)\d+)?)') {$version=$Matches[1]}
        } catch {Add-Problem $File.FullName 'version_binario_no_legible'}
        Add-Observation 'php' $File.FullName $version 'windows_product_version'
    }
    if ($File.Extension -notin @('.jar','.war','.ear','.zip') -or -not (@($config.checks) | Where-Object {$_ -in @('log4j','struts')})) {return}
    if ($File.Length -gt ([long]$config.max_archive_mb*1048576)) {Add-Problem $File.FullName 'zip_excede_tamano'; return}
    $stream=$null
    try {
        $stream=[IO.File]::Open($File.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        Inspect-Archive $stream $File.FullName
    } catch {Add-Problem $File.FullName 'sin_permiso_o_error_lectura'} finally {if ($stream) {$stream.Dispose()}}
}
function Walk-Roots {
    foreach ($root in @($config.windows_roots)) {
        if ((Test-Expired) -or $script:FileCount -ge [int]$config.max_files) {$script:BudgetExhausted=$true; break}
        try {$item=Get-Item -LiteralPath $root -Force -ErrorAction Stop} catch {
            if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {$script:Absent.Add($root)}
            else {Add-Problem $root 'raiz_no_legible'}
            continue
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {Add-Problem $root 'reparse_point_no_seguido'; continue}
        $stack=New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($item.FullName)
        while ($stack.Count -gt 0) {
            if ((Test-Expired) -or $script:FileCount -ge [int]$config.max_files) {$script:BudgetExhausted=$true; break}
            $dir=$stack.Pop()
            try {$children=Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop} catch {Add-Problem $dir 'directorio_no_legible'; continue}
            foreach ($child in $children) {
                if ((Test-Expired) -or $script:FileCount -ge [int]$config.max_files) {$script:BudgetExhausted=$true; break}
                $exclude=$false
                foreach ($e in @($config.windows_excludes)) {
                    if ($child.FullName.Equals($e,[StringComparison]::OrdinalIgnoreCase) -or $child.FullName.StartsWith($e.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) {$exclude=$true; break}
                }
                if ($exclude) {continue}
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {Add-Problem $child.FullName 'reparse_point_no_seguido'; continue}
                if ($child.PSIsContainer) {$stack.Push($child.FullName)} else {Inspect-File $child}
            }
        }
        if (-not $script:BudgetExhausted) {$script:Completed.Add($root)}
    }
}
function Invoke-Bounded([string]$Exe,[string]$Arguments) {
    if (Test-Expired) {return $null}
    $p=New-Object Diagnostics.Process
    $p.StartInfo=[Diagnostics.ProcessStartInfo]::new($Exe,$Arguments)
    $p.StartInfo.UseShellExecute=$false
    $p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true
    $p.StartInfo.RedirectStandardError=$true
    try {
        [void]$p.Start()
        $read=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
        $ms=[Math]::Max(1,[Math]::Min([int]$config.command_timeout*1000,($script:Deadline-[DateTime]::UtcNow).TotalMilliseconds))
        if (-not $p.WaitForExit([int]$ms)) {$p.Kill(); Add-Problem $Exe 'timeout'; return $null}
        $text=$read.GetAwaiter().GetResult()
        [void]$err.GetAwaiter().GetResult()
        if ($p.ExitCode -ne 0) {Add-Problem $Exe 'consulta_fallida'; return $null}
        if ($text.Length -gt 4194304) {Add-Problem $Exe 'salida_excede_limite'; return $null}
        return $text
    } catch {Add-Problem $Exe 'error_consulta'; return $null} finally {$p.Dispose()}
}
$script:Stage='runtime_initialization'
$services=@(); $processes=@(); $containers=@(); $localAddresses=@(); $os=$null
try {
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {throw 'PowerShell 5.1 required'}
    Add-Type -AssemblyName System.IO.Compression
    $script:Stage='system_inventory'
    $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
    $localAddresses=@()
    try {
        foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) {continue}
            foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
                $address=$unicast.Address
                if (-not [Net.IPAddress]::IsLoopback($address) -and -not $address.IsIPv6LinkLocal -and $address.ToString() -notin $localAddresses) {
                    $localAddresses+=@($address.ToString())
                }
            }
        }
    } catch {Add-Problem 'direcciones_locales' 'consulta_no_disponible'}
    $script:Stage='service_inventory'
    $services=@()
    try {
        $services=@(Get-CimInstance Win32_Service -OperationTimeoutSec 15 | Where-Object {$_.Name -match 'php|apache|httpd|nginx|tomcat|instana|ds_agent|trend|cloudreset|W3SVC'} | ForEach-Object {@{name=$_.Name; state=$_.State}})
    } catch {Add-Problem 'servicios' 'consulta_no_disponible'}
    $processes=@()
    try {$processes=@(Get-Process | Where-Object {$_.ProcessName -match 'php|apache|httpd|nginx|tomcat|java|instana|ds_agent|trend|cloudreset'} | ForEach-Object {
        $exe=''; try {$exe=$_.Path} catch {}
        @{name=$_.ProcessName; pid=$_.Id; executable=$exe}
    })} catch {Add-Problem 'procesos' 'consulta_no_disponible'}
    $script:Stage='php_inventory'
    if ('php' -in @($config.checks)) {
        $php=Get-Command php.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($php) {
            $file=Get-Item -LiteralPath $php.Source
            Inspect-File $file
            if ($config.run_php_version) {
                $text=Invoke-Bounded $php.Source '-n -v'
                if ($text -match '(?m)^PHP\s+(\S+)') {Add-Observation 'php' $php.Source $Matches[1] 'php_cli_no_ini'}
            }
        }
    }
    $containers=@()
    if ($config.container_inventory) {
        foreach ($engine in @('docker','podman')) {
            $cmd=Get-Command ($engine+'.exe') -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd) {
                $text=Invoke-Bounded $cmd.Source 'ps --format "{{.ID}}|{{.Image}}|{{.Names}}"'
                $running=@()
                foreach ($line in ($text -split '\r?\n')) {if ($line) {$a=$line -split '\|',3; if ($a.Count -eq 3) {$running+=@{id=$a[0]; image=$a[1]; name=$a[2]}}}}
                $containers+=@{engine=$engine; status=$(if ($null -eq $text) {'no_evaluado'} else {'consultado'}); running=$running; contents_scanned=$false}
            }
        }
    }
    if ($config.php_inventory_only) {
        # Explicit finite scope; additional application drives require later roots.
        $roots=@('C:\PHP','C:\Program Files\PHP','C:\Program Files (x86)\PHP',
                 'C:\xampp\php','C:\wamp\bin\php','C:\wamp64\bin\php')
        if ($php) {$roots+=Split-Path -Parent $php.Source}
        foreach ($proc in $processes) {
            if ($proc.name -match '^php' -and $proc.executable) {$roots+=Split-Path -Parent $proc.executable}
        }
        $config.windows_roots=@($roots | Select-Object -Unique)
    }
    $script:Stage='file_search'
    Walk-Roots
    $searchState=if ($script:ErrorCount -gt 0 -or $script:BudgetExhausted) {'parcial'} elseif ($script:Completed.Count -eq 0) {'sin_rutas_revisadas'} else {'completado_en_rutas'}
    $families=@{}
    foreach ($family in @($config.checks)) {
        $families[$family]=@{status=$searchState; sources=@('archivos en raíces configuradas')}
        if ($family -eq 'php') {
            $families[$family].sources=@('PHP CLI en PATH','metadatos de ejecutables en raíces configuradas')
            $families[$family].runtime_web='pendiente_de_correlacion'
            if ($config.php_inventory_only -and $script:ErrorCount -eq 0 -and -not $script:BudgetExhausted) {$families[$family].status='completado_en_fuentes'}
            $families[$family].note='No acredita ausencia de PHP fuera de las fuentes consultadas ni en contenedores.'
        }
    }
    $script:Stage='result_serialization'
    $result=@{
        schema_version=1; collector_version='1.5-piloto'; status='recolectado'; platform='windows'; timestamp_utc=[DateTime]::UtcNow.ToString('o')
        system=@{hostname=[Environment]::MachineName; ip_addresses=$localAddresses; PRETTY_NAME=$os.Caption; VERSION_ID=$os.Version; build=$os.BuildNumber; architecture=$os.OSArchitecture}
        observations=@($script:Observations.ToArray()); services=$services; processes=$processes; containers=$containers
        trend_local=@{services=@($services | Where-Object {$_.name -match 'ds_agent|trend'}); note='Evidencia local; estado de protección y cobertura requieren consola de Seguridad.'}
        coverage=@{
            file_search=$searchState; families=$families
            roots_requested=@($config.windows_roots); roots_completed=@($script:Completed.ToArray()); roots_absent=@($script:Absent.ToArray()); excluded=@($config.windows_excludes)
            files_seen=$script:FileCount; archives_seen=$script:ArchiveCount; errors_count=$script:ErrorCount; errors=@($script:Errors.ToArray()); budget_exhausted=$script:BudgetExhausted
            elapsed_seconds=[Math]::Round(([DateTime]::UtcNow-$script:Started).TotalSeconds,2); limits=$config
            limitations=@('Solo rutas configuradas; no prueba ausencia global.','Contenedores: solo inventario; imágenes y contenido interno no inspeccionados.','No correlaciona automáticamente bibliotecas con aplicaciones ni exposición pública.','No evalúa condiciones de explotación ni configuraciones de Struts/PHP.','Los volúmenes adicionales requieren raíces explícitas; no se siguen junctions ni reparse points.')
        }
    }
} catch {
    $result=@{status='no_evaluado'; platform='windows'; reason=('Fallo interno del recolector Windows en '+$script:Stage); timestamp_utc=[DateTime]::UtcNow.ToString('o'); diagnostics=@{code='collector_exception'; stage=$script:Stage; exception_type=$_.Exception.GetType().Name; line=$_.InvocationInfo.ScriptLineNumber}}
    if ($script:Observations.Count -gt 0) {
        $result.status='recolectado'
        $result.observations=@($script:Observations.ToArray())
        $result.system=@{hostname=[Environment]::MachineName; ip_addresses=$localAddresses}
        $result.services=$services; $result.processes=$processes; $result.containers=$containers
        $result.coverage=@{file_search='parcial'; limits=$config; errors_count=($script:ErrorCount+1); errors=@($script:Errors.ToArray())+@(@{location=$script:Stage; reason='collector_exception'}); roots_requested=@($config.windows_roots); roots_completed=@($script:Completed.ToArray()); roots_absent=@($script:Absent.ToArray()); budget_exhausted=$script:BudgetExhausted}
    }
}
[Console]::WriteLine('VIKO_VULN_JSON:'+($result | ConvertTo-Json -Depth 30 -Compress))
