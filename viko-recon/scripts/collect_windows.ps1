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
# VIKO PHP evidence 1.6: isolated queries share the existing global deadline.
function Invoke-JsonProbe([string]$Body) {
    $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ErrorActionPreference='Stop'; "+$Body))
    $text=Invoke-Bounded "$PSHOME\powershell.exe" ("-NoProfile -NonInteractive -EncodedCommand "+$enc)
    if ($null -eq $text) {return $null}
    try {return ($text | ConvertFrom-Json -ErrorAction Stop)} catch {return $null}
}
function Get-ServicesBounded {
    $old=$config.command_timeout
    $config.command_timeout=[Math]::Min(3,[int]$old)
    try {
        foreach ($method in @('scm','cim','wmi')) {
            if (Test-Expired) {break}
            $body=switch ($method) {
                'scm' { '@{items=@(Get-Service -ErrorAction Stop | Where-Object {$_.Name -match "php|apache|httpd|nginx|tomcat|instana|ds_agent|trend|cloudreset|W3SVC|WAS"} | ForEach-Object {@{name=$_.Name; state=$_.Status.ToString(); source="ServiceController"}})} | ConvertTo-Json -Depth 5 -Compress' }
                'cim' { '@{items=@(Get-CimInstance Win32_Service -OperationTimeoutSec 1 -ErrorAction Stop | Where-Object {$_.Name -match "php|apache|httpd|nginx|tomcat|instana|ds_agent|trend|cloudreset|W3SVC|WAS"} | ForEach-Object {@{name=$_.Name; state=$_.State; source="CIM"}})} | ConvertTo-Json -Depth 5 -Compress' }
                'wmi' { '@{items=@(Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object {$_.Name -match "php|apache|httpd|nginx|tomcat|instana|ds_agent|trend|cloudreset|W3SVC|WAS"} | ForEach-Object {@{name=$_.Name; state=$_.State; source="WMI"}})} | ConvertTo-Json -Depth 5 -Compress' }
            }
            $answer=Invoke-JsonProbe $body
            if ($null -ne $answer -and $null -ne $answer.items) {
                $script:ServiceCoverage=@{status='consultado'; method=$method}
                return @($answer.items)
            }
        }
        $script:ServiceCoverage=@{status='no_evaluado'; method='scm_cim_wmi'}
        Add-Problem 'servicios_auxiliares' 'consultas_agotadas_o_timeout'
        return @()
    } finally {$config.command_timeout=$old}
}
function Get-WebRuntimeBounded {
    # Only approved attributes and extracted paths are returned, never XML/config dumps.
    $body=@'
$ErrorActionPreference='Stop'
$answer=@{processes=@(); config=@(); binaries=@(); errors=@(); files_consulted=@(); status='correlacion_parcial'}
$paths=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
try {
    $answer.processes=@(Get-Process -ErrorAction Stop | Where-Object {$_.ProcessName -match 'php|apache|httpd|nginx|w3wp|tomcat|java|instana|ds_agent|trend|cloudreset'} | ForEach-Object {
        $exe=''; try {$exe=$_.Path} catch {}
        @{name=$_.ProcessName; pid=$_.Id; executable=$exe}
    })
} catch {$answer.errors+=@{location='procesos_php_web'; reason='consulta_no_disponible'}}
$apphost=Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (Test-Path -LiteralPath $apphost) {
    try {
        Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
        $sm=New-Object Microsoft.Web.Administration.ServerManager
        try {
            $count=0
            foreach ($site in $sm.Sites) {
                foreach ($app in $site.Applications) {
                    if (++$count -gt 128) {throw 'ApplicationLimit'}
                    try {
                        $wc=$sm.GetWebConfiguration($site.Name,$app.Path)
                        foreach ($h in $wc.GetSection('system.webServer/handlers').GetCollection()) {
                            $processor=[Environment]::ExpandEnvironmentVariables([string]$h.GetAttributeValue('scriptProcessor'))
                            $exe=($processor -split '\|',2)[0].Trim('"')
                            if ($exe -match '(?i)^[A-Z]:\\[^\r\n]*\\php-cgi\.exe$') {
                                [void]$paths.Add($exe)
                                $answer.config+=@{server='iis'; file='effective_handlers'; site=$site.Name; application=$app.Path; target=$exe; directive='FastCgiModule'; state='handler_configurado'; site_state=$site.State.ToString()}
                            }
                        }
                    } catch {$answer.errors+=@{location='iis_handlers'; reason='aplicacion_no_legible'}}
                }
            }
        } finally {$sm.Dispose()}
    } catch {$answer.errors+=@{location='iis'; reason='consulta_efectiva_no_disponible'}}
}
$queue=New-Object 'System.Collections.Generic.Queue[string]'
foreach ($proc in $answer.processes) {
    if ($proc.executable -and $proc.name -match '^php') {[void]$paths.Add($proc.executable)}
    if ($proc.executable -and $proc.name -match '^(httpd|apache|nginx)') {
        $dir=Split-Path -Parent $proc.executable
        foreach ($p in @((Join-Path $dir 'conf\nginx.conf'),(Join-Path $dir 'conf\httpd.conf'),(Join-Path (Split-Path -Parent $dir) 'conf\httpd.conf'))) {
            if (Test-Path -LiteralPath $p) {$queue.Enqueue($p)}
        }
    }
}
foreach ($p in @('C:\nginx\conf\nginx.conf','C:\Apache24\conf\httpd.conf','C:\xampp\apache\conf\httpd.conf','C:\PHP\php.exe')) {
    if (Test-Path -LiteralPath $p) {if ($p -match '\.exe$') {[void]$paths.Add($p)} else {$queue.Enqueue($p)}}
}
$seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
while ($queue.Count -gt 0 -and $seen.Count -lt 64) {
    $file=$queue.Dequeue()
    if (-not $seen.Add($file)) {continue}
    try {
        $item=Get-Item -LiteralPath $file -ErrorAction Stop
        if ($item.Length -gt 262144) {throw 'SizeLimit'}
        $answer.files_consulted+=@{path=$file; sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash}
        $n=0
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            $n++; $s=$line.Trim()
            if ($s.StartsWith('#')) {continue}
            if ($s -match '(?i)^(Include|IncludeOptional|include)\s+([^;]+)') {
                $inc=$Matches[2].Trim().Trim('"')
                if ($inc -notmatch '\$' -and [IO.Path]::IsPathRooted($inc)) {
                    foreach ($child in @(Get-ChildItem -Path $inc -File -ErrorAction SilentlyContinue | Select-Object -First 64)) {$queue.Enqueue($child.FullName)}
                } else {$answer.errors+=@{location=$file; reason='include_relativo_o_variable_pendiente'}}
            }
            if ($s -match '(?i)^(LoadModule\s+php\S*|FcgidWrapper|fastcgi_pass|SetHandler|ProxyPassMatch)\s+') {
                $directive=$Matches[1]; $target='no_resuelto'
                if ($s -match '(?i)([A-Z]:[\\/][^"\r\n]*?php(?:-cgi|[0-9]+apache[0-9_]*)\.(?:exe|dll))') {$target=$Matches[1]; [void]$paths.Add($target)}
                elseif ($s -match '([A-Za-z0-9_.-]+:\d{1,5})') {$target=$Matches[1]}
                $answer.config+=@{server='apache_nginx'; file=$file; line=$n; directive=$directive; target=$target; state='configurada_en_disco'}
            }
        }
    } catch {$answer.errors+=@{location=$file; reason='config_no_legible'}}
}
foreach ($exe in @($paths | Select-Object -First 64)) {
    try {
        $file=Get-Item -LiteralPath $exe -ErrorAction Stop
        $version=''
        if ($file.VersionInfo.ProductVersion -match '(\d+\.\d+\.\d+(?:[-.]?(?:RC|beta|alpha)\d+)?)') {$version=$Matches[1]}
        $pids=@($answer.processes | Where-Object {$_.executable -eq $exe} | ForEach-Object {$_.pid})
        $answer.binaries+=@{path=$exe; version=$version; sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash; pids=$pids; runtime_state=$(if ($pids.Count) {'proceso_php_observado'} else {'configurado_uso_no_confirmado'})}
    } catch {$answer.errors+=@{location=$exe; reason='ejecutable_no_legible'}}
}
foreach ($edge in $answer.config) {
    $pids=@($answer.processes | Where-Object {$_.executable -and $_.executable -eq $edge.target} | ForEach-Object {$_.pid})
    if ($pids.Count) {$edge.worker_pids=$pids; $edge.state='handler_configurado_y_proceso_observado'}
}
$answer.status=if (@($answer.config | Where-Object {$_.worker_pids}).Count) {'handler_y_worker_observados'} elseif (@($answer.processes | Where-Object {$_.name -match '^php'}).Count) {'worker_observado_ruta_web_pendiente'} elseif ($answer.config.Count) {'configuracion_sin_worker_correlacionado'} elseif ($answer.errors.Count) {'pendiente_no_evaluado'} else {'sin_runtime_detectado_en_fuentes'}
$answer | ConvertTo-Json -Depth 12 -Compress
'@
    $answer=Invoke-JsonProbe $body
    if ($null -eq $answer) {
        return @{status='pendiente_no_evaluado'; errors=@(@{location='php_web'; reason='consulta_fallida_o_timeout'}); config=@(); binaries=@(); files_consulted=@(); processes=@()}
    }
    return $answer
}

$script:Stage='runtime_initialization'
$services=@(); $processes=@(); $containers=@(); $localAddresses=@(); $os=$null
try {
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {throw 'PowerShell 5.1 required'}
    Add-Type -AssemblyName System.IO.Compression
    $script:Stage='system_inventory'
    $osAnswer=Invoke-JsonProbe '@{items=@(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 1 | Select-Object Caption,Version,BuildNumber,OSArchitecture)} | ConvertTo-Json -Depth 4 -Compress'
    $os=if ($osAnswer -and @($osAnswer.items).Count) {@($osAnswer.items)[0]} else {$null}
    if (-not $os) {Add-Problem 'sistema_auxiliar' 'consulta_no_disponible'}
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
    $auxStart=$script:ErrorCount
    $services=@(Get-ServicesBounded)
    $phpErrorsStart=$script:ErrorCount
    $script:Stage='php_web_runtime'
    $web=Get-WebRuntimeBounded
    $processes=@($web.processes)
    foreach ($bin in @($web.binaries)) {
        if ('php' -notin @($config.checks)) {continue}
        Add-Observation 'php' $bin.path $bin.version 'windows_product_version'
        $obs=$script:Observations[$script:Observations.Count-1]
        $obs.runtime_state=$bin.runtime_state; $obs.sha256=$bin.sha256
        $obs.provenance=@{provider='no_confirmado'; note='ProductVersion y hash no certifican backports ni firma del proveedor.'}
    }
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
    $phpCollectionErrors=$script:ErrorCount-$phpErrorsStart
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
        foreach ($bin in @($web.binaries)) {$roots+=Split-Path -Parent $bin.path}
        foreach ($proc in $processes) {
            if ($proc.name -match '^php' -and $proc.executable) {$roots+=Split-Path -Parent $proc.executable}
        }
        $config.windows_roots=@($roots | Select-Object -Unique)
    }
    $script:Stage='file_search'
    $phpWalkErrorsStart=$script:ErrorCount
    Walk-Roots
    $phpCollectionErrors+=($script:ErrorCount-$phpWalkErrorsStart)
    $searchState=if ($script:ErrorCount -gt 0 -or $script:BudgetExhausted) {'parcial'} elseif ($script:Completed.Count -eq 0) {'sin_rutas_revisadas'} else {'completado_en_rutas'}
    $families=@{}
    foreach ($family in @($config.checks)) {
        $families[$family]=@{status=$searchState; sources=@('archivos en raíces configuradas')}
        if ($family -eq 'php') {
            $families[$family].sources=@('PHP CLI en PATH','metadatos de ejecutables en raíces configuradas')
            $families[$family].runtime_web=$web.status
            $families[$family].runtime_errors=@($web.errors)
            if ($config.php_inventory_only -and $phpCollectionErrors -eq 0 -and @($web.errors).Count -eq 0 -and -not $script:BudgetExhausted) {$families[$family].status='completado_en_fuentes'}
            $families[$family].note='No acredita ausencia de PHP fuera de las fuentes consultadas ni en contenedores.'
        }
    }
    $script:Stage='result_serialization'
    $result=@{
        schema_version=1; collector_version='1.6.1-evidencia'; status='recolectado'; platform='windows'; timestamp_utc=[DateTime]::UtcNow.ToString('o')
        system=@{hostname=[Environment]::MachineName; ip_addresses=$localAddresses; PRETTY_NAME=$os.Caption; VERSION_ID=$os.Version; build=$os.BuildNumber; architecture=$os.OSArchitecture}
        observations=@($script:Observations.ToArray()); services=$services; processes=$processes; containers=$containers; php_web=$web; service_coverage=$script:ServiceCoverage
        trend_local=@{services=@($services | Where-Object {$_.name -match 'ds_agent|trend'}); note='Evidencia local; estado de protección y cobertura requieren consola de Seguridad.'}
        coverage=@{
            file_search=$searchState; families=$families
            roots_requested=@($config.windows_roots); roots_completed=@($script:Completed.ToArray()); roots_absent=@($script:Absent.ToArray()); excluded=@($config.windows_excludes)
            files_seen=$script:FileCount; archives_seen=$script:ArchiveCount; errors_count=$script:ErrorCount; errors=@($script:Errors.ToArray()); budget_exhausted=$script:BudgetExhausted
            elapsed_seconds=[Math]::Round(([DateTime]::UtcNow-$script:Started).TotalSeconds,2); limits=$config
            limitations=@('Solo rutas configuradas; no prueba ausencia global.','Contenedores: solo inventario; imágenes y contenido interno no inspeccionados.','Correlación por configuración/proceso; no demuestra petición atendida ni exposición pública.','No evalúa condiciones de explotación ni configuraciones de Struts/PHP.','Los volúmenes adicionales requieren raíces explícitas; no se siguen junctions ni reparse points.')
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
