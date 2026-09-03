$ErrorActionPreference = 'Stop'

try {
    $eventName = [Environment]::GetEnvironmentVariable('DBPILOT_BOUNDED_GATE_EVENT')
    $commandEncoded = [Environment]::GetEnvironmentVariable('DBPILOT_BOUNDED_GATE_COMMAND')
    $argumentsEncoded = [Environment]::GetEnvironmentVariable('DBPILOT_BOUNDED_GATE_ARGUMENTS')
    if ([string]::IsNullOrWhiteSpace($eventName) -or [string]::IsNullOrWhiteSpace($commandEncoded) -or [string]::IsNullOrWhiteSpace($argumentsEncoded)) { exit 125 }
    $gate = [Threading.EventWaitHandle]::OpenExisting($eventName)
    try {
        if (-not $gate.WaitOne([TimeSpan]::FromSeconds(30))) { exit 125 }
    } finally {
        $gate.Dispose()
    }
    $command = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($commandEncoded))
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($argumentsEncoded)) | ConvertFrom-Json
    $arguments = @($decoded | ForEach-Object { [string]$_ })
    if ([string]::IsNullOrWhiteSpace($command) -or -not [IO.Path]::IsPathRooted($command)) { exit 125 }
    & $command @arguments
    if ($null -eq $LASTEXITCODE) { exit 0 }
    exit $LASTEXITCODE
} catch {
    exit 125
}
