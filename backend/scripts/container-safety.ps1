function New-DBPilotOwnedContainerName {
    param([Parameter(Mandatory = $true)][string]$Prefix)
    if ($Prefix -notmatch '^[a-z0-9][a-z0-9_.-]*$') {
        throw 'Container name prefix is invalid.'
    }
    return $Prefix + '-' + [guid]::NewGuid().ToString('N')
}

function New-DBPilotOwnedContainer {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$CreateArguments
    )
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name -match '[\r\n]') {
        throw 'Owned container name is invalid.'
    }
    $existing = @(& $DockerBinary ps -a --filter "name=^/$Name$" --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect the owned container name '$Name'."
    }
    if ($existing.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($existing -join ''))) {
        throw "Refusing to replace the pre-existing container '$Name'."
    }
    $created = @(& $DockerBinary create --name $Name @CreateArguments)
    $createExitCode = $LASTEXITCODE
    $containerID = ($created | Out-String).Trim()
    if ($createExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($containerID)) {
        throw "Unable to create the owned container '$Name'."
    }
    return $containerID
}

function Remove-DBPilotOwnedContainer {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [AllowNull()][AllowEmptyString()][string]$ContainerID
    )
    if ([string]::IsNullOrWhiteSpace($ContainerID)) { return }
    & $DockerBinary rm -f -v $ContainerID | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to remove owned container '$ContainerID'."
    }
}

function ConvertTo-DBPilotNativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            if ($backslashes -gt 0) { $null = $builder.Append(('\' * ($backslashes * 2))) }
            $null = $builder.Append('\"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { $null = $builder.Append(('\' * $backslashes)); $backslashes = 0 }
        $null = $builder.Append($character)
    }
    if ($backslashes -gt 0) { $null = $builder.Append(('\' * ($backslashes * 2))) }
    $null = $builder.Append([char]34)
    return $builder.ToString()
}

function Invoke-DBPilotSafetyDocker {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [scriptblock]$Invoker
    )
    if ($null -ne $Invoker) { return & $Invoker $Arguments }
    $stdout = (& $DockerBinary @Arguments 2>$null | Out-String).Trim()
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Stdout = $stdout }
}

function Get-DBPilotOwnedContainerRecord {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$ContainerID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $result = Invoke-DBPilotSafetyDocker $DockerBinary @('inspect', $ContainerID) $InvokeDocker
    if ($result.ExitCode -ne 0) { throw "Unable to inspect recorded container '$ContainerID'." }
    $items = @($result.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $ContainerID -or
        $items[0].Config.Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Config.Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Recorded container '$ContainerID' does not have the expected ownership labels."
    }
    return [pscustomobject]@{
        ID = $ContainerID
        VolumeNames = @($items[0].Mounts | Where-Object Type -eq 'volume' | ForEach-Object Name)
    }
}

function Get-DBPilotOwnedNetworkRecord {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$NetworkID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $result = Invoke-DBPilotSafetyDocker $DockerBinary @('network', 'inspect', $NetworkID) $InvokeDocker
    if ($result.ExitCode -ne 0) { throw "Unable to inspect recorded network '$NetworkID'." }
    $items = @($result.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $NetworkID -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Recorded network '$NetworkID' does not have the expected ownership labels."
    }
    return [pscustomobject]@{ ID = $NetworkID }
}

function Get-DBPilotOwnedVolumeRecord {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$VolumeName,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $result = Invoke-DBPilotSafetyDocker $DockerBinary @('volume', 'inspect', $VolumeName) $InvokeDocker
    if ($result.ExitCode -ne 0) { throw "Unable to inspect recorded volume '$VolumeName'." }
    $items = @($result.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Name -cne $VolumeName -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Recorded volume '$VolumeName' does not have the expected ownership labels."
    }
    return [pscustomobject]@{ Name = $VolumeName }
}

function Remove-DBPilotRecordedContainer {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$ContainerID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $inspection = Invoke-DBPilotSafetyDocker $DockerBinary @('inspect', $ContainerID) $InvokeDocker
    if ($inspection.ExitCode -ne 0) { return }
    $items = @($inspection.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $ContainerID -or
        $items[0].Config.Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Config.Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove container '$ContainerID' because its ownership labels do not match."
    }
    $removal = Invoke-DBPilotSafetyDocker $DockerBinary @('rm', '-f', '-v', $ContainerID) $InvokeDocker
    if ($removal.ExitCode -ne 0) { throw "Unable to remove recorded container '$ContainerID'." }
}

function Remove-DBPilotRecordedNetwork {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$NetworkID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $inspection = Invoke-DBPilotSafetyDocker $DockerBinary @('network', 'inspect', $NetworkID) $InvokeDocker
    if ($inspection.ExitCode -ne 0) { return }
    $items = @($inspection.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $NetworkID -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove network '$NetworkID' because its ownership labels do not match."
    }
    $removal = Invoke-DBPilotSafetyDocker $DockerBinary @('network', 'rm', $NetworkID) $InvokeDocker
    if ($removal.ExitCode -ne 0) { throw "Unable to remove recorded network '$NetworkID'." }
}

function Remove-DBPilotRecordedVolume {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$VolumeName,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel,
        [scriptblock]$InvokeDocker
    )
    $inspection = Invoke-DBPilotSafetyDocker $DockerBinary @('volume', 'inspect', $VolumeName) $InvokeDocker
    if ($inspection.ExitCode -ne 0) { return }
    $items = @($inspection.Stdout | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Name -cne $VolumeName -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove volume '$VolumeName' because its ownership labels do not match."
    }
    $removal = Invoke-DBPilotSafetyDocker $DockerBinary @('volume', 'rm', $VolumeName) $InvokeDocker
    if ($removal.ExitCode -ne 0) { throw "Unable to remove recorded volume '$VolumeName'." }
}
