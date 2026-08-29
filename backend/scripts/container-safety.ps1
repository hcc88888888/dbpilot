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

function Get-DBPilotOwnedContainerRecord {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$ContainerID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $body = (& $DockerBinary inspect $ContainerID | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect recorded container '$ContainerID'." }
    $items = @($body | ConvertFrom-Json)
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
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $body = (& $DockerBinary network inspect $NetworkID | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect recorded network '$NetworkID'." }
    $items = @($body | ConvertFrom-Json)
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
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $body = (& $DockerBinary volume inspect $VolumeName | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect recorded volume '$VolumeName'." }
    $items = @($body | ConvertFrom-Json)
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
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $inspection = (& $DockerBinary inspect $ContainerID 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { return }
    $items = @($inspection | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $ContainerID -or
        $items[0].Config.Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Config.Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove container '$ContainerID' because its ownership labels do not match."
    }
    & $DockerBinary rm -f -v $ContainerID | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to remove recorded container '$ContainerID'." }
}

function Remove-DBPilotRecordedNetwork {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$NetworkID,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $inspection = (& $DockerBinary network inspect $NetworkID 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { return }
    $items = @($inspection | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Id -cne $NetworkID -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove network '$NetworkID' because its ownership labels do not match."
    }
    & $DockerBinary network rm $NetworkID | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to remove recorded network '$NetworkID'." }
}

function Remove-DBPilotRecordedVolume {
    param(
        [Parameter(Mandatory = $true)][string]$DockerBinary,
        [Parameter(Mandatory = $true)][string]$VolumeName,
        [Parameter(Mandatory = $true)][string]$Verifier,
        [Parameter(Mandatory = $true)][string]$RunLabel
    )
    $inspection = (& $DockerBinary volume inspect $VolumeName 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { return }
    $items = @($inspection | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Name -cne $VolumeName -or
        $items[0].Labels.'dbpilot.verifier' -cne $Verifier -or
        $items[0].Labels.'dbpilot.run' -cne $RunLabel) {
        throw "Refusing to remove volume '$VolumeName' because its ownership labels do not match."
    }
    & $DockerBinary volume rm $VolumeName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to remove recorded volume '$VolumeName'." }
}
