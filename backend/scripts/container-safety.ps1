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
    & $DockerBinary rm -f $ContainerID | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to remove owned container '$ContainerID'."
    }
}
