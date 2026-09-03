if ($env:OS -eq 'Windows_NT' -and $null -eq ('DBPilotProcessJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class DBPilotProcessJob
{
    private const uint JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    public static IntPtr CreateKillOnClose()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        ExtendedLimitInformation information = new ExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(information, pointer, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, pointer, (uint)size))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(job);
                throw new Win32Exception(error);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
        return job;
    }

    public static void Assign(IntPtr job, IntPtr process)
    {
        if (!AssignProcessToJobObject(job, process)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
}

$script:DBPilotBoundedProcessGatePath = Join-Path $PSScriptRoot 'bounded-process-gate.ps1'

function Set-BoundedProcessArguments {
    param([Diagnostics.ProcessStartInfo]$StartInfo, [string[]]$Arguments)
    if ($null -ne $StartInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) { $null = $StartInfo.ArgumentList.Add([string]$argument) }
        return
    }
    $StartInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-DBPilotNativeArgument ([string]$_) }) -join ' ')
}

function Stop-BoundedProcessTree {
    param([Diagnostics.Process]$Process)
    try { if ($Process.HasExited) { return } } catch { return }
    if ($env:OS -eq 'Windows_NT') {
        $taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
        if (Test-Path -LiteralPath $taskkill -PathType Leaf) {
            try {
                $killer = Start-Process -FilePath $taskkill -ArgumentList @('/PID', [string]$Process.Id, '/T', '/F') -WindowStyle Hidden -PassThru
                if (-not $killer.WaitForExit(10000)) { try { $killer.Kill() } catch { } }
                $killer.Dispose()
            } catch { }
        }
    }
    try { if ($Process.HasExited) { return } } catch { return }
    try {
        $treeKill = $Process.GetType().GetMethod('Kill', [type[]]@([bool]))
        if ($null -ne $treeKill) { $null = $treeKill.Invoke($Process, @($true)) } else { $Process.Kill() }
    } catch { try { $Process.Kill() } catch { } }
}

function Wait-BoundedOutputTask {
    param([Threading.Tasks.Task]$Task, [DateTime]$Deadline)
    $remaining = [int][Math]::Floor(($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if ($remaining -le 0) { return $false }
    return $Task.Wait($remaining)
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$StartFailure,
        [Parameter(Mandatory = $true)][string]$TimeoutFailure
    )
    $commandArguments = @($Arguments)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $gateEvent = $null
    if ($env:OS -eq 'Windows_NT') {
        if (-not (Test-Path -LiteralPath $script:DBPilotBoundedProcessGatePath -PathType Leaf)) { throw $StartFailure }
        $startInfo.FileName = (Get-Process -Id $PID).Path
        $gateEventName = 'Local\DBPilotBounded-' + [Guid]::NewGuid().ToString('N')
        $created = $false
        $gateEvent = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $gateEventName, [ref]$created)
        if (-not $created) { $gateEvent.Dispose(); throw $StartFailure }
        $startInfo.EnvironmentVariables['DBPILOT_BOUNDED_GATE_EVENT'] = $gateEventName
        $startInfo.EnvironmentVariables['DBPILOT_BOUNDED_GATE_COMMAND'] = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
        $encodedArguments = ConvertTo-Json -InputObject ([object[]]$commandArguments) -Compress
        $startInfo.EnvironmentVariables['DBPILOT_BOUNDED_GATE_ARGUMENTS'] = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($encodedArguments))
        $commandArguments = @('-NoProfile', '-File', $script:DBPilotBoundedProcessGatePath)
    } elseif ([IO.Path]::GetExtension($Command) -ieq '.ps1') {
        $startInfo.FileName = (Get-Process -Id $PID).Path
        $commandArguments = @('-NoProfile', '-File', $Command) + $commandArguments
    } else {
        $startInfo.FileName = $Command
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($key in [Environment]::GetEnvironmentVariables().Keys) {
        if ([string]$key -like 'DBPILOT_BOUNDED_GATE_*') { continue }
        $startInfo.EnvironmentVariables[[string]$key] = [string][Environment]::GetEnvironmentVariable([string]$key)
    }
    Set-BoundedProcessArguments $startInfo $commandArguments
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $job = [IntPtr]::Zero
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        try {
            if ($env:OS -eq 'Windows_NT') { $job = [DBPilotProcessJob]::CreateKillOnClose() }
            if (-not $process.Start()) { throw $StartFailure }
            if ($env:OS -eq 'Windows_NT') {
                [DBPilotProcessJob]::Assign($job, $process.Handle)
                $null = $gateEvent.Set()
            }
        } catch {
            if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job); $job = [IntPtr]::Zero }
            Stop-BoundedProcessTree $process
            throw $StartFailure
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $remaining = [int][Math]::Floor(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) {
            if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job); $job = [IntPtr]::Zero }
            Stop-BoundedProcessTree $process
            $null = $process.WaitForExit(2000)
            throw $TimeoutFailure
        }
        if (-not (Wait-BoundedOutputTask $stdoutTask $deadline) -or -not (Wait-BoundedOutputTask $stderrTask $deadline)) {
            if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job); $job = [IntPtr]::Zero }
            Stop-BoundedProcessTree $process
            throw $TimeoutFailure
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $stdoutTruncated = $stdout.Length -gt 1000000
        $stderrTruncated = $stderr.Length -gt 1000000
        if ($stdoutTruncated) { $stdout = $stdout.Substring($stdout.Length - 1000000) }
        if ($stderrTruncated) { $stderr = $stderr.Substring($stderr.Length - 1000000) }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.Trim(); Stderr = $stderr.Trim(); StdoutTruncated = $stdoutTruncated; StderrTruncated = $stderrTruncated }
    } finally {
        if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job) }
        if ($null -ne $gateEvent) { $gateEvent.Dispose() }
        $process.Dispose()
    }
}
