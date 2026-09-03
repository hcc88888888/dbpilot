if ($env:OS -eq 'Windows_NT' -and $null -eq ('DBPilotProcessJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

public static class DBPilotProcessJob
{
    private const uint JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectBasicAccountingInformation = 1;
    private const uint JobObjectBasicProcessIdList = 3;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint Synchronize = 0x00100000;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;

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

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, uint informationClass, IntPtr information, uint length, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

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

    public static bool TerminateAndWait(IntPtr job, int timeoutMilliseconds)
    {
        if (job == IntPtr.Zero || timeoutMilliseconds < 0) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        List<IntPtr> processes = OpenActiveProcesses(job);
        Stopwatch watch = Stopwatch.StartNew();
        try
        {
            if (!TerminateJobObject(job, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            foreach (IntPtr process in processes)
            {
                long remaining = timeoutMilliseconds - watch.ElapsedMilliseconds;
                if (remaining < 0) return false;
                uint result = WaitForSingleObject(process, (uint)remaining);
                if (result == WaitTimeout) return false;
                if (result != WaitObject0) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            int size = Marshal.SizeOf(typeof(BasicAccountingInformation));
            IntPtr pointer = Marshal.AllocHGlobal(size);
            try
            {
                while (true)
                {
                    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, pointer, (uint)size, IntPtr.Zero))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    BasicAccountingInformation information = (BasicAccountingInformation)Marshal.PtrToStructure(pointer, typeof(BasicAccountingInformation));
                    if (information.ActiveProcesses == 0) return true;
                    if (watch.ElapsedMilliseconds >= timeoutMilliseconds) return false;
                    Thread.Sleep(1);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
        finally
        {
            foreach (IntPtr process in processes) CloseHandle(process);
        }
    }

    private static List<IntPtr> OpenActiveProcesses(IntPtr job)
    {
        int capacity = 16;
        while (capacity <= 16384)
        {
            int size = checked(8 + IntPtr.Size * capacity);
            IntPtr pointer = Marshal.AllocHGlobal(size);
            try
            {
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, pointer, (uint)size, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 234)
                    {
                        int assigned = Marshal.ReadInt32(pointer, 0);
                        capacity = Math.Max(capacity * 2, assigned + 16);
                        continue;
                    }
                    throw new Win32Exception(error);
                }
                int count = Marshal.ReadInt32(pointer, 4);
                List<IntPtr> result = new List<IntPtr>(count);
                for (int index = 0; index < count; index++)
                {
                    long raw = Marshal.ReadIntPtr(pointer, 8 + index * IntPtr.Size).ToInt64();
                    if (raw <= 0 || raw > UInt32.MaxValue) continue;
                    IntPtr process = OpenProcess(Synchronize, false, (uint)raw);
                    if (process != IntPtr.Zero) result.Add(process);
                }
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
        throw new InvalidOperationException("job process list exceeds its bound");
    }
}
'@
}

if ($null -eq ('DBPilotBoundedOutputReader' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading.Tasks;

public sealed class DBPilotBoundedOutput
{
    public readonly string Text;
    public readonly bool Overflow;

    public DBPilotBoundedOutput(string text, bool overflow)
    {
        Text = text;
        Overflow = overflow;
    }
}

public static class DBPilotBoundedOutputReader
{
    public static async Task<DBPilotBoundedOutput> ReadAsync(TextReader reader, int limit)
    {
        if (reader == null || limit <= 0) throw new ArgumentOutOfRangeException("limit");
        char[] buffer = new char[checked(limit + 1)];
        int length = 0;
        while (length < buffer.Length)
        {
            int count = await reader.ReadAsync(buffer, length, buffer.Length - length).ConfigureAwait(false);
            if (count == 0) return new DBPilotBoundedOutput(new string(buffer, 0, length), false);
            length += count;
            if (length > limit) return new DBPilotBoundedOutput(null, true);
        }
        return new DBPilotBoundedOutput(null, true);
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

function Stop-BoundedOwnedProcessTree {
    param([Diagnostics.Process]$Process, [IntPtr]$Job)
    $settled = $true
    if ($Job -ne [IntPtr]::Zero) {
        try { $settled = [DBPilotProcessJob]::TerminateAndWait($Job, 2000) }
        catch { $settled = $false }
        finally { $null = [DBPilotProcessJob]::CloseHandle($Job) }
    }
    Stop-BoundedProcessTree $Process
    return $settled
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
            $settled = Stop-BoundedOwnedProcessTree $process $job
            $job = [IntPtr]::Zero
            if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
            throw $StartFailure
        }
        $outputLimit = 1000000
        $stdoutTask = [DBPilotBoundedOutputReader]::ReadAsync($process.StandardOutput, $outputLimit)
        $stderrTask = [DBPilotBoundedOutputReader]::ReadAsync($process.StandardError, $outputLimit)
        $stdoutResult = $null
        $stderrResult = $null
        while ($true) {
            try {
                if ($null -eq $stdoutResult -and $stdoutTask.IsCompleted) { $stdoutResult = $stdoutTask.GetAwaiter().GetResult() }
                if ($null -eq $stderrResult -and $stderrTask.IsCompleted) { $stderrResult = $stderrTask.GetAwaiter().GetResult() }
            } catch {
                $settled = Stop-BoundedOwnedProcessTree $process $job
                $job = [IntPtr]::Zero
                if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
                throw $TimeoutFailure
            }
            if (($null -ne $stdoutResult -and $stdoutResult.Overflow) -or ($null -ne $stderrResult -and $stderrResult.Overflow)) {
                $settled = Stop-BoundedOwnedProcessTree $process $job
                $job = [IntPtr]::Zero
                $null = $process.WaitForExit(2000)
                if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
                throw 'Bounded process output exceeded its limit.'
            }
            $remaining = [int][Math]::Floor(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($remaining -le 0) {
                $settled = Stop-BoundedOwnedProcessTree $process $job
                $job = [IntPtr]::Zero
                $null = $process.WaitForExit(2000)
                if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
                throw $TimeoutFailure
            }
            if ($process.WaitForExit([Math]::Min(20, $remaining))) { break }
        }
        try {
            if ($null -eq $stdoutResult -and -not (Wait-BoundedOutputTask $stdoutTask $deadline)) { throw $TimeoutFailure }
            if ($null -eq $stderrResult -and -not (Wait-BoundedOutputTask $stderrTask $deadline)) { throw $TimeoutFailure }
            if ($null -eq $stdoutResult) { $stdoutResult = $stdoutTask.GetAwaiter().GetResult() }
            if ($null -eq $stderrResult) { $stderrResult = $stderrTask.GetAwaiter().GetResult() }
        } catch {
            $settled = Stop-BoundedOwnedProcessTree $process $job
            $job = [IntPtr]::Zero
            if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
            throw $TimeoutFailure
        }
        if ($stdoutResult.Overflow -or $stderrResult.Overflow) {
            $settled = Stop-BoundedOwnedProcessTree $process $job
            $job = [IntPtr]::Zero
            if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
            throw 'Bounded process output exceeded its limit.'
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdoutResult.Text.Trim(); Stderr = $stderrResult.Text.Trim(); StdoutTruncated = $false; StderrTruncated = $false }
    } finally {
        if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job) }
        if ($null -ne $gateEvent) { $gateEvent.Dispose() }
        $process.Dispose()
    }
}
