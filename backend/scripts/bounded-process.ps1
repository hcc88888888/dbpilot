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
    private const uint ProcessQueryLimitedInformation = 0x00001000;
    private const uint Synchronize = 0x00100000;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorMoreData = 234;
    private const int MaximumProcessIds = 65536;

    private sealed class ObservedProcess
    {
        public readonly IntPtr Handle;
        public readonly bool Synchronizable;

        public ObservedProcess(IntPtr handle, bool synchronizable)
        {
            Handle = handle;
            Synchronizable = synchronizable;
        }
    }

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
    private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

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

    public static bool TerminateAndWait(IntPtr job, long deadlineTimestamp)
    {
        if (job == IntPtr.Zero) throw new ArgumentException("job");
        Dictionary<uint, ObservedProcess> processes = new Dictionary<uint, ObservedProcess>();
        try
        {
            int emptyPasses = 0;
            while (true)
            {
                Exception captureFailure = null;
                try
                {
                    CaptureActiveProcesses(job, processes, deadlineTimestamp);
                }
                catch (Exception error)
                {
                    captureFailure = error;
                }

                int terminateError = 0;
                if (!TerminateJobObject(job, 1)) terminateError = Marshal.GetLastWin32Error();
                if (captureFailure != null || terminateError != 0)
                {
                    try { WaitForProcesses(processes, deadlineTimestamp); } catch { }
                    try { WaitForActiveZero(job, deadlineTimestamp); } catch { }
                    if (captureFailure != null) throw captureFailure;
                    throw new Win32Exception(terminateError);
                }

                if (!WaitForProcesses(processes, deadlineTimestamp)) return false;

                uint[] active;
                try
                {
                    active = CaptureActiveProcesses(job, processes, deadlineTimestamp);
                }
                catch (Exception error)
                {
                    TerminateJobObject(job, 1);
                    try { WaitForProcesses(processes, deadlineTimestamp); } catch { }
                    try { WaitForActiveZero(job, deadlineTimestamp); } catch { }
                    throw error;
                }

                uint activeCount = QueryActiveCount(job);
                if (active.Length == 0 && activeCount == 0)
                {
                    emptyPasses++;
                    if (emptyPasses == 2) return true;
                    Thread.Yield();
                }
                else
                {
                    emptyPasses = 0;
                }
            }
        }
        finally
        {
            foreach (ObservedProcess process in processes.Values) CloseHandle(process.Handle);
        }
    }

    private static uint[] CaptureActiveProcesses(IntPtr job, Dictionary<uint, ObservedProcess> processes, long deadlineTimestamp)
    {
        uint[] processIds = QueryActiveProcessIds(job, deadlineTimestamp);
        List<uint> disappeared = new List<uint>();
        foreach (uint processId in processIds)
        {
            if (processes.ContainsKey(processId)) continue;
            ThrowIfDeadlineExpired(deadlineTimestamp);
            IntPtr process = OpenProcess(Synchronize | ProcessQueryLimitedInformation, false, processId);
            if (process == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ErrorInvalidParameter)
                {
                    disappeared.Add(processId);
                    continue;
                }
                IntPtr auditProcess = OpenProcess(ProcessQueryLimitedInformation, false, processId);
                if (auditProcess != IntPtr.Zero)
                {
                    try
                    {
                        bool departed;
                        if (TrackProcess(job, processId, auditProcess, false, processes, out departed)) auditProcess = IntPtr.Zero;
                    }
                    finally
                    {
                        if (auditProcess != IntPtr.Zero) CloseHandle(auditProcess);
                    }
                }
                throw new Win32Exception(error);
            }
            try
            {
                bool departed;
                if (TrackProcess(job, processId, process, true, processes, out departed)) process = IntPtr.Zero;
                else if (departed) disappeared.Add(processId);
            }
            finally
            {
                if (process != IntPtr.Zero) CloseHandle(process);
            }
        }

        if (disappeared.Count != 0)
        {
            uint[] confirmation = QueryActiveProcessIds(job, deadlineTimestamp);
            foreach (uint processId in disappeared)
            {
                if (Array.IndexOf(confirmation, processId) >= 0)
                    throw new Win32Exception(ErrorInvalidParameter);
            }
        }
        return processIds;
    }

    private static bool TrackProcess(IntPtr job, uint processId, IntPtr process, bool synchronizable, Dictionary<uint, ObservedProcess> processes, out bool departed)
    {
        departed = false;
        bool isMember;
        if (!IsProcessInJob(process, job, out isMember))
        {
            int error = Marshal.GetLastWin32Error();
            if (HasExited(process, synchronizable)) return false;
            throw new Win32Exception(error);
        }
        if (!isMember)
        {
            if (HasExited(process, synchronizable)) return false;
            departed = true;
            return false;
        }
        processes.Add(processId, new ObservedProcess(process, synchronizable));
        return true;
    }

    private static uint[] QueryActiveProcessIds(IntPtr job, long deadlineTimestamp)
    {
        int capacity = 16;
        while (true)
        {
            ThrowIfDeadlineExpired(deadlineTimestamp);
            int size = checked(8 + IntPtr.Size * capacity);
            IntPtr pointer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.WriteInt64(pointer, 0);
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, pointer, (uint)size, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == ErrorMoreData)
                    {
                        uint assignedOnFailure = unchecked((uint)Marshal.ReadInt32(pointer, 0));
                        capacity = GrowCapacity(capacity, assignedOnFailure);
                        continue;
                    }
                    throw new Win32Exception(error);
                }
                uint assigned = unchecked((uint)Marshal.ReadInt32(pointer, 0));
                uint returned = unchecked((uint)Marshal.ReadInt32(pointer, 4));
                if (returned > capacity || returned > assigned)
                    throw new InvalidOperationException("job process list returned invalid counts");
                if (returned != assigned)
                {
                    capacity = GrowCapacity(capacity, assigned);
                    continue;
                }
                uint[] result = new uint[returned];
                for (int index = 0; index < result.Length; index++)
                {
                    long raw = Marshal.ReadIntPtr(pointer, 8 + index * IntPtr.Size).ToInt64();
                    if (raw <= 0 || raw > UInt32.MaxValue)
                        throw new InvalidOperationException("job process list returned an invalid process identifier");
                    result[index] = (uint)raw;
                }
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
        }
    }

    private static int GrowCapacity(int capacity, uint assigned)
    {
        long next = Math.Max((long)capacity * 2, (long)assigned);
        if (next <= capacity || next > MaximumProcessIds)
            throw new InvalidOperationException("job process list exceeds its bound");
        return (int)next;
    }

    private static bool WaitForProcesses(Dictionary<uint, ObservedProcess> processes, long deadlineTimestamp)
    {
        foreach (ObservedProcess process in processes.Values)
        {
            if (process.Synchronizable)
            {
                int remaining = RemainingMilliseconds(deadlineTimestamp);
                uint result = WaitForSingleObject(process.Handle, (uint)remaining);
                if (result == WaitTimeout) return false;
                if (result == WaitFailed) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (result != WaitObject0) throw new InvalidOperationException("unexpected process wait result");
                continue;
            }
            while (!HasExited(process.Handle, false))
            {
                if (RemainingMilliseconds(deadlineTimestamp) == 0) return false;
                Thread.Yield();
            }
        }
        return true;
    }

    private static bool HasExited(IntPtr process, bool synchronizable)
    {
        if (synchronizable)
        {
            uint result = WaitForSingleObject(process, 0);
            if (result == WaitObject0) return true;
            if (result == WaitTimeout) return false;
            if (result == WaitFailed) throw new Win32Exception(Marshal.GetLastWin32Error());
            throw new InvalidOperationException("unexpected process wait result");
        }
        uint exitCode;
        if (!GetExitCodeProcess(process, out exitCode)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return exitCode != 259;
    }

    private static uint QueryActiveCount(IntPtr job)
    {
        int size = Marshal.SizeOf(typeof(BasicAccountingInformation));
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, pointer, (uint)size, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            BasicAccountingInformation information = (BasicAccountingInformation)Marshal.PtrToStructure(pointer, typeof(BasicAccountingInformation));
            return information.ActiveProcesses;
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static bool WaitForActiveZero(IntPtr job, long deadlineTimestamp)
    {
        try
        {
            while (true)
            {
                if (QueryActiveCount(job) == 0) return true;
                if (RemainingMilliseconds(deadlineTimestamp) == 0) return false;
                Thread.Yield();
            }
        }
        catch
        {
            return false;
        }
    }

    private static void ThrowIfDeadlineExpired(long deadlineTimestamp)
    {
        if (RemainingMilliseconds(deadlineTimestamp) == 0)
            throw new TimeoutException("bounded process deadline expired");
    }

    private static int RemainingMilliseconds(long deadlineTimestamp)
    {
        long ticks = deadlineTimestamp - Stopwatch.GetTimestamp();
        if (ticks <= 0) return 0;
        double milliseconds = Math.Ceiling(ticks * 1000.0 / Stopwatch.Frequency);
        if (milliseconds >= Int32.MaxValue) return Int32.MaxValue;
        return (int)milliseconds;
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

function Get-BoundedRemainingMilliseconds {
    param([long]$DeadlineTimestamp)
    $remainingTicks = $DeadlineTimestamp - [Diagnostics.Stopwatch]::GetTimestamp()
    if ($remainingTicks -le 0) { return 0 }
    $remaining = [Math]::Ceiling(([double]$remainingTicks * 1000.0) / [Diagnostics.Stopwatch]::Frequency)
    if ($remaining -ge [int]::MaxValue) { return [int]::MaxValue }
    return [int]$remaining
}

function Stop-BoundedProcessTree {
    param([Diagnostics.Process]$Process, [long]$DeadlineTimestamp)
    try { $null = $Process.Id } catch { return $true }
    try { if ($Process.HasExited) { return $true } } catch { return $true }
    try {
        if ($env:OS -ne 'Windows_NT') {
            $treeKill = $Process.GetType().GetMethod('Kill', [type[]]@([bool]))
            if ($null -ne $treeKill) { $null = $treeKill.Invoke($Process, @($true)) } else { $Process.Kill() }
        } else {
            $Process.Kill()
        }
    } catch { }
    try { if ($Process.HasExited) { return $true } } catch { return $true }
    $remaining = Get-BoundedRemainingMilliseconds $DeadlineTimestamp
    if ($remaining -le 0) { return $false }
    try { return $Process.WaitForExit($remaining) } catch { return $false }
}

function Stop-BoundedOwnedProcessTree {
    param(
        [Diagnostics.Process]$Process,
        [IntPtr]$Job,
        [bool]$JobAssigned,
        [long]$DeadlineTimestamp
    )
    $settled = $true
    if ($Job -ne [IntPtr]::Zero) {
        if ($JobAssigned) {
            try { $settled = [DBPilotProcessJob]::TerminateAndWait($Job, $DeadlineTimestamp) }
            catch { $settled = $false }
        }
        try {
            if (-not [DBPilotProcessJob]::CloseHandle($Job)) { $settled = $false }
        } catch {
            $settled = $false
        }
    }
    if (-not $JobAssigned -or -not $settled) {
        $rootSettled = Stop-BoundedProcessTree $Process $DeadlineTimestamp
        if (-not $JobAssigned -and -not $rootSettled) { $settled = $false }
    }
    return [bool]$settled
}

function Wait-BoundedOutputTask {
    param([Threading.Tasks.Task]$Task, [long]$DeadlineTimestamp)
    if ($null -eq $Task -or $Task.IsCompleted) { return $true }
    $remaining = Get-BoundedRemainingMilliseconds $DeadlineTimestamp
    if ($remaining -le 0) { return $false }
    try { return $Task.Wait($remaining) } catch { return $false }
}

function Wait-BoundedOutputTasks {
    param([Threading.Tasks.Task]$StdoutTask, [Threading.Tasks.Task]$StderrTask, [long]$DeadlineTimestamp)
    if (-not (Wait-BoundedOutputTask $StdoutTask $DeadlineTimestamp)) { return $false }
    if (-not (Wait-BoundedOutputTask $StderrTask $DeadlineTimestamp)) { return $false }
    return $true
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$StartFailure,
        [Parameter(Mandatory = $true)][string]$TimeoutFailure
    )
    if ($TimeoutSeconds -le 0) { throw $TimeoutFailure }
    $startedTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()
    $timeoutMilliseconds = [long]$TimeoutSeconds * 1000L
    $deadlineTimestamp = $startedTimestamp + [long][Math]::Ceiling(([double]$TimeoutSeconds * [Diagnostics.Stopwatch]::Frequency))
    $teardownReserveMilliseconds = [long][Math]::Min(500.0, [Math]::Max(100.0, [Math]::Ceiling($timeoutMilliseconds / 4.0)))
    $teardownReserveTicks = [long][Math]::Ceiling(($teardownReserveMilliseconds * [double][Diagnostics.Stopwatch]::Frequency) / 1000.0)
    $executionDeadlineTimestamp = $deadlineTimestamp - $teardownReserveTicks
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
    $jobAssigned = $false
    $stdoutTask = $null
    $stderrTask = $null
    try {
        try {
            if ($env:OS -eq 'Windows_NT') { $job = [DBPilotProcessJob]::CreateKillOnClose() }
            if (-not $process.Start()) { throw $StartFailure }
            if ($env:OS -eq 'Windows_NT') {
                [DBPilotProcessJob]::Assign($job, $process.Handle)
                $jobAssigned = $true
                $null = $gateEvent.Set()
            }
        } catch {
            $settled = Stop-BoundedOwnedProcessTree $process $job $jobAssigned $deadlineTimestamp
            $job = [IntPtr]::Zero
            if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
            throw $StartFailure
        }
        $outputLimit = 1000000
        try {
            $stdoutTask = [DBPilotBoundedOutputReader]::ReadAsync($process.StandardOutput, $outputLimit)
            $stderrTask = [DBPilotBoundedOutputReader]::ReadAsync($process.StandardError, $outputLimit)
        } catch {
            $settled = Stop-BoundedOwnedProcessTree $process $job $jobAssigned $deadlineTimestamp
            $job = [IntPtr]::Zero
            if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
            throw $TimeoutFailure
        }
        $stdoutResult = $null
        $stderrResult = $null
        $failure = $null
        while ($true) {
            try {
                if ($null -eq $stdoutResult -and $stdoutTask.IsCompleted) { $stdoutResult = $stdoutTask.GetAwaiter().GetResult() }
                if ($null -eq $stderrResult -and $stderrTask.IsCompleted) { $stderrResult = $stderrTask.GetAwaiter().GetResult() }
            } catch {
                $failure = 'timeout'
                break
            }
            if (($null -ne $stdoutResult -and $stdoutResult.Overflow) -or ($null -ne $stderrResult -and $stderrResult.Overflow)) {
                $failure = 'overflow'
                break
            }
            $remaining = Get-BoundedRemainingMilliseconds $executionDeadlineTimestamp
            if ($remaining -le 0) {
                $failure = 'timeout'
                break
            }
            if ($process.WaitForExit([Math]::Min(20, $remaining))) { break }
        }
        if ($null -eq $failure) {
            try {
                if ($null -eq $stdoutResult -and -not (Wait-BoundedOutputTask $stdoutTask $executionDeadlineTimestamp)) { $failure = 'timeout' }
                if ($null -eq $failure -and $null -eq $stderrResult -and -not (Wait-BoundedOutputTask $stderrTask $executionDeadlineTimestamp)) { $failure = 'timeout' }
                if ($null -eq $failure -and $null -eq $stdoutResult) { $stdoutResult = $stdoutTask.GetAwaiter().GetResult() }
                if ($null -eq $failure -and $null -eq $stderrResult) { $stderrResult = $stderrTask.GetAwaiter().GetResult() }
            } catch {
                $failure = 'timeout'
            }
        }
        if ($null -eq $failure -and ($stdoutResult.Overflow -or $stderrResult.Overflow)) { $failure = 'overflow' }
        if ($null -ne $failure) {
            $settled = Stop-BoundedOwnedProcessTree $process $job $jobAssigned $deadlineTimestamp
            $job = [IntPtr]::Zero
            $outputsSettled = Wait-BoundedOutputTasks $stdoutTask $stderrTask $deadlineTimestamp
            if (-not $settled -or -not $outputsSettled) { throw 'Bounded process tree termination did not settle.' }
            if ($failure -eq 'overflow') { throw 'Bounded process output exceeded its limit.' }
            throw $TimeoutFailure
        }
        $exitCode = $process.ExitCode
        $settled = Stop-BoundedOwnedProcessTree $process $job $jobAssigned $deadlineTimestamp
        $job = [IntPtr]::Zero
        if (-not $settled) { throw 'Bounded process tree termination did not settle.' }
        return [pscustomobject]@{ ExitCode = $exitCode; Stdout = $stdoutResult.Text.Trim(); Stderr = $stderrResult.Text.Trim(); StdoutTruncated = $false; StderrTruncated = $false }
    } catch {
        $failureRecord = $_
        if ($job -ne [IntPtr]::Zero) {
            $settled = Stop-BoundedOwnedProcessTree $process $job $jobAssigned $deadlineTimestamp
            $job = [IntPtr]::Zero
            $outputsSettled = Wait-BoundedOutputTasks $stdoutTask $stderrTask $deadlineTimestamp
            if (-not $settled -or -not $outputsSettled) { throw 'Bounded process tree termination did not settle.' }
        }
        throw $failureRecord
    } finally {
        if ($job -ne [IntPtr]::Zero) { $null = [DBPilotProcessJob]::CloseHandle($job) }
        if ($null -ne $gateEvent) { $gateEvent.Dispose() }
        $process.Dispose()
    }
}
