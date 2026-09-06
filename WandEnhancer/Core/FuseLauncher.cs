using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using WandEnhancer.View.MainWindow;

namespace WandEnhancer.Core
{
    /// <summary>
    /// Patches each Wand image at its creation debug event, before any user-mode code runs.
    /// Keep observing Wand for its entire lifetime: overlay renderers can start much later.
    /// Foreign children are explicitly suspended, detached, then resumed so games do not
    /// execute under our debugger. Never scan or write a foreign process's memory.
    /// </summary>
    internal static class FuseLauncher
    {
        private const int AsarIntegrityExitCode = -36861;

        public static bool Launch(string exePath, string args, Action<string, ELogType> log = null)
        {
            if (IntPtr.Size != 8)
            {
                log?.Invoke("The Wand launcher requires a 64-bit process.", ELogType.Error);
                return false;
            }
            exePath = Path.GetFullPath(exePath);
            long stateRva;
            try { stateRva = ElectronFuse.FindStateRva(exePath); }
            catch (Exception e)
            {
                log?.Invoke($"Could not inspect Wand: {e.Message}", ELogType.Error);
                return false;
            }
            if (stateRva < 0)
            {
                log?.Invoke("No supported Electron fuse block found. Wand was not started.", ELogType.Error);
                return false;
            }

            var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
            var command = new StringBuilder(string.IsNullOrEmpty(args) ? $"\"{exePath}\"" : $"\"{exePath}\" {args}");
            if (!CreateProcessW(exePath, command, IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS,
                    IntPtr.Zero, Path.GetDirectoryName(exePath), ref startup, out var info))
            {
                log?.Invoke($"Could not start Wand (win32 error {Marshal.GetLastWin32Error()}).", ELogType.Error);
                return false;
            }

            try
            {
                log?.Invoke($"Started {exePath} as pid {info.dwProcessId} (creation-event launcher).", ELogType.Info);
                // All debug APIs stay on the creating thread. A launcher failure must not kill
                // unrelated children through the default debugger-exit policy.
                if (!DebugSetProcessKillOnExit(false))
                {
                    int error = Marshal.GetLastWin32Error();
                    TerminateProcess(info.hProcess, 1);
                    DebugActiveProcessStop(info.dwProcessId);
                    log?.Invoke($"Could not configure process observation (win32 error {error}).", ELogType.Error);
                    return false;
                }
                bool success = Observe(exePath, stateRva, info.dwProcessId, log);
                if (!success) TerminateProcess(info.hProcess, 1);
                return success;
            }
            finally
            {
                CloseHandle(info.hThread);
                CloseHandle(info.hProcess);
            }
        }

        private static bool Observe(string exePath, long stateRva, int mainPid, Action<string, ELogType> log)
        {
            // Debug-event process/thread handles are owned by Windows, unlike CreateProcess's
            // handles. ContinueDebugEvent(EXIT_PROCESS) or detach releases them automatically.
            var wand = new Dictionary<int, IntPtr>();
            var attached = new HashSet<int> { mainPid };
            var initialBreakpoints = new HashSet<int>();
            int? mainExit = null;
            bool healthy = true;
            try
            {
                while (attached.Count > 0)
                {
                    if (!WaitForDebugEvent(out var evt, 1000))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_SEM_TIMEOUT) continue;
                        throw new Win32Exception(error, "Waiting for process events failed");
                    }
                    uint status = DBG_CONTINUE;
                    bool continued = false;
                    try
                    {
                        switch (evt.Code)
                        {
                            case CREATE_PROCESS_DEBUG_EVENT:
                                attached.Add(evt.ProcessId);
                                try
                                {
                                    // The root is the exact executable supplied to CreateProcess.
                                    string path = evt.ProcessId == mainPid ? exePath : GetImagePath(evt.Process);
                                    if (!string.Equals(path, exePath, StringComparison.OrdinalIgnoreCase))
                                    {
                                        DetachChild(evt, attached, ref continued);
                                        log?.Invoke($"pid {evt.ProcessId} detached before execution (non-Wand image).", ELogType.Info);
                                        break;
                                    }
                                    wand.Add(evt.ProcessId, evt.Process);
                                    if (!ElectronFuse.ClearAt(evt.Process, evt.ImageBase, stateRva, out string problem))
                                        throw new InvalidOperationException($"Fuse not cleared in pid {evt.ProcessId}: {problem}");
                                    log?.Invoke($"pid {evt.ProcessId} started - fuse verified before execution.", ELogType.Info);
                                }
                                finally
                                {
                                    if (evt.File != IntPtr.Zero) CloseHandle(evt.File);
                                }
                                break;
                            case LOAD_DLL_DEBUG_EVENT:
                                if (evt.File != IntPtr.Zero) CloseHandle(evt.File);
                                break;
                            case EXCEPTION_DEBUG_EVENT:
                                // Swallow only the loader's first, first-chance breakpoint.
                                status = evt.ExceptionCode == EXCEPTION_BREAKPOINT && evt.FirstChance != 0
                                         && initialBreakpoints.Add(evt.ProcessId)
                                    ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
                                if (evt.FirstChance == 0)
                                {
                                    log?.Invoke($"pid {evt.ProcessId} unhandled exception 0x{evt.ExceptionCode:X8}.", ELogType.Error);
                                }
                                break;
                            case EXIT_PROCESS_DEBUG_EVENT:
                                if (evt.ProcessId == mainPid) mainExit = evt.ExitCode;
                                if (evt.ExitCode != 0)
                                {
                                    // Chromium can recover from a GPU/utility crash. An ASAR rejection
                                    // cannot recover while every replacement uses the same archive.
                                    healthy = healthy && evt.ProcessId != mainPid && evt.ExitCode != AsarIntegrityExitCode;
                                    log?.Invoke($"pid {evt.ProcessId} exited with code {DescribeCode(evt.ExitCode)}.", ELogType.Error);
                                }
                                wand.Remove(evt.ProcessId);
                                attached.Remove(evt.ProcessId);
                                initialBreakpoints.Remove(evt.ProcessId);
                                break;
                        }
                    }
                    catch
                    {
                        // Fail closed for Wand, but do not terminate a foreign game/process.
                        foreach (var process in wand.Values) TerminateProcess(process, 1);
                        throw;
                    }
                    finally
                    {
                        if (!continued && !ContinueDebugEvent(evt.ProcessId, evt.ThreadId, status))
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "Continuing process event failed");
                    }
                    if (!healthy)
                    {
                        // Surface a failed renderer immediately instead of waiting behind a black window.
                        foreach (var process in wand.Values) TerminateProcess(process, 1);
                        return false;
                    }
                }
                log?.Invoke($"Wand exited with code {mainExit}.", ELogType.Info);
                return mainExit == 0;
            }
            catch (Exception e)
            {
                foreach (var process in wand.Values) TerminateProcess(process, 1);
                log?.Invoke($"Wand launch failed: {e.Message}", ELogType.Error);
                return false;
            }
            finally
            {
                foreach (int pid in attached)
                    if (!DebugActiveProcessStop(pid))
                        log?.Invoke($"Could not detach pid {pid} (win32 error {Marshal.GetLastWin32Error()}).", ELogType.Error);
            }
        }

        private static string GetImagePath(IntPtr process)
        {
            var path = new StringBuilder(32768);
            int length = path.Capacity;
            if (!QueryFullProcessImageName(process, 0, path, ref length))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Identifying a new process failed");
            return Path.GetFullPath(path.ToString());
        }

        private static void DetachChild(DEBUG_EVENT evt, HashSet<int> attached, ref bool continued)
        {
            // Detach closes debug-owned handles. Duplicate the initial thread before detaching
            // so we can remove exactly our own suspend count afterwards (preserve CREATE_SUSPENDED).
            IntPtr self = GetCurrentProcess();
            if (!DuplicateHandle(self, evt.Thread, self, out IntPtr thread, 0, false, DUPLICATE_SAME_ACCESS))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Duplicating child thread failed");
            bool suspended = false;
            int logResumeFailure = 0;
            try
            {
                if (SuspendThread(thread) == uint.MaxValue)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Suspending foreign child failed");
                suspended = true;
                if (!ContinueDebugEvent(evt.ProcessId, evt.ThreadId, DBG_CONTINUE))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Continuing foreign child failed");
                continued = true;
                if (!DebugActiveProcessStop(evt.ProcessId))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Detaching foreign child failed");
                attached.Remove(evt.ProcessId);
            }
            finally
            {
                // Even a detach failure must not strand somebody else's process suspended.
                if (suspended && ResumeThread(thread) == uint.MaxValue)
                    logResumeFailure = Marshal.GetLastWin32Error();
                CloseHandle(thread);
            }
            if (logResumeFailure != 0)
                throw new Win32Exception(logResumeFailure, "Resuming foreign child failed");
        }

        private static string DescribeCode(int code)
        {
            return code == AsarIntegrityExitCode
                ? $"{code} (ASAR integrity check failed)"
                : $"{code} (0x{code:X8})";
        }

        private const uint DEBUG_PROCESS = 1, DUPLICATE_SAME_ACCESS = 2;
        private const uint DBG_CONTINUE = 0x00010002, DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        private const uint EXCEPTION_BREAKPOINT = 0x80000003;
        private const int ERROR_SEM_TIMEOUT = 121;
        private const int EXCEPTION_DEBUG_EVENT = 1, CREATE_PROCESS_DEBUG_EVENT = 3;
        private const int EXIT_PROCESS_DEBUG_EVENT = 5, LOAD_DLL_DEBUG_EVENT = 6;

        // x64 DEBUG_EVENT has a 16-byte prefix and a 160-byte union (EXCEPTION_DEBUG_INFO).
        [StructLayout(LayoutKind.Explicit, Size = 176)]
        private struct DEBUG_EVENT
        {
            [FieldOffset(0)] public int Code;
            [FieldOffset(4)] public int ProcessId;
            [FieldOffset(8)] public int ThreadId;
            [FieldOffset(16)] public IntPtr File;
            [FieldOffset(24)] public IntPtr Process;
            [FieldOffset(32)] public IntPtr Thread;
            [FieldOffset(40)] public IntPtr ImageBase;
            [FieldOffset(16)] public uint ExceptionCode;
            [FieldOffset(168)] public uint FirstChance;
            [FieldOffset(16)] public int ExitCode;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string application, StringBuilder command,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags,
            IntPtr environment, string directory, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForDebugEvent(out DEBUG_EVENT evt, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ContinueDebugEvent(int processId, int threadId, uint status);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugActiveProcessStop(int processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugSetProcessKillOnExit(bool killOnExit);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder path, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr source, IntPtr handle, IntPtr target,
            out IntPtr duplicate, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
