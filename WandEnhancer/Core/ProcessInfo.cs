using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WandEnhancer.Core
{
    /// <summary>
    /// Facts read straight out of another process's PEB before modules load.
    /// </summary>
    internal static class ProcessInfo
    {
        /// <summary>
        /// The kernel writes the image base before the first instruction runs, so this is the one
        /// reading that works on a process that young.
        /// </summary>
        /// <returns>Zero while the process has no PEB yet.</returns>
        public static IntPtr GetImageBase(IntPtr process, out string problem)
        {
            var info = new PROCESS_BASIC_INFORMATION();
            int status = NtQueryInformationProcess(process, ProcessBasicInformation, ref info,
                Marshal.SizeOf(info), out int returned);
            problem = null;
            if (status != 0 || info.PebBaseAddress == IntPtr.Zero)
            {
                problem = $"PEB query failed (NTSTATUS 0x{status:X8}, returned {returned} bytes, PEB {info.PebBaseAddress})";
                return IntPtr.Zero;
            }
            var bytes = new byte[IntPtr.Size];
            if (!ReadProcessMemory(process, new IntPtr(info.PebBaseAddress.ToInt64() + ImageBaseOffset),
                    bytes, (UIntPtr)bytes.Length, out UIntPtr read) || read.ToUInt64() != (ulong)bytes.Length)
            {
                problem = $"image base read failed (win32 error {Marshal.GetLastWin32Error()}, read {read.ToUInt64()}/{bytes.Length} bytes)";
                return IntPtr.Zero;
            }
            var imageBase = new IntPtr(BitConverter.ToInt64(bytes, 0));
            if (imageBase == IntPtr.Zero) problem = "PEB contains a null image base";
            return imageBase;
        }

        /// <summary>
        /// Electron's process type, taken from the command line (e.g. "renderer", "main").
        /// </summary>
        /// <returns>Null when the command line is not readable, which a bare pid still survives.</returns>
        public static string GetElectronRole(IntPtr process)
        {
            string commandLine = GetCommandLine(process);
            if (commandLine == null)
            {
                return null;
            }

            string type = ValueOf(commandLine, "--type=");
            if (type == null)
            {
                return "main";
            }

            string subType = ValueOf(commandLine, "--utility-sub-type=");
            return subType == null ? type : $"{type}/{subType}";
        }

        private static string GetCommandLine(IntPtr process)
        {
            IntPtr peb = GetPeb(process);
            IntPtr parameters = peb == IntPtr.Zero
                ? IntPtr.Zero
                : ReadPointer(process, new IntPtr(peb.ToInt64() + ProcessParametersOffset));
            if (parameters == IntPtr.Zero)
            {
                return null;
            }

            // UNICODE_STRING: Length, MaximumLength, four bytes of padding, then the buffer.
            var descriptor = new byte[16];
            var address = new IntPtr(parameters.ToInt64() + CommandLineOffset);
            if (!Read(process, address, descriptor))
            {
                return null;
            }

            int length = BitConverter.ToUInt16(descriptor, 0);
            var buffer = new IntPtr(BitConverter.ToInt64(descriptor, 8));
            if (length == 0 || buffer == IntPtr.Zero)
            {
                return null;
            }

            var text = new byte[length];
            return Read(process, buffer, text) ? Encoding.Unicode.GetString(text) : null;
        }

        /// <summary>Reads a switch value up to the next space; Chromium never quotes these.</summary>
        private static string ValueOf(string commandLine, string option)
        {
            int start = commandLine.IndexOf(option, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }

            start += option.Length;
            int end = commandLine.IndexOf(' ', start);
            return end < 0 ? commandLine.Substring(start) : commandLine.Substring(start, end - start);
        }

        private static IntPtr GetPeb(IntPtr process)
        {
            var info = new PROCESS_BASIC_INFORMATION();
            return NtQueryInformationProcess(process, ProcessBasicInformation, ref info,
                Marshal.SizeOf(info), out _) == 0
                ? info.PebBaseAddress
                : IntPtr.Zero;
        }

        private static IntPtr ReadPointer(IntPtr process, IntPtr address)
        {
            var buffer = new byte[IntPtr.Size];
            return Read(process, address, buffer) ? new IntPtr(BitConverter.ToInt64(buffer, 0)) : IntPtr.Zero;
        }

        private static bool Read(IntPtr process, IntPtr address, byte[] buffer)
        {
            return ReadProcessMemory(process, address, buffer, (UIntPtr)buffer.Length, out UIntPtr read)
                   && read.ToUInt64() == (ulong)buffer.Length;
        }

        #region P/Invoke

        private const int ProcessBasicInformation = 0;
        private const int ImageBaseOffset = 0x10;
        private const int ProcessParametersOffset = 0x20;
        private const int CommandLineOffset = 0x70;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr dwSize, out UIntPtr lpNumberOfBytesRead);

        #endregion
    }
}
