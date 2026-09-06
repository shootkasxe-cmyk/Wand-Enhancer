using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// Compiled only by test-launcher.ps1. No installed application is opened or changed.
public static class LauncherFixture
{
    [DllImport("kernel32.dll")] private static extern bool IsDebuggerPresent();

    public static int Main(string[] args)
    {
        string output = args[1];
        if (args[0] == "foreign")
        {
            File.WriteAllText(output, IsDebuggerPresent() ? "debugged" : "detached");
            return IsDebuggerPresent() ? 21 : 0;
        }

        var module = Process.GetCurrentProcess().MainModule;
        var image = File.ReadAllBytes(module.FileName);
        var sentinel = Encoding.ASCII.GetBytes("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX");
        bool verified = false;
        for (int i = 0; i + 39 <= image.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < sentinel.Length; j++)
                if (image[i + j] != sentinel[j]) { match = false; break; }
            if (match && image[i + 32] == 1 && image[i + 33] == 8)
            {
                int pe = BitConverter.ToInt32(image, 0x3c);
                int sections = BitConverter.ToUInt16(image, pe + 6);
                int table = pe + 24 + BitConverter.ToUInt16(image, pe + 20);
                for (int section = 0; section < sections; section++)
                {
                    int entry = table + section * 40;
                    int raw = BitConverter.ToInt32(image, entry + 20);
                    int size = BitConverter.ToInt32(image, entry + 16);
                    if (i >= raw && i + 39 <= raw + size)
                    {
                        int rva = BitConverter.ToInt32(image, entry + 12) + i - raw;
                        verified = Marshal.ReadByte(new IntPtr(module.BaseAddress.ToInt64() + rva + 38)) == (byte)'r';
                        break;
                    }
                }
                break;
            }
        }
        if (!verified) return -36861;
        File.AppendAllText(output, args[0] + " verified\n");
        if (args[0] == "child") return 0;
        if (args[0] == "fail-child") return -36861;

        string self = module.FileName;
        if (args[0] == "failure")
        {
            using (var child = Process.Start(new ProcessStartInfo(self, "fail-child \"" + output + "\"") { UseShellExecute = false }))
                child.WaitForExit();
            Thread.Sleep(30000); // A child failure must be surfaced before the parent exits.
            return 0;
        }
        // Late creation catches the old startup-only debugger regression.
        Thread.Sleep(10000);
        using (var child = Process.Start(new ProcessStartInfo(self, "child \"" + output + "\"") { UseShellExecute = false }))
        {
            child.WaitForExit();
            if (child.ExitCode != 0) return child.ExitCode;
        }
        using (var foreign = Process.Start(new ProcessStartInfo(args[2], "foreign \"" + output + ".foreign\"") { UseShellExecute = false }))
        {
            foreign.WaitForExit();
            return foreign.ExitCode;
        }
    }
}
