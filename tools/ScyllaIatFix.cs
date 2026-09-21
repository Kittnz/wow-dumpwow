// Automated Scylla IAT fix for a live dumpwow-paused WowClassic process.
// Usage: ScyllaIatFix.exe <pid> <dump.exe> [imageBaseHex] [out.exe]
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class ScyllaIatFix
{
    const int SCY_ERROR_SUCCESS = 0;

    [DllImport("Scylla.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int ScyllaIatSearch(
        uint dwProcessId,
        out UIntPtr iatStart,
        out uint iatSize,
        UIntPtr searchStart,
        [MarshalAs(UnmanagedType.Bool)] bool advancedSearch);

    [DllImport("Scylla.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    static extern int ScyllaIatFixAutoW(
        UIntPtr iatAddr,
        uint iatSize,
        uint dwProcessId,
        string dumpFile,
        string iatFixFile);

    [DllImport("Scylla.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    static extern int ScyllaRebuildFileW(
        string fileToRebuild,
        [MarshalAs(UnmanagedType.Bool)] bool removeDosStub,
        [MarshalAs(UnmanagedType.Bool)] bool updatePeHeaderChecksum,
        [MarshalAs(UnmanagedType.Bool)] bool createBackup);

    [DllImport("Scylla.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    static extern bool ScyllaDumpProcessW(
        uint pid,
        string fileToDump,
        UIntPtr imagebase,
        UIntPtr entrypoint,
        string fileResult);

    static int Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: ScyllaIatFix <pid> <dump.exe> [imageBaseHex] [out.exe]");
            return 1;
        }

        uint pid = uint.Parse(args[0]);
        string dumpFile = Path.GetFullPath(args[1]);
        UIntPtr imageBase = args.Length >= 3 && args[2].Length > 0
            ? new UIntPtr(Convert.ToUInt64(args[2], 16))
            : UIntPtr.Zero;
        string outFile = args.Length >= 4
            ? Path.GetFullPath(args[3])
            : Path.Combine(Path.GetDirectoryName(dumpFile),
                Path.GetFileNameWithoutExtension(dumpFile) + "_SCY.exe");

        string scyllaDir = Path.GetFullPath(Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory));
        string scyllaDll = Path.Combine(scyllaDir, "Scylla.dll");
        if (!File.Exists(scyllaDll))
        {
            Console.Error.WriteLine("Scylla.dll not found next to this exe: " + scyllaDll);
            return 2;
        }

        SetDllDirectory(scyllaDir);
        Console.WriteLine("PID={0}", pid);
        Console.WriteLine("Dump={0}", dumpFile);
        Console.WriteLine("ImageBase=0x{0:X}", imageBase.ToUInt64());
        Console.WriteLine("Out={0}", outFile);

        // Prefer a fresh Scylla dump of the live process when we know the base.
        string workDump = dumpFile;
        if (imageBase != UIntPtr.Zero)
        {
            string liveDump = Path.Combine(Path.GetDirectoryName(outFile),
                Path.GetFileNameWithoutExtension(dumpFile) + "_live_SCY.exe");
            Console.WriteLine("Dumping live process to {0} ...", liveDump);
            if (ScyllaDumpProcessW(pid, null, imageBase, UIntPtr.Zero, liveDump))
            {
                workDump = liveDump;
                Console.WriteLine("Live dump OK");
            }
            else
            {
                Console.WriteLine("Live dump failed; falling back to existing dump file");
            }
        }

        UIntPtr iatStart;
        uint iatSize;
        Console.WriteLine("ScyllaIatSearch advanced...");
        int rc = ScyllaIatSearch(pid, out iatStart, out iatSize, imageBase, true);
        Console.WriteLine("advanced rc={0} iat=0x{1:X} size=0x{2:X}",
            rc, iatStart.ToUInt64(), iatSize);
        if (rc != SCY_ERROR_SUCCESS || iatStart == UIntPtr.Zero || iatSize == 0)
        {
            Console.WriteLine("Retrying ScyllaIatSearch normal...");
            rc = ScyllaIatSearch(pid, out iatStart, out iatSize, imageBase, false);
            Console.WriteLine("normal rc={0} iat=0x{1:X} size=0x{2:X}",
                rc, iatStart.ToUInt64(), iatSize);
        }
        if (rc != SCY_ERROR_SUCCESS || iatStart == UIntPtr.Zero || iatSize == 0)
        {
            Console.Error.WriteLine("IAT search failed");
            return 3;
        }

        string fixedTmp = outFile + ".tmp";
        if (File.Exists(fixedTmp)) File.Delete(fixedTmp);
        Console.WriteLine("ScyllaIatFixAutoW...");
        rc = ScyllaIatFixAutoW(iatStart, iatSize, pid, workDump, fixedTmp);
        Console.WriteLine("fix rc={0}", rc);
        if (rc != SCY_ERROR_SUCCESS || !File.Exists(fixedTmp))
        {
            Console.Error.WriteLine("IAT fix failed");
            return 4;
        }

        Console.WriteLine("ScyllaRebuildFileW...");
        rc = ScyllaRebuildFileW(fixedTmp, false, true, false);
        Console.WriteLine("rebuild rc={0}", rc);

        if (File.Exists(outFile)) File.Delete(outFile);
        File.Move(fixedTmp, outFile);
        Console.WriteLine("Wrote {0} ({1} bytes)", outFile, new FileInfo(outFile).Length);
        return 0;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetDllDirectory(string lpPathName);
}
