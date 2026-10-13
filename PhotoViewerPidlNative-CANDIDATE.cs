using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class PhotoViewerPidlNativeCandidate
{
    const uint ACCESS = 0x0410;
    const uint COMMIT = 0x1000;
    const uint PRIVATE = 0x20000;
    const uint GUARD = 0x100;
    const int CHUNK = 1048576;

    [StructLayout(LayoutKind.Sequential)]
    struct MBI
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FILEINFO
    {
        public uint Attributes;
        public FILETIME Creation;
        public FILETIME Access;
        public FILETIME Write;
        public uint Volume;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint IndexHigh;
        public uint IndexLow;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(
        uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UIntPtr VirtualQueryEx(
        IntPtr process, IntPtr address,
        out MBI info, UIntPtr length);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address,
        [Out] byte[] buffer, UIntPtr size,
        out UIntPtr read);

    [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
    static extern bool SHGetPathFromIDListW(
        byte[] pidl, StringBuilder path);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode,
        SetLastError=true)]
    static extern IntPtr CreateFileW(
        string name, uint access, uint share,
        IntPtr security, uint disposition,
        uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(
        IntPtr handle, out FILEINFO info);

    public class Result
    {
        public string Status;
        public string DocumentPath;
        public int CandidateCount;
        public int RawPathCount;
        public int ShellCalls;
        public long BytesScanned;
    }

    static byte[] Read(IntPtr process, ulong address, int count)
    {
        if (count <= 0) return null;

        byte[] buffer = new byte[count];
        UIntPtr got;

        bool ok = ReadProcessMemory(
            process,
            new IntPtr(unchecked((long)address)),
            buffer,
            (UIntPtr)(uint)count,
            out got);

        return ok && got.ToUInt64() == (ulong)count
            ? buffer : null;
    }

    static bool Readable(uint protect)
    {
        if ((protect & GUARD) != 0) return false;

        uint p = protect & 0xFF;

        return p == 2 || p == 4 || p == 8 ||
               p == 0x20 || p == 0x40 || p == 0x80;
    }

    static ushort Word(byte[] data, int offset)
    {
        return (ushort)(data[offset] |
            (data[offset + 1] << 8));
    }

    static bool Chain(byte[] data)
    {
        int pos = 0;
        int items = 0;

        while (pos + 2 <= data.Length && items < 32)
        {
            int cb = Word(data, pos);

            if (cb == 0)
                return items > 0 && pos + 2 == data.Length;

            if (cb < 3 || cb > 4096 ||
                pos + cb > data.Length)
                return false;

            pos += cb;
            items++;
        }

        return false;
    }

    static string ShellPath(byte[] pidl)
    {
        if (!Chain(pidl)) return null;

        StringBuilder buffer = new StringBuilder(32768);

        return SHGetPathFromIDListW(pidl, buffer)
            ? buffer.ToString() : null;
    }

    static string FileIdentity(string path)
    {
        IntPtr handle = CreateFileW(
            path, 0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);

        if (handle == IntPtr.Zero ||
            handle == new IntPtr(-1))
            return null;

        try
        {
            FILEINFO info;

            if (!GetFileInformationByHandle(handle, out info))
                return null;

            ulong index =
                ((ulong)info.IndexHigh << 32) |
                info.IndexLow;

            return info.Volume.ToString("X8") +
                ":" + index.ToString("X16");
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    static int NamePreference(string path)
    {
        int count = 0;

        foreach (string part in path.Split('\\'))
            if (part.Contains("~")) count++;

        return count;
    }

    static void AddPidl(
        byte[] pidl, string filename,
        HashSet<string> paths, Result result)
    {
        result.ShellCalls++;

        string path = ShellPath(pidl);

        if (String.IsNullOrEmpty(path)) return;

        if (!String.Equals(
            Path.GetFileName(path), filename,
            StringComparison.OrdinalIgnoreCase))
            return;

        if (!Path.IsPathRooted(path) || !File.Exists(path))
            return;

        paths.Add(Path.GetFullPath(path));
    }

    static void ExamineHit(
        IntPtr process,
        ulong regionStart,
        ulong regionEnd,
        ulong hit,
        byte[] needle,
        string filename,
        HashSet<string> paths,
        Result result)
    {
        if (hit < regionStart + 74) return;

        ulong child = hit - 74;

        byte[] head = Read(process, child, 3);
        if (head == null || head[2] != 0x32)
            return;

        int cb = Word(head, 0);

        if (cb < 76 + needle.Length ||
            cb > 4096 ||
            child + (ulong)cb + 2 > regionEnd)
            return;

        byte[] item = Read(process, child, cb + 2);
        if (item == null) return;

        if (Word(item, cb) != 0 ||
            Word(item, 74 + needle.Length) != 0)
            return;

        for (int i = 0; i < needle.Length; i++)
            if (item[74 + i] != needle[i])
                return;

        AddPidl(item, filename, paths, result);

        ulong start = Math.Max(
            regionStart, child > 8192 ? child - 8192 : 0);

        byte[] prior = Read(
            process, start, checked((int)(child - start)));

        if (prior == null) return;

        for (int i = 0; i + 3 <= prior.Length; i++)
        {
            if (prior[i] != 0x14 ||
                prior[i + 1] != 0 ||
                prior[i + 2] != 0x1F)
                continue;

            ulong root = start + (ulong)i;

            byte[] full = Read(
                process, root,
                checked((int)(child + (ulong)cb + 2 - root)));

            if (full != null && Chain(full))
                AddPidl(full, filename, paths, result);
        }
    }

    public static Result Resolve(uint pid, string filename)
    {
        Result result = new Result();
        result.Status = "UNRESOLVED";

        if (pid == 0 || String.IsNullOrWhiteSpace(filename))
            return result;

        IntPtr process = OpenProcess(ACCESS, false, pid);

        if (process == IntPtr.Zero)
            throw new Win32Exception(
                Marshal.GetLastWin32Error());

        HashSet<string> paths =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        byte[] needle = Encoding.Unicode.GetBytes(filename);

        try
        {
            ulong address = 0x10000;
            ulong maximum = 0x0000800000000000UL;

            while (address < maximum)
            {
                MBI mbi;

                if (VirtualQueryEx(
                    process,
                    new IntPtr(unchecked((long)address)),
                    out mbi,
                    (UIntPtr)(uint)Marshal.SizeOf(typeof(MBI))
                    ) == UIntPtr.Zero)
                    break;

                ulong begin = unchecked(
                    (ulong)mbi.BaseAddress.ToInt64());

                ulong length = mbi.RegionSize.ToUInt64();
                ulong end = begin + length;

                if (length == 0 || end <= address)
                    break;

                if (mbi.State == COMMIT &&
                    mbi.Type == PRIVATE &&
                    Readable(mbi.Protect))
                {
                    for (ulong pos = begin; pos < end;)
                    {
                        int wanted = (int)Math.Min(
                            (ulong)CHUNK, end - pos);

                        int overlap = (int)Math.Min(
                            (ulong)(needle.Length + 128),
                            end - pos - (ulong)wanted);

                        byte[] data = Read(
                            process, pos, wanted + overlap);

                        if (data != null)
                        {
                            result.BytesScanned += wanted;

                            for (int i = 0;
                                i + needle.Length <= data.Length &&
                                i < wanted; i++)
                            {
                                if (data[i] != needle[0])
                                    continue;

                                bool match = true;

                                for (int j = 1;
                                     j < needle.Length; j++)
                                {
                                    if (data[i+j] != needle[j])
                                    {
                                        match = false;
                                        break;
                                    }
                                }

                                if (match)
                                {
                                    ExamineHit(
                                        process, begin, end,
                                        pos + (ulong)i,
                                        needle, filename,
                                        paths, result);
                                }
                            }
                        }

                        pos += (ulong)wanted;
                    }
                }

                address = end;
            }
        }
        finally
        {
            CloseHandle(process);
        }

        result.RawPathCount = paths.Count;

        Dictionary<string, List<string>> groups =
            new Dictionary<string, List<string>>();

        foreach (string path in paths)
        {
            string id = FileIdentity(path);

            if (id == null)
            {
                result.Status = "AMBIGUOUS";
                result.CandidateCount = paths.Count;
                return result;
            }

            if (!groups.ContainsKey(id))
                groups[id] = new List<string>();

            groups[id].Add(path);
        }

        result.CandidateCount = groups.Count;

        if (groups.Count > 1)
        {
            result.Status = "AMBIGUOUS";
            return result;
        }

        if (groups.Count == 1)
        {
            foreach (List<string> aliases in groups.Values)
            {
                aliases.Sort(delegate(string a, string b)
                {
                    int compare = NamePreference(a).CompareTo(
                        NamePreference(b));

                    if (compare != 0) return compare;

                    compare = b.Length.CompareTo(a.Length);

                    return compare != 0 ? compare :
                        StringComparer.OrdinalIgnoreCase.Compare(a, b);
                });

                result.DocumentPath = aliases[0];
            }

            result.Status = "SUCCESS";
        }

        return result;
    }
}
