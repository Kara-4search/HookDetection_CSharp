using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HookDectection
{
    class NativeFunctions
    {
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(IntPtr pBuffer, int length);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Boolean NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 NumberOfBytesToRead,
            ref UInt32 liRet
        );
    }
}
