using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static HookDectection.NativeStruct;
using static HookDectection.NativeFunctions;

namespace HookDectection
{
    public class Program
    {
        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }

        private static bool CompareArray(byte[] bt1, byte[] bt2)
        {
            var len1 = bt1.Length;
            var len2 = bt2.Length;

            if (len1 != len2)
            {
                return false;
            }

            for (var i = 0; i < len1; i++)
            {
                if (bt1[i] != bt2[i])
                    return false;
            }

            return true;
        }

        private static void FindFuncitonHooked()
        {
            IntPtr BaseAddress = LoadLibrary("ntdll");

            //Alloc memory for IMAGE_DOS_HEADER struct
            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
            IntPtr IMAGE_DOS_HEADER_Address = Marshal.AllocHGlobal(Marshal.SizeOf(IMAGE_DOS_HEADER_instance));
            RtlZeroMemory(IMAGE_DOS_HEADER_Address, Marshal.SizeOf(IMAGE_DOS_HEADER_instance));

            uint getsize = 0;
            bool return_status = false; 
            IntPtr CurrentHandle = Process.GetCurrentProcess().Handle;
            return_status = NtReadVirtualMemory(
                CurrentHandle, BaseAddress, 
                IMAGE_DOS_HEADER_Address, 
                (uint)Marshal.SizeOf(IMAGE_DOS_HEADER_instance),
                ref getsize
             );

            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(IMAGE_DOS_HEADER_Address, typeof(IMAGE_DOS_HEADER));
            // Console.WriteLine((IMAGE_DOS_HEADER_instance.e_lfanew).ToString());
            // Console.WriteLine("{}", BaseAddress);
           
            return;
        }

        private static Object FindObjectAddress(IntPtr BaseAddress, Object StructObject, IntPtr CurrentHandle)
        {
            IntPtr ObjAllocMemAddr = Marshal.AllocHGlobal(Marshal.SizeOf(StructObject.GetType()));
            RtlZeroMemory(ObjAllocMemAddr, Marshal.SizeOf(StructObject.GetType()));

            uint getsize = 0;
            bool return_status = false;
        
            return_status = NtReadVirtualMemory(
                CurrentHandle, 
                BaseAddress,
                ObjAllocMemAddr,
                (uint)Marshal.SizeOf(StructObject),
                ref getsize
             );

            StructObject = Marshal.PtrToStructure(ObjAllocMemAddr, StructObject.GetType());
            return StructObject;
        }

        private static Object Locate_Image_Export_Directory(IntPtr BaseAddress, IntPtr CurrentHandle)
        {
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;             
            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)FindObjectAddress(
                BaseAddress, 
                IMAGE_DOS_HEADER_instance, 
                CurrentHandle);

            IntPtr IMAGE_NT_HEADER64_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DOS_HEADER_instance.e_lfanew);
            IMAGE_NT_HEADERS64 IMAGE_NT_HEADER64_instance = new IMAGE_NT_HEADERS64();
            IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADERS64)FindObjectAddress(
                IMAGE_NT_HEADER64_address, 
                IMAGE_NT_HEADER64_instance, 
                CurrentHandle);

            IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADER64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            
            IntPtr IMAGE_EXPORT_DIRECTORY_address = (IntPtr)(BaseAddress.ToInt64() + (int)IMAGE_DATA_DIRECTORY_instance.VirtualAddress);
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = new IMAGE_EXPORT_DIRECTORY();
            IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY)FindObjectAddress(
                IMAGE_EXPORT_DIRECTORY_address, 
                IMAGE_EXPORT_DIRECTORY_instance, 
                CurrentHandle);

            // Console.WriteLine(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);
            // Console.WriteLine(ExportDirectoryRVA_address);
            // Console.WriteLine(IMAGE_NT_HEADER64_instance.Signature);
            // Console.WriteLine(IMAGE_NT_HEADER64_Address);
            // Console.WriteLine(IMAGE_DOS_HEADER_instance.e_lfanew);
            return IMAGE_EXPORT_DIRECTORY_instance;
        }

        public static void HookDectection()
        {
            IntPtr BaseAddress = LoadLibrary("ntdll");
            IntPtr CurrentHandle = Process.GetCurrentProcess().Handle;
            byte[] SyscallPrologue = new byte[4];
            byte[] SyscallHead = new byte[4] { 0x4c, 0x8b, 0xd1, 0xb8 };

            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = 
                (IMAGE_EXPORT_DIRECTORY)Locate_Image_Export_Directory(BaseAddress, CurrentHandle);

            IntPtr RVA_AddressOfFunctions = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions);
            IntPtr RVA_AddressOfNameOrdinals = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals);
            IntPtr RVA_AddressOfNames = (IntPtr)(BaseAddress.ToInt64() + IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 RVA_AddressOfNames_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfNames, 4 * iterate_num);
                string FuncName_temp = Marshal.PtrToStringAnsi((IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfNames_single));

                if ((FuncName_temp.Substring(0, 2)).ToLower() == "zw" || (FuncName_temp.Substring(0, 2)).ToLower() == "nt")
                {
                    UInt16 RVA_AddressOfNameOrdinals_single = (UInt16)Marshal.ReadInt16(RVA_AddressOfNameOrdinals, 2 * iterate_num);
                    UInt32 RVA_AddressOfFunctions_single = (UInt32)Marshal.ReadInt32(RVA_AddressOfFunctions, 4 * RVA_AddressOfNameOrdinals_single);
                    IntPtr REAL_Func_Address = (IntPtr)(BaseAddress.ToInt64() + RVA_AddressOfFunctions_single);

                    
                    for(int byte_offset = 0; byte_offset < SyscallPrologue.Length; byte_offset++)
                    {
                        SyscallPrologue[byte_offset] = Marshal.ReadByte(REAL_Func_Address, byte_offset);
                        // Console.ForegroundColor = ConsoleColor.Gray;
                        // Console.Write("{0} ", SyscallPrologue[byte_offset].ToString("x2"));
                    }

                    
                    // Console.WriteLine("\n{0}", RVA_AddressOfNameOrdinals_single);
                    if (CompareArray(SyscallPrologue, SyscallHead))
                    {
                        // Console.ForegroundColor = ConsoleColor.Green;
                        // Console.WriteLine("{0}:{1} is not hooked", RVA_AddressOfNames_single.ToString(), FuncName_temp);
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("{0}:{1} is hooked", RVA_AddressOfNames_single.ToString(), FuncName_temp);
                    }
                    
                   
                    //System.Threading.Thread.Sleep(100);
                }

            }

            // UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;         
            // Console.WriteLine(IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames);
            // Console.WriteLine(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames);

            //string FuncName_temp = Marshal.PtrToStringUni(RVA_AddressOfNames);
            /*
            UInt32 RVA_temp_address = 0;
            IntPtr RVA_temp_address_mem = Marshal.AllocHGlobal(Marshal.SizeOf(RVA_temp_address));
            RtlZeroMemory(RVA_temp_address_mem, Marshal.SizeOf(RVA_temp_address));
            uint getsize = 0;

            NtReadVirtualMemory(
               CurrentHandle,
               RVA_AddressOfNames,
               RVA_temp_address_mem,
               (uint)Marshal.SizeOf(RVA_temp_address),
               ref getsize
            );
            */


            /*
            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                NtReadVirtualMemory(
                   CurrentHandle,
                   RVA_AddressOfNames,
                   RVA_temp_address_mem,
                   (uint)Marshal.SizeOf(RVA_temp_address),
                   ref getsize
                );
            }
            */
            return; 

        }
       

        static void Main(string[] args)
        {
            HookDectection();
            System.Threading.Thread.Sleep(10000);
        }
    }
}
