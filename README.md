# HookDetection_Csharp

Blog link: working on it

- Detecting if ntdll's funcitons got hook via iterating RVAs.
- So we could avoid using the functions which already hooked，or unhook them。 
- Only detect functions start with "Zw" or "Nt".
- Only tested in Win10/x64, works fine.
- Steps
	1. Iterate through all the exported functions of the ntdll.dll
	2. Read the first 4 bytes of the the syscall stub and check if they start with 4c 8b d1 b8
		- If yes, the function is not hooked
		- If no, the function is most likely hooked (with a couple of exceptions mentioned in the False Positives callout).
- **Although highly effective at detecting functions hooked with inline patching, this method returns a few false positives when enumerating hooked functions inside ntdll.dll, such as:**
**False Positives**
```
	NtGetTickCount
	NtQuerySystemTime
	NtdllDefWindowProc_A
	NtdllDefWindowProc_W
	NtdllDialogWndProc_A
	NtdllDialogWndProc_W
	ZwQuerySystemTime
```
**The above functions are not hooked.**
## Usage 
1. Launch through a white-list application
- With windowsdefender
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/HookDetection_WD.png)
- With EDR
	![avatar](https://raw.githubusercontent.com/Kara-4search/tempPic/main/HookDetection_EDR.jpeg)



## TO-DO list
- x86 version of it.
- Maybe check the kernel32.dll.

## Update history
- Restruct code - 20210821


## Reference link:
	1. https://blog.csdn.net/sankernel/article/details/104266483
	2. https://blog.csdn.net/whatday/article/details/52691109
	3. https://blog.csdn.net/sryan/article/details/7950950
	4. https://blog.csdn.net/mywsfxzxb/article/details/15336663
	5. http://blog.leanote.com/post/snowming/e4bd72b3279b
	6. http://lmao123.com/index.php/175.html
	7. http://pinvoke.net/default.aspx/Structures/IMAGE_OPTIONAL_HEADER64.html
	8. http://pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
	9. http://pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
	10. https://stackoverflow.com/questions/2170843/va-virtual-address-rva-relative-virtual-address
	11. https://blog.csdn.net/sankernel/article/details/104266483
	12. https://makosecblog.com/malware-dev/dll-unhooking-csharp/