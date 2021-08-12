# HookDetection_Csharp

Blog link: working on it

- Detecting if ntdll's funcitons got hook via iterating RVAs.
- Only detect functions start with "Zw" or "Nt".
- Only tested in Win10/x64 with windows defender, works fine.

## README.md update later



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