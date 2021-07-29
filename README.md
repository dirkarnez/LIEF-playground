LIEF-playground
===============
### Reference
- [LIEF/src/PE/utils/ordinals_lookup_tables at 158f291b1f1beec2e420e6624ec7833add0fb1e4 · lief-project/LIEF](https://github.com/lief-project/LIEF/tree/158f291b1f1beec2e420e6624ec7833add0fb1e4/src/PE/utils/ordinals_lookup_tables)
- [LIEF/test_hooking.py at master · lief-project/LIEF](https://github.com/lief-project/LIEF/blob/master/tests/pe/test_hooking.py)
- [LIEF/pe_from_scratch.py at master · lief-project/LIEF](https://github.com/lief-project/LIEF/blob/master/examples/python/pe_from_scratch.py)
- [patch elf文件 - 使用lief - 簡書](https://www.jianshu.com/p/4c5acb6df903)
- [02 - Create a PE from scratch — LIEF Documentation](https://lief.quarkslab.com/doc/stable/tutorials/02_pe_from_scratch.html)
- [PE — LIEF Documentation](https://lief.quarkslab.com/doc/latest/api/python/pe.html#lief.PE.OptionalHeader.imagebase)
  - ```
    The preferred address of the first byte of image when loaded into memory. It must be a multiple of 64K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    ```
