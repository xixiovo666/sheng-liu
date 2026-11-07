from pathlib import Path
import re
p=Path('uefi-sheng/Platforms/Xiaomi/shengPkg/sheng.dsc'); s=p.read_text(); assert re.search(r'SHENG_VENDOR_HW\s*=\s*0',s) and re.search(r'USE_CUSTOM_DISPLAY_DRIVER\s*=\s*0',s)
needle='  UniXNUPkg/Driver/UniXNURamDiskDxe/UniXNURamDiskDxe.inf'; assert s.count(needle)==1
s=s.replace(needle,needle+' {\n    <LibraryClasses>\n      NULL|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf\n  }'); p.write_text(s)
p=Path('device/board.toml'); s=p.read_text();
if '"MDEPKG_NDEBUG"' not in s:
 marker='["firmware"."defines"]'; assert marker in s; s=s.replace(marker,marker+'\n"MDEPKG_NDEBUG" = "TRUE"',1)
p.write_text(s)
print('Configured vendorHW0/customDisplay0, module-scoped LZMA and NDEBUG; no kernel/root build')
