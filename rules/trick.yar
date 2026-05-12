/*
   YARA Rule Set
   Author: yarGen GUI
   Date: 2026-05-12
   Identifier: Trickbot
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc {
   meta:
      description = "Malware family rule - file 4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc"
   strings:
      $x1 = "c:\\temp\\loader.log" fullword ascii /* score: '41.00'*/
      $x2 = "c:\\temp\\core-dll.log" fullword ascii /* score: '37.00'*/
      $x3 = "loader.dll" fullword ascii /* score: '32.00'*/
      $s4 = "Injecting process pid = %ld" fullword ascii /* score: '29.00'*/
      $s5 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" fullword ascii /* score: '29.00'*/
      $s6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" fullword ascii /* score: '29.00'*/
      $s7 = "\\System32\\KERNEL32.DLL" fullword wide /* score: '29.00'*/
      $s8 = "\\System32\\kernelbase.dll" fullword wide /* score: '29.00'*/
      $s9 = "[INJECT] inject_via_remotethread_wow64: GetVersionEx failed" fullword ascii /* score: '28.00'*/
      $s10 = "Injection failure process pid = %ld" fullword ascii /* score: '28.00'*/
      $s11 = "[HTTP::ExecuteMethod] Content type = %s" fullword ascii /* score: '28.00'*/
      $s12 = "Failed to read Edge passwords from loader module" fullword ascii /* score: '27.00'*/
      $s13 = "Failed to inject the DLL: %ld" fullword ascii /* score: '26.00'*/
      $s14 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" fullword ascii /* score: '26.00'*/
      $s15 = "crashreporter.exe" fullword ascii /* score: '25.00'*/
      $s16 = "runtimebroker.exe" fullword ascii /* score: '25.00'*/
      $s17 = "DLL and target process must be same architecture" fullword ascii /* score: '25.00'*/
      $s18 = "Injected process pid = %ld" fullword ascii /* score: '25.00'*/
      $s19 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" fullword ascii /* score: '23.00'*/
      $s20 = "chrome.dll" fullword ascii /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "fc1713ab03790cbe4946cc01b2d67b20" and ( pe.exports("b'Control'") and pe.exports("b'FreeBuffer'") and pe.exports("b'Release'") and pe.exports("b'Start'") ) or ( 1 of ($x*) or 4 of them ) )
}

rule ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4 {
   meta:
      description = "Malware family rule - file ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
   strings:
      $x1 = "c:\\temp\\core-dll.log" fullword ascii /* score: '37.00'*/
      $s2 = "\\System32\\KERNEL32.DLL" fullword wide /* score: '29.00'*/
      $s3 = "\\System32\\kernelbase.dll" fullword wide /* score: '29.00'*/
      $s4 = "[HTTP::ExecuteMethod] Content type = %s" fullword ascii /* score: '28.00'*/
      $s5 = "Failed to read Edge passwords from loader module" fullword ascii /* score: '27.00'*/
      $s6 = "crashreporter.exe" fullword ascii /* score: '25.00'*/
      $s7 = "chrome.dll" fullword ascii /* score: '23.00'*/
      $s8 = "updater.exe" fullword ascii /* score: '22.00'*/
      $s9 = "Failed to read DPost config- exit" fullword ascii /* score: '22.00'*/
      $s10 = ";UWININET.DLL" fullword ascii /* score: '20.00'*/
      $s11 = "DPOST failed - no servers responding. DISABLED for 10 minutes!" fullword ascii /* score: '20.00'*/
      $s12 = "core-dll.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Skip DPOST on %s - disabled (%ld)" fullword ascii /* score: '20.00'*/
      $s14 = "c:\\config.bin" fullword ascii /* score: '19.00'*/
      $s15 = "\\\\.\\pipe\\pidplacesomepipe" fullword ascii /* score: '19.00'*/
      $s16 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" fullword ascii /* score: '19.00'*/
      $s17 = "Failed to read rules - exit" fullword ascii /* score: '18.00'*/
      $s18 = "(): PeProcessImport error" fullword ascii /* score: '18.00'*/
      $s19 = "STATIC INJECT OVERRIDE" fullword ascii /* score: '18.00'*/
      $s20 = "Failed to read ID - exit" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "ab602db9ab9becb3827c383c833793d3" and pe.exports("b'?ReflectiveLoader@@YGXPAX0K0K@Z'") or ( 1 of ($x*) or 4 of them ) )
}

rule sig_6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a2b84ba {
   meta:
      description = "Malware family rule - file 6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a2b84ba"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a2b84ba"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ /* score: '30.00'*/
      $s2 = "c:\\developer\\webinject\\http-lib\\parser.c" fullword wide /* score: '29.00'*/
      $s3 = "%SystemRoot%\\System32\\ntoskrnl.exe" fullword ascii /* score: '27.00'*/
      $s4 = "StartSubProcess" fullword ascii /* score: '15.00'*/
      $s5 = "<moduleconfig><nohead>yes</nohead><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"winj\" file=\"winj\" perio" ascii /* score: '12.00'*/
      $s6 = "><conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" fullword ascii /* score: '12.00'*/
      $s7 = "<moduleconfig><nohead>yes</nohead><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"winj\" file=\"winj\" perio" ascii /* score: '12.00'*/
      $s8 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s9 = "Content-Disposition: form-data; " fullword ascii /* score: '9.00'*/
      $s10 = "operator co_await" fullword ascii /* score: '9.00'*/
      $s11 = "nopqrstu" fullword ascii /* score: '8.00'*/
      $s12 = "fghijklm" fullword ascii /* score: '8.00'*/
      $s13 = "4Y:\\a4AP" fullword ascii /* score: '7.00'*/
      $s14 = "bInw/r^." fullword ascii /* score: '7.00'*/
      $s15 = "\\.\"I+v" fullword ascii /* score: '7.00'*/
      $s16 = "LMNOPQRSJT" fullword ascii /* score: '6.50'*/
      $s17 = "$\"%d,!g" fullword ascii /* score: '6.50'*/
      $s18 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s19 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s20 = "!\"decoder is corrupt\"" fullword wide /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "5574e26277fe9f79e7fdb49ca0e6182d" and ( pe.exports("b'?AFind@@YAHPEAX@Z'") and pe.exports("b'?AIAnAiAt@@YAXH@Z'") and pe.exports("b'?MegaFreeBuffer@@YAXPEAX@Z'") and pe.exports("b'?ReleaseModuleBuffers@@YAXPEAX@Z'") and pe.exports("b'?ShAuAtadAoAwan@@YAXXZ'") and pe.exports("b'?ShutdownPrimary@@YAXXZ'") ) or 8 of them )
}

rule e2e034dfa6cc9e5dae4121a0b3fa6d56 {
   meta:
      description = "Malware family rule - file e2e034dfa6cc9e5dae4121a0b3fa6d56"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "e4d2675a178319609e0b022d9dfed2b6e68d1d269b0b4e25ed63cc24f7296841"
   strings:
      $s1 = "17.11.2020 19:55:46,56 [Log START]  ============ C:\\OEM\\FIVT\\ModularizationItems\\CheckBIOSSkuID\\CheckBIOSSkuID.cmd ========" ascii /* score: '23.00'*/
      $s2 = "151.0.5.81.asq.exe" fullword wide /* score: '21.00'*/
      $s3 = "asq.exe" fullword wide /* score: '19.00'*/
      $s4 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s5 = "6;839%;-;" fullword ascii /* score: '9.00'*/ /* hex encoded string 'h9' */
      $s6 = "vjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvt" ascii /* score: '8.00'*/
      $s7 = "lfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfjurbcrjnbynsswovjvtnjbywcifjclfju" ascii /* score: '8.00'*/
      $s8 = "lfjurbcrjnbynsswovjvtnjbywcifjc" fullword ascii /* score: '8.00'*/
      $s9 = "u2Q]r:\"" fullword ascii /* score: '7.00'*/
      $s10 = "407P7T7X7@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s11 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s12 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s13 = "deli hevet associacy limte " fullword wide /* score: '6.00'*/
      $s14 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s15 = "Y+ [9!" fullword ascii /* score: '5.00'*/
      $s16 = "crhnny" fullword ascii /* score: '5.00'*/
      $s17 = "vtujfy" fullword ascii /* score: '5.00'*/
      $s18 = "bynsswovjv0" fullword ascii /* score: '5.00'*/
      $s19 = "k /kTv" fullword ascii /* score: '5.00'*/
      $s20 = "Broken pipe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.26'*/ /* Goodware String - occured 742 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "13012c7764c22db0eea00ae6b1458d85" or 8 of them )
}

rule ec2a22d92dd78e37a6705c8116251fabdae2afecb358b32be32da58008115f77 {
   meta:
      description = "Malware family rule - file ec2a22d92dd78e37a6705c8116251fabdae2afecb358b32be32da58008115f77"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "ec2a22d92dd78e37a6705c8116251fabdae2afecb358b32be32da58008115f77"
   strings:
      $x1 = "C:\\Users\\User\\Desktop\\2008\\18.2.20\\imagestone_src\\image_stone\\example\\002\\Release\\002.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '27.00'*/
      $s3 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x8" ascii /* score: '21.00'*/
      $s4 = "002.exe" fullword wide /* score: '19.00'*/
      $s5 = "http://www.phoxo.com/en/" fullword wide /* score: '17.00'*/
      $s6 = "phoxo.ascii_%d.txt" fullword wide /* score: '17.00'*/
      $s7 = ".?AVCProcessTask@DlgEffectBase@@" fullword ascii /* score: '15.00'*/
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s9 = "Bf:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\winfrm.cpp" fullword wide /* score: '13.00'*/
      $s10 = "Cf:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\auxdata.cpp" fullword wide /* score: '13.00'*/
      $s11 = ".?AVCResizeImageCommand@@" fullword ascii /* score: '12.00'*/
      $s12 = ".?AVFCEffectSoftPortrait@@" fullword ascii /* score: '12.00'*/
      $s13 = ".?AVCDrawTextCommand@@" fullword ascii /* score: '12.00'*/
      $s14 = ".?AV?$DlgEffectThreeSlider@VFCEffectSoftPortrait@@@@" fullword ascii /* score: '12.00'*/
      $s15 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s16 = "Paint.NET v2.64" fullword ascii /* score: '10.00'*/
      $s17 = "Paint.NET v2.6%" fullword ascii /* score: '10.00'*/
      $s18 = "SAVE_ERROR_NO_AUTHORITY" fullword wide /* score: '10.00'*/
      $s19 = "All Supported Image|*.bmp; *.jpg; *.jpeg; *.gif; *.tif; *.tiff; *.png|All Files (*.*)|*.*||" fullword wide /* score: '10.00'*/
      $s20 = "SAVE_ERROR_NO_AUTHORITY=Save file fails, no permission to save in this directory" fullword wide /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "d41fffa3a8fcea2babca0623806f1c67" or ( 1 of ($x*) or 4 of them ) )
}

/* Super Rules ------------------------------------------------------------- */

rule _4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc_ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b_0 {
   meta:
      description = "Malware family rule - from files 4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc, ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc"
      hash2 = "ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
   strings:
      $x1 = "c:\\temp\\core-dll.log" fullword ascii /* score: '37.00'*/
      $s2 = "\\System32\\KERNEL32.DLL" fullword wide /* score: '29.00'*/
      $s3 = "\\System32\\kernelbase.dll" fullword wide /* score: '29.00'*/
      $s4 = "[HTTP::ExecuteMethod] Content type = %s" fullword ascii /* score: '28.00'*/
      $s5 = "Failed to read Edge passwords from loader module" fullword ascii /* score: '27.00'*/
      $s6 = "crashreporter.exe" fullword ascii /* score: '25.00'*/
      $s7 = "chrome.dll" fullword ascii /* score: '23.00'*/
      $s8 = "updater.exe" fullword ascii /* score: '22.00'*/
      $s9 = "Failed to read DPost config- exit" fullword ascii /* score: '22.00'*/
      $s10 = ";UWININET.DLL" fullword ascii /* score: '20.00'*/
      $s11 = "DPOST failed - no servers responding. DISABLED for 10 minutes!" fullword ascii /* score: '20.00'*/
      $s12 = "core-dll.dll" fullword ascii /* score: '20.00'*/
      $s13 = "Skip DPOST on %s - disabled (%ld)" fullword ascii /* score: '20.00'*/
      $s14 = "c:\\config.bin" fullword ascii /* score: '19.00'*/
      $s15 = "\\\\.\\pipe\\pidplacesomepipe" fullword ascii /* score: '19.00'*/
      $s16 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" fullword ascii /* score: '19.00'*/
      $s17 = "Failed to read rules - exit" fullword ascii /* score: '18.00'*/
      $s18 = "(): PeProcessImport error" fullword ascii /* score: '18.00'*/
      $s19 = "STATIC INJECT OVERRIDE" fullword ascii /* score: '18.00'*/
      $s20 = "Failed to read ID - exit" fullword ascii /* score: '18.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc_6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a_1 {
   meta:
      description = "Malware family rule - from files 4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc, 6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a2b84ba, e2e034dfa6cc9e5dae4121a0b3fa6d56, ec2a22d92dd78e37a6705c8116251fabdae2afecb358b32be32da58008115f77, ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
      author = "yarGen GUI"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2026-05-12"
      hash1 = "4becc0d518a97cc31427cd08348958cda4e00487c7ec0ac38fdcd53bbe36b5cc"
      hash2 = "6a75c212b49093517e6c29dcb2644df57a931194cf5cbd58e39e649c4a2b84ba"
      hash3 = "e4d2675a178319609e0b022d9dfed2b6e68d1d269b0b4e25ed63cc24f7296841"
      hash4 = "ec2a22d92dd78e37a6705c8116251fabdae2afecb358b32be32da58008115f77"
      hash5 = "ef6603a7ef46177ecba194148f72d396d0ddae47e3d6e86cf43085e34b3a64d4"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s3 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s4 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s5 = " delete[]" fullword ascii /* score: '4.00'*/
      $s6 = " delete" fullword ascii /* score: '3.00'*/
      $s7 = " new[]" fullword ascii /* score: '1.00'*/
      $s8 = " Base Class Array'" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

