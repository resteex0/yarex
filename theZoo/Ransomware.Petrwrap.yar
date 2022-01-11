
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Petrwrap 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Petrwrap {
	meta: 
		 description= "Ransomware_Petrwrap Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0487382a4daf8eb9660f1c67e30f8b25"
		 hash2= "51c028cd5f3afe9bf179d81def8d7a8e"
		 hash3= "65d9d04ea080e04e9d0aebf55aecd5d0"
		 hash4= "71b6a493388e7d0b40c83ce903bc6b04"
		 hash5= "b2303c3eb127d1ce6906d21d9d2d07a5"
		 hash6= "d2ec63b63e88ece47fbaab1ca22da1ef"

	strings:

	
 		 $s1= "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" fullword wide
		 $s2= "1. Send $300 worth of Bitcoin to following address:" fullword wide
		 $s3= "2. Send your Bitcoin wallet ID and personal installation key to e-mail " fullword wide
		 $s4= ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz." fullword wide
		 $s5= "{71461f04-2faa-4bb9-a0dd-28a79101b599}" fullword wide
		 $s6= "{8175e2c1-d077-43b3-8e9b-6232d4603826}" fullword wide
		 $s7= "9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONC" fullword wide
		 $s8= "All you need to do is submit the payment and purchase the decryption key." fullword wide
		 $s9= "Assembly Version" fullword wide
		 $s10= "at %02d:%02d %ws" fullword wide
		 $s11= "{ce810127-2302-472e-8116-06e26a6156f5}, PublicKeyToken=3e56350693f7355e" fullword wide
		 $s12= "deletejournal /D %c:" fullword wide
		 $s13= "e2NlODEwMTI3LTIzMDItNDcyZS04MTE2LTA2ZTI2YTYxNTZmNX0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1" fullword wide
		 $s14= "FileDescription" fullword wide
		 $s15= "h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar." fullword wide
		 $s16= "If you see this text, then your files are no longer accessible, because" fullword wide
		 $s17= "LegalTrademarks" fullword wide
		 $s18= "lKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB" fullword wide
		 $s19= "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide
		 $s20= "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ" fullword wide
		 $s21= "NjM1MDY5M2Y3MzU1ZQ==,[z]{98542371-8c60-497f-90d1-06e7bb84eeb8},e2NlODEwMTI3LTIzMDItNDcyZS04MTE2LTA2Z" fullword wide
		 $s22= "Ooops, your important files are encrypted." fullword wide
		 $s23= "OriginalFilename" fullword wide
		 $s24= "our decryption service." fullword wide
		 $s25= "Please follow the instructions:" fullword wide
		 $s26= ", PublicKeyToken=" fullword wide
		 $s27= "PublicKeyToken=" fullword wide
		 $s28= "SeDebugPrivilege" fullword wide
		 $s29= "SeShutdownPrivilege" fullword wide
		 $s30= "shutdown.exe /r /f" fullword wide
		 $s31= ",Sysinternals Utilitie" fullword wide
		 $s32= "they have been encrypted. Perhaps you are busy looking for a way to recover" fullword wide
		 $s33= "TI2YTYxNTZmNX0=,[z]{98542371-8c60-497f-90d1-06e7bb84eeb8}" fullword wide
		 $s34= "uEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiF" fullword wide
		 $s35= "u%s \\%s -accepteula -s " fullword wide
		 $s36= "vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip." fullword wide
		 $s37= "VS_VERSION_INFO" fullword wide
		 $s38= "We guarantee that you can recover all your files safely and easily." fullword wide
		 $s39= "wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn" fullword wide
		 $s40= "wowsmith123456@posteo.net." fullword wide
		 $s41= "Wrong Header Signature" fullword wide
		 $s42= "\\%wsadmin$%ws" fullword wide
		 $s43= "your files, but don't waste your time. Nobody can recover your files without" fullword wide
		 $s44= "Your personal installation key:" fullword wide
		 $a1= "$08FED190-BE19-11D3-A28B-00104BD35090" fullword ascii
		 $a2= "$08FED191-BE19-11D3-A28B-00104BD35090" fullword ascii
		 $a3= "$093FF999-1EA0-4079-9525-9614C3504B74" fullword ascii
		 $a4= "$0AB5A3D0-E5B6-11D0-ABF5-00A0C90FFFC0" fullword ascii
		 $a5= "$0BB02EC0-EF49-11CF-8940-00A0C9054228" fullword ascii
		 $a6= "$0D43FE01-F093-11CF-8940-00A0C9054228" fullword ascii
		 $a7= "$24BE5A30-EDFE-11D2-B933-00104B365C9F" fullword ascii
		 $a8= "$24BE5A31-EDFE-11D2-B933-00104B365C9F" fullword ascii
		 $a9= "$2A0B9D10-4B87-11D3-A97A-00104B365C9F" fullword ascii
		 $a10= "$2f84182c-db91-4187-a381-821cb5112a09" fullword ascii
		 $a11= "$387DAFF4-DA03-44D2-B0D1-80C927C905AC" fullword ascii
		 $a12= "$41904400-BE18-11D3-A28B-00104BD35090" fullword ascii
		 $a13= "$50E13488-6F1E-4450-96B0-873755403955" fullword ascii
		 $a14= "$53BAD8C1-E718-11CF-893D-00A0C9054228" fullword ascii
		 $a15= "$72C24DD5-D70A-438B-8A42-98424B88AFB8" fullword ascii
		 $a16= "$A548B8E4-51D5-4661-8824-DAA1D893DFB2" fullword ascii
		 $a17= "$C7C3F5A0-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a18= "$C7C3F5A1-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a19= "$C7C3F5A2-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a20= "$C7C3F5A3-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a21= "$C7C3F5A4-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a22= "$C7C3F5A5-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a23= "$C7C3F5B1-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a24= "$C7C3F5B2-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a25= "$C7C3F5B3-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a26= "$C7C3F5B4-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a27= "$C7C3F5B5-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a28= "$C7C3F5B6-88A3-11D0-ABCB-00A0C90FFFC0" fullword ascii
		 $a29= "$ebc25cf6-9120-4283-b972-0e5520d00004" fullword ascii
		 $a30= "$ebc25cf6-9120-4283-b972-0e5520d00005" fullword ascii
		 $a31= "$ebc25cf6-9120-4283-b972-0e5520d00006" fullword ascii
		 $a32= "$ebc25cf6-9120-4283-b972-0e5520d00007" fullword ascii
		 $a33= "$ebc25cf6-9120-4283-b972-0e5520d00008" fullword ascii
		 $a34= "$ebc25cf6-9120-4283-b972-0e5520d00009" fullword ascii
		 $a35= "$ebc25cf6-9120-4283-b972-0e5520d0000A" fullword ascii
		 $a36= "$ebc25cf6-9120-4283-b972-0e5520d0000B" fullword ascii
		 $a37= "$ebc25cf6-9120-4283-b972-0e5520d0000C" fullword ascii
		 $a38= "$ebc25cf6-9120-4283-b972-0e5520d0000D" fullword ascii
		 $a39= "$ebc25cf6-9120-4283-b972-0e5520d0000E" fullword ascii
		 $a40= "$F48229AF-E28C-42B5-BB92-E114E62BDD54" fullword ascii
		 $a41= "$F935DC1F-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a42= "$F935DC21-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a43= "$F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a44= "$F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a45= "$F935DC24-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a46= "$F935DC25-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a47= "$F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a48= "$F935DC27-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a49= "$F935DC28-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a50= "$F935DC29-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a51= "$F935DC2A-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a52= "$F935DC2B-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a53= "$F935DC2C-1CF0-11D0-ADB9-00C04FD58A0B" fullword ascii
		 $a54= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" fullword ascii
		 $a55= "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" fullword ascii
		 $a56= "3http://crl.microsoft.com/pki/crl/products/CSPCA.crl0H" fullword ascii
		 $a57= "3http://crl.microsoft.com/pki/crl/products/tspca.crl0H" fullword ascii
		 $a58= "{8175e2c1-d077-43b3-8e9b-6232d4603826}" fullword ascii
		 $a59= "{98542371-8c60-497f-90d1-06e7bb84eeb8}" fullword ascii
		 $a60= "AddDirectoryWillTraverseReparsePoints" fullword ascii
		 $a61= "AddWindowsPrinterConnection" fullword ascii
		 $a62= "ArgumentOutOfRangeException" fullword ascii
		 $a63= "AssemblyConfigurationAttribute" fullword ascii
		 $a64= "AssemblyCopyrightAttribute" fullword ascii
		 $a65= "AssemblyDescriptionAttribute" fullword ascii
		 $a66= "AssemblyFileVersionAttribute" fullword ascii
		 $a67= "AssemblyTrademarkAttribute" fullword ascii
		 $a68= "AttributesIndicateDirectory" fullword ascii
		 $a69= "CompilationRelaxationsAttribute" fullword ascii
		 $a70= "CompileAssemblyFromSource" fullword ascii
		 $a71= "CompilerGeneratedAttribute" fullword ascii
		 $a72= "CreateMemberRefsDelegates" fullword ascii
		 $a73= "ddddddddddddddddddddddddddddddd," fullword ascii
		 $a74= "ddddddddddddddddddddddddddddddddddddddddddddddddd367," fullword ascii
		 $a75= "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a76= "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddLgddDddd" fullword ascii
		 $a77= "ddddddddddddddddddddddddzdddEidd*idddmddd:idddddddddd" fullword ascii
		 $a78= "DisableThreadLibraryCalls" fullword ascii
		 $a79= "EmitTimesInUnixFormatWhenSaving" fullword ascii
		 $a80= "EmitTimesInWindowsFormatWhenSaving" fullword ascii
		 $a81= "get_CompletedSynchronously" fullword ascii
		 $a82= "GetFileNameWithoutExtension" fullword ascii
		 $a83= "GetManifestResourceStream" fullword ascii
		 $a84= ",http://www.microsoft.com/pki/certs/CSPCA.crt0" fullword ascii
		 $a85= ",http://www.microsoft.com/pki/certs/tspca.crt0" fullword ascii
		 $a86= "InitializeCriticalSection" fullword ascii
		 $a87= "InitializeSecurityDescriptor" fullword ascii
		 $a88= "InitiateSystemShutdownExW" fullword ascii
		 $a89= "InputStreamWasJitProvided" fullword ascii
		 $a90= "InvalidOperationException" fullword ascii
		 $a91= "IsProcessorFeaturePresent" fullword ascii
		 $a92= "IWshCollection_ClassClass" fullword ascii
		 $a93= "IWshEnvironment_ClassClass" fullword ascii
		 $a94= "IWshRuntimeLibrary.DriveClass" fullword ascii
		 $a95= "IWshRuntimeLibrary.DrivesClass" fullword ascii
		 $a96= "!IWshRuntimeLibrary.DriveTypeConst" fullword ascii
		 $a97= "IWshRuntimeLibrary.FileClass" fullword ascii
		 $a98= "IWshRuntimeLibrary.FilesClass" fullword ascii
		 $a99= "(IWshRuntimeLibrary.FileSystemObjectClass" fullword ascii
		 $a100= "IWshRuntimeLibrary.FolderClass" fullword ascii
		 $a101= "IWshRuntimeLibrary.FoldersClass" fullword ascii
		 $a102= ",IWshRuntimeLibrary.IWshCollection_ClassClass" fullword ascii
		 $a103= "-IWshRuntimeLibrary.IWshEnvironment_ClassClass" fullword ascii
		 $a104= ")IWshRuntimeLibrary.IWshNetwork_ClassClass" fullword ascii
		 $a105= "'IWshRuntimeLibrary.IWshShell_ClassClass" fullword ascii
		 $a106= "*IWshRuntimeLibrary.IWshShortcut_ClassClass" fullword ascii
		 $a107= "-IWshRuntimeLibrary.IWshURLShortcut_ClassClass" fullword ascii
		 $a108= "%IWshRuntimeLibrary.SpecialFolderConst" fullword ascii
		 $a109= "&IWshRuntimeLibrary.StandardStreamTypes" fullword ascii
		 $a110= "%IWshRuntimeLibrary.WshCollectionClass" fullword ascii
		 $a111= "&IWshRuntimeLibrary.WshEnvironmentClass" fullword ascii
		 $a112= "IWshRuntimeLibrary.WshExecClass" fullword ascii
		 $a113= "#IWshRuntimeLibrary.WshShortcutClass" fullword ascii
		 $a114= "&IWshRuntimeLibrary.WshURLShortcutClass" fullword ascii
		 $a115= "IWshURLShortcut_ClassClass" fullword ascii
		 $a116= "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" fullword ascii
		 $a117= "ManagementObjectCollection" fullword ascii
		 $a118= "ManagementObjectEnumerator" fullword ascii
		 $a119= "__MIDL___MIDL_itf_iwshom_0000_0000_0001" fullword ascii
		 $a120= "__MIDL___MIDL_itf_iwshom_0000_0000_0002" fullword ascii
		 $a121= "__MIDL___MIDL_itf_iwshom_0000_0000_0003" fullword ascii
		 $a122= "__MIDL___MIDL_itf_iwshom_0000_0000_0004" fullword ascii
		 $a123= "__MIDL___MIDL_itf_iwshom_0001_0008_0001" fullword ascii
		 $a124= "__MIDL___MIDL_itf_iwshom_0001_0017_0001" fullword ascii
		 $a125= "nddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" fullword ascii
		 $a126= "NeutralResourcesLanguageAttribute" fullword ascii
		 $a127= "NumberOfSegmentsForMostRecentSave" fullword ascii
		 $a128= "ParallelDeflateMaxBufferPairs" fullword ascii
		 $a129= "ProtocolViolationException" fullword ascii
		 $a130= "ProvisionalAlternateEncoding" fullword ascii
		 $a131= "RuntimeCompatibilityAttribute" fullword ascii
		 $a132= "SetCompatibleTextRenderingDefault" fullword ascii
		 $a133= "set_IncludeDebugInformation" fullword ascii
		 $a134= "set_RedirectStandardOutput" fullword ascii
		 $a135= "SetSecurityDescriptorDacl" fullword ascii
		 $a136= "SmartAssembly.HouseOfCards" fullword ascii
		 $a137= "SmartAssembly.MemoryManagement" fullword ascii
		 $a138= "sSsAsCsCsCsSsAsBsJsFsss$s" fullword ascii
		 $a139= "System.Collections.Generic" fullword ascii
		 $a140= "System.Collections.ObjectModel" fullword ascii
		 $a141= "System.Collections.Specialized" fullword ascii
		 $a142= "System.Net.NetworkInformation" fullword ascii
		 $a143= "System.Runtime.CompilerServices" fullword ascii
		 $a144= "System.Runtime.InteropServices" fullword ascii
		 $a145= "System.Runtime.Serialization" fullword ascii
		 $a146= "System.Security.Cryptography" fullword ascii
		 $a147= "System.Security.Permissions" fullword ascii
		 $a148= "System.Text.RegularExpressions" fullword ascii
		 $a149= "UnauthorizedAccessException" fullword ascii
		 $a150= "UnsupportedCompressionMethod" fullword ascii

		 $hex1= {24613130303d202249}
		 $hex2= {24613130313d202249}
		 $hex3= {24613130323d20222c}
		 $hex4= {24613130333d20222d}
		 $hex5= {24613130343d202229}
		 $hex6= {24613130353d202227}
		 $hex7= {24613130363d20222a}
		 $hex8= {24613130373d20222d}
		 $hex9= {24613130383d202225}
		 $hex10= {24613130393d202226}
		 $hex11= {246131303d20222432}
		 $hex12= {24613131303d202225}
		 $hex13= {24613131313d202226}
		 $hex14= {24613131323d202249}
		 $hex15= {24613131333d202223}
		 $hex16= {24613131343d202226}
		 $hex17= {24613131353d202249}
		 $hex18= {24613131363d20224b}
		 $hex19= {24613131373d20224d}
		 $hex20= {24613131383d20224d}
		 $hex21= {24613131393d20225f}
		 $hex22= {246131313d20222433}
		 $hex23= {24613132303d20225f}
		 $hex24= {24613132313d20225f}
		 $hex25= {24613132323d20225f}
		 $hex26= {24613132333d20225f}
		 $hex27= {24613132343d20225f}
		 $hex28= {24613132353d20226e}
		 $hex29= {24613132363d20224e}
		 $hex30= {24613132373d20224e}
		 $hex31= {24613132383d202250}
		 $hex32= {24613132393d202250}
		 $hex33= {246131323d20222434}
		 $hex34= {24613133303d202250}
		 $hex35= {24613133313d202252}
		 $hex36= {24613133323d202253}
		 $hex37= {24613133333d202273}
		 $hex38= {24613133343d202273}
		 $hex39= {24613133353d202253}
		 $hex40= {24613133363d202253}
		 $hex41= {24613133373d202253}
		 $hex42= {24613133383d202273}
		 $hex43= {24613133393d202253}
		 $hex44= {246131333d20222435}
		 $hex45= {24613134303d202253}
		 $hex46= {24613134313d202253}
		 $hex47= {24613134323d202253}
		 $hex48= {24613134333d202253}
		 $hex49= {24613134343d202253}
		 $hex50= {24613134353d202253}
		 $hex51= {24613134363d202253}
		 $hex52= {24613134373d202253}
		 $hex53= {24613134383d202253}
		 $hex54= {24613134393d202255}
		 $hex55= {246131343d20222435}
		 $hex56= {24613135303d202255}
		 $hex57= {246131353d20222437}
		 $hex58= {246131363d20222441}
		 $hex59= {246131373d20222443}
		 $hex60= {246131383d20222443}
		 $hex61= {246131393d20222443}
		 $hex62= {2461313d2022243038}
		 $hex63= {246132303d20222443}
		 $hex64= {246132313d20222443}
		 $hex65= {246132323d20222443}
		 $hex66= {246132333d20222443}
		 $hex67= {246132343d20222443}
		 $hex68= {246132353d20222443}
		 $hex69= {246132363d20222443}
		 $hex70= {246132373d20222443}
		 $hex71= {246132383d20222443}
		 $hex72= {246132393d20222465}
		 $hex73= {2461323d2022243038}
		 $hex74= {246133303d20222465}
		 $hex75= {246133313d20222465}
		 $hex76= {246133323d20222465}
		 $hex77= {246133333d20222465}
		 $hex78= {246133343d20222465}
		 $hex79= {246133353d20222465}
		 $hex80= {246133363d20222465}
		 $hex81= {246133373d20222465}
		 $hex82= {246133383d20222465}
		 $hex83= {246133393d20222465}
		 $hex84= {2461333d2022243039}
		 $hex85= {246134303d20222446}
		 $hex86= {246134313d20222446}
		 $hex87= {246134323d20222446}
		 $hex88= {246134333d20222446}
		 $hex89= {246134343d20222446}
		 $hex90= {246134353d20222446}
		 $hex91= {246134363d20222446}
		 $hex92= {246134373d20222446}
		 $hex93= {246134383d20222446}
		 $hex94= {246134393d20222446}
		 $hex95= {2461343d2022243041}
		 $hex96= {246135303d20222446}
		 $hex97= {246135313d20222446}
		 $hex98= {246135323d20222446}
		 $hex99= {246135333d20222446}
		 $hex100= {246135343d20223132}
		 $hex101= {246135353d2022314d}
		 $hex102= {246135363d20223368}
		 $hex103= {246135373d20223368}
		 $hex104= {246135383d20227b38}
		 $hex105= {246135393d20227b39}
		 $hex106= {2461353d2022243042}
		 $hex107= {246136303d20224164}
		 $hex108= {246136313d20224164}
		 $hex109= {246136323d20224172}
		 $hex110= {246136333d20224173}
		 $hex111= {246136343d20224173}
		 $hex112= {246136353d20224173}
		 $hex113= {246136363d20224173}
		 $hex114= {246136373d20224173}
		 $hex115= {246136383d20224174}
		 $hex116= {246136393d2022436f}
		 $hex117= {2461363d2022243044}
		 $hex118= {246137303d2022436f}
		 $hex119= {246137313d2022436f}
		 $hex120= {246137323d20224372}
		 $hex121= {246137333d20226464}
		 $hex122= {246137343d20226464}
		 $hex123= {246137353d20226464}
		 $hex124= {246137363d20226464}
		 $hex125= {246137373d20226464}
		 $hex126= {246137383d20224469}
		 $hex127= {246137393d2022456d}
		 $hex128= {2461373d2022243234}
		 $hex129= {246138303d2022456d}
		 $hex130= {246138313d20226765}
		 $hex131= {246138323d20224765}
		 $hex132= {246138333d20224765}
		 $hex133= {246138343d20222c68}
		 $hex134= {246138353d20222c68}
		 $hex135= {246138363d2022496e}
		 $hex136= {246138373d2022496e}
		 $hex137= {246138383d2022496e}
		 $hex138= {246138393d2022496e}
		 $hex139= {2461383d2022243234}
		 $hex140= {246139303d2022496e}
		 $hex141= {246139313d20224973}
		 $hex142= {246139323d20224957}
		 $hex143= {246139333d20224957}
		 $hex144= {246139343d20224957}
		 $hex145= {246139353d20224957}
		 $hex146= {246139363d20222149}
		 $hex147= {246139373d20224957}
		 $hex148= {246139383d20224957}
		 $hex149= {246139393d20222849}
		 $hex150= {2461393d2022243241}
		 $hex151= {247331303d20226174}
		 $hex152= {247331313d20227b63}
		 $hex153= {247331323d20226465}
		 $hex154= {247331333d20226532}
		 $hex155= {247331343d20224669}
		 $hex156= {247331353d2022682e}
		 $hex157= {247331363d20224966}
		 $hex158= {247331373d20224c65}
		 $hex159= {247331383d20226c4b}
		 $hex160= {247331393d20224d69}
		 $hex161= {2473313d2022314d7a}
		 $hex162= {247332303d20224d49}
		 $hex163= {247332313d20224e6a}
		 $hex164= {247332323d20224f6f}
		 $hex165= {247332333d20224f72}
		 $hex166= {247332343d20226f75}
		 $hex167= {247332353d2022506c}
		 $hex168= {247332363d20222c20}
		 $hex169= {247332373d20225075}
		 $hex170= {247332383d20225365}
		 $hex171= {247332393d20225365}
		 $hex172= {2473323d2022312e20}
		 $hex173= {247333303d20227368}
		 $hex174= {247333313d20222c53}
		 $hex175= {247333323d20227468}
		 $hex176= {247333333d20225449}
		 $hex177= {247333343d20227545}
		 $hex178= {247333353d20227525}
		 $hex179= {247333363d20227662}
		 $hex180= {247333373d20225653}
		 $hex181= {247333383d20225765}
		 $hex182= {247333393d20227765}
		 $hex183= {2473333d2022322e20}
		 $hex184= {247334303d2022776f}
		 $hex185= {247334313d20225772}
		 $hex186= {247334323d20222577}
		 $hex187= {247334333d2022796f}
		 $hex188= {247334343d2022596f}
		 $hex189= {2473343d20222e3364}
		 $hex190= {2473353d20227b3731}
		 $hex191= {2473363d20227b3831}
		 $hex192= {2473373d2022394571}
		 $hex193= {2473383d2022416c6c}
		 $hex194= {2473393d2022417373}

	condition:
		24 of them
}
