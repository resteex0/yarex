
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_EnergeticBear 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_EnergeticBear {
	meta: 
		 description= "APT_Sample_EnergeticBear Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_12-20-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "122543722bbbeb4cec9ee977157a59da"
		 hash2= "f7c5d117c91bd22fa17d2d5444ff7ab7"
		 hash3= "f901c645188f9c80afa8f49174f065ce"

	strings:

	
 		 $s1= "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" fullword wide
		 $s2= "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" fullword wide
		 $s3= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $s4= "%4d/%02d/%02d %02d:%02d:%02d\\WinRAR\\~temp.dat" fullword wide
		 $s5= "5.2.3790.0 (srv03_rtm.030324-2048)usbclass" fullword wide
		 $s6= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
		 $s7= "/a>" fullword wide
		 $s8= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s9= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s10= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s11= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s12= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s13= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s14= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s15= "api-ms-win-core-registry-l1-1-0.dll" fullword wide
		 $s16= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s17= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s18= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s19= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s20= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s21= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s22= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s23= "ASijnoKGszdpodPPiaoaghj8127391" fullword wide
		 $s24= "ASPACK.EXECLOSEDFOLDERASPack compressor" fullword wide
		 $s25= "BATScriptingFBqINhRdpgnqATxJ.htmlmagic_key" fullword wide
		 $s26= "CAPESPN.DLLWINF.DLLNCFG.DLLmsgrthlp.dll" fullword wide
		 $s27= "C:\\ddd\\wer2.txt\\Microsoft\\Windows	mp43hh11.txt" fullword wide
		 $s28= "C:\\ProgramData\\stat2.dat" fullword wide
		 $s29= "CurrentControlSet\\Control\\Keyboard Layouts\\" fullword wide
		 $s30= "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		 $s31= "C:\\Windows\\Temp\\Down.txt" fullword wide
		 $s32= "CYBERGATEFULLSERVERCYBERGATEBINDERSETTINGSPASSCYBERGATEPASS" fullword wide
		 $s33= "\\Device\\IDTProt\\??\\slIDTProt" fullword wide
		 $s34= "\\Device\\KProcessHacker2" fullword wide
		 $s35= "\\Device\\StreamPortal\\Device\\PNTFILTER" fullword wide
		 $s36= "\\Device\\XScanPF\\DosDevices\\XScanPF" fullword wide
		 $s37= "dickcursor.cur{0}|{1}|{2}" fullword wide
		 $s38= "\\DosDevices\\port_optimizer" fullword wide
		 $s39= "\\DosDevices\\%ws\\Device\\%ws_%ws" fullword wide
		 $s40= "\\Drivers\\usbmgr.tmp\\Drivers\\usbmgr.sys" fullword wide
		 $s41= "{E190BC79-02DC-0166-4CF1-BD8F8CB2FF21}" fullword wide
		 $s42= "Email: blacksplitn@gmail.com" fullword wide
		 $s43= "EMAIL:haoq@neusoft.comQQ2000b.exe" fullword wide
		 $s44= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s45= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s46= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s47= "_Gt_Remote_%sBurn\\workdll.tmp" fullword wide
		 $s48= "HarvesterSocksBot.Properties.Resources" fullword wide
		 $s49= "helpldr.dllswma.dlliomus.dllatiml.dllhlpuctf.dll" fullword wide
		 $s50= "hikit>Global\\%s__SHOW__Global\\%s__HIDE__Global\\%s__STOP__" fullword wide
		 $s51= "/Home/SaveFile?commandId=CmdResult=" fullword wide
		 $s52= "IEXT2_IDC_HORZLINEMOVECURSORmsctls_progress32" fullword wide
		 $s53= "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
		 $s54= "KDSTORAGEKDSTORAGE_64KDRUNDRV32KDRAR" fullword wide
		 $s55= "KilsSheASheDSheCFolsFilsDein" fullword wide
		 $s56= "\\Librariesireeye.vbs&" fullword wide
		 $s57= "LScanPort.EXEwww.honker8.com" fullword wide
		 $s58= "mailto:Mohammed.sarah@gratner.commailto:Tarik.Imam@gartner.com" fullword wide
		 $s59= "MaximumPortsServicedConnectMultiplePorts" fullword wide
		 $s60= "msacm32.drvC:\\Windowsxplorer.exe" fullword wide
		 $s61= "msisvc_32@PROP=-EmbeddingS:(ML;;NW;;;LW)" fullword wide
		 $s62= "MYINPUTCONFIGQLinkEVENTSITETYPEMOD" fullword wide
		 $s63= "netsh.exeroutemon.exescript=disconnect" fullword wide
		 $s64= "NextSecurity.NETSwitchSniffer Setup" fullword wide
		 $s65= "nKERNEL32.DLL@ReturnValue" fullword wide
		 $s66= "Not supported.SystemDefaultEUDCFont" fullword wide
		 $s67= "nView_DiskLoydbnView_KeyLoydbnView_skinsUsbLoydb%sBurn%ssoul" fullword wide
		 $s68= "(&(objectCategory=person)(objectClass=user)(cn=Schedule" fullword wide
		 $s69= "(&(objectClass=user)(objectCategory=person)" fullword wide
		 $s70= "Paramore756Contex43Zw_&one@ldrContext43" fullword wide
		 $s71= "\\??\\pipe1_stdin\\??\\pipe1_stdout" fullword wide
		 $s72= "PluginDeflater.exe.Deflated" fullword wide
		 $s73= "@prkMtxSTATICwindirWinStaObj" fullword wide
		 $s74= "program=bot&country=&name=&opsys=&version=&hwid=" fullword wide
		 $s75= "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
		 $s76= "SeTcbPrivilegewinsta0\\default" fullword wide
		 $s77= "..\\..\\SharedSourceCpp\\MHook\\disasm_x86.cpp" fullword wide
		 $s78= "%s?i=%s&m=%s&f=%d&d=%S%s?i=%s&m=u&f=0&d=%d" fullword wide
		 $s79= "software\\microsoft\\internet explorer	ypedurls" fullword wide
		 $s80= "SOFTWAREWow6432NodeMicrosoftVisualStudio14.0SetupVC" fullword wide
		 $s81= "spanish-dominican republic" fullword wide
		 $s82= "\\sysprep\\sysprep.exe\\sysprep\\CRYPTBASE.dll" fullword wide
		 $s83= "TSETPASSWORDFORMTGETNTUSERNAMEFORMTPORTFORM" fullword wide
		 $s84= "TSNIFFERFRMTCRACKSETFRMTCRACKFRM" fullword wide
		 $s85= "TTFTPSERVERFRMTPORTSCANSETFRMTIISSHELLFRMTADVSCANSETFRM" fullword wide
		 $s86= ")U71UDAU_QU_YU_aU_iU_qU_yU_" fullword wide
		 $s87= "USER_PRIV_GUESTUSER_PRIV_ADMINUSER_PRIV_USER" fullword wide
		 $s88= "winrarsfxmappingfile.tmpGETPASSWORD1" fullword wide
		 $s89= "Wole32.dllSystem32\\migwizSystem32\\migwiz\\CRYPTBASE.dll" fullword wide
		 $s90= "%ws%03d%ws%wZTCP/IP driver" fullword wide
		 $s91= "www.gxgl.com&www.gxgl.net" fullword wide
		 $s92= "/%x/archive/%02d%02d%02d%02d.html" fullword wide
		 $s93= "X-HTTP-Attempts@CommandLineModeX-Retry-After" fullword wide
		 $a1= "089ParadoxRATStartRMCamFloodersSlowLarisSHITEMIDset_Remote_ChatM" fullword ascii
		 $a2= "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}WUServiceMainC" fullword ascii
		 $a3= "^B*stype=info&data=?mmid=&status=run succeed_KB10B2D1_CIlFD2C" fullword ascii
		 $a4= "c:/go/src/internal/syscall/windows/registry/zsyscall_windows.go" fullword ascii
		 $a5= "c:/go/src/vendor/golang_org/x/crypto/curve25519/curve25519.go" fullword ascii
		 $a6= "c:/go/src/vendor/golang_org/x/text/unicode/norm/composition.go" fullword ascii
		 $a7= "c:/go/src/vendor/golang_org/x/text/unicode/norm/normalize.go" fullword ascii
		 $a8= "c:/go/src/vendor/golang_org/x/text/unicode/norm/transform.go" fullword ascii
		 $a9= "FreeConsoleProcess WriteParameterFilesSTOCKMASTERInsertEmailFax" fullword ascii
		 $a10= "net/http.(*Transport).(net/http.onceSetNextProtoDefaults)-fm" fullword ascii
		 $a11= "NOKIAN95/WEBERSvmpaIaiMjnagpkvERVaikpaPlvae`ERGkiiej`GkjpvkhhavX" fullword ascii
		 $a12= "Projects\\NadzorModulesNadzor\\Nadzor_sln[injectPE] svcName=%s[" fullword ascii
		 $a13= "svrg.pdbW32pServiceTableIn formaReleaseFastMutexR0omp4arH.text" fullword ascii
		 $a14= "type..eq.[61]vendor/golang_org/x/net/http2/hpack.HeaderField" fullword ascii
		 $a15= "type..hash.[61]vendor/golang_org/x/net/http2/hpack.HeaderField" fullword ascii
		 $a16= "vendor/golang_org/x/net/http2/hpack.constantTimeStringCompare" fullword ascii
		 $a17= "vendor/golang_org/x/net/http2/hpack.(*Decoder).parseFieldIndexed" fullword ascii
		 $a18= "vendor/golang_org/x/net/http2/hpack.(*Decoder).parseFieldLiteral" fullword ascii
		 $a19= "vendor/golang_org/x/net/http2/hpack.(*dynamicTable).setMaxSize" fullword ascii
		 $a20= "vendor/golang_org/x/net/http2/hpack.(*InvalidIndexError).Error" fullword ascii
		 $a21= "vendor/golang_org/x/net/lex/httplex.headerValueContainsToken" fullword ascii
		 $a22= "vendor/golang_org/x/net/lex/httplex.HeaderValuesContainsToken" fullword ascii
		 $a23= "vendor/golang_org/x/text/unicode/norm.(*nfcTrie).lookupString" fullword ascii
		 $a24= "vendor/golang_org/x/text/unicode/norm.(*nfcTrie).lookupValue" fullword ascii
		 $a25= "vendor/golang_org/x/text/unicode/norm.(*nfkcTrie).lookupString" fullword ascii
		 $a26= "vendor/golang_org/x/text/unicode/norm.(*nfkcTrie).lookupValue" fullword ascii
		 $a27= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).compose" fullword ascii
		 $a28= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).doFlush" fullword ascii
		 $a29= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).flushCopy" fullword ascii
		 $a30= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).insertCGJ" fullword ascii
		 $a31= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).runeAt" fullword ascii
		 $a32= "vendor/golang_org/x/text/unicode/norm.(*sparseBlocks).lookup" fullword ascii
		 $a33= "XPPPYZIQD[L-f6-g41GDSXu'@,~P^P_O,!(GU(GZ(Gnu5-NETSEND_V1.00_JRT=" fullword ascii
		 $a34= "zhLookUp.PropertiesMimikatzRunnerzhmimikatzZh0uSh311your target" fullword ascii

		 $hex1= {21232527292b2d2f31}
		 $hex2= {253032642e25303264}
		 $hex3= {2534642f253032642f}
		 $hex4= {25733f693d2573266d}
		 $hex5= {257773253033642577}
		 $hex6= {2826286f626a656374}
		 $hex7= {29553731554441555f}
		 $hex8= {2e2e2e2e5368617265}
		 $hex9= {2f25782f6172636869}
		 $hex10= {2f486f6d652f536176}
		 $hex11= {30383950617261646f}
		 $hex12= {352e322e333739302e}
		 $hex13= {3f3f7069706514315f}
		 $hex14= {4070726b4d74785354}
		 $hex15= {41535041434b2e4558}
		 $hex16= {4153696a6e6f4b4773}
		 $hex17= {424154536372697074}
		 $hex18= {433a50726f6772616d}
		 $hex19= {433a57696e646f7773}
		 $hex20= {433a64646477657232}
		 $hex21= {4341504553504e2e44}
		 $hex22= {435942455247415445}
		 $hex23= {43757272656e74436f}
		 $hex24= {446576696365494454}
		 $hex25= {4465766963654b5072}
		 $hex26= {446576696365537472}
		 $hex27= {446576696365585363}
		 $hex28= {446f73446576696365}
		 $hex29= {447269766572737573}
		 $hex30= {454d41494c3a68616f}
		 $hex31= {456d61696c3a20626c}
		 $hex32= {46726565436f6e736f}
		 $hex33= {486172766573746572}
		 $hex34= {49455854325f494443}
		 $hex35= {4b4453544f52414745}
		 $hex36= {4b696c735368654153}
		 $hex37= {4c5363616e506f7274}
		 $hex38= {4c6962726172696573}
		 $hex39= {4d59494e505554434f}
		 $hex40= {4d6178696d756d506f}
		 $hex41= {4e4f4b49414e39352f}
		 $hex42= {4e6578745365637572}
		 $hex43= {4e6f7420737570706f}
		 $hex44= {506172616d6f726537}
		 $hex45= {506c7567696e446566}
		 $hex46= {50726f6a656374734e}
		 $hex47= {53454c45435420554e}
		 $hex48= {534f46545741524557}
		 $hex49= {536554636250726976}
		 $hex50= {545345545041535357}
		 $hex51= {54534e494646455246}
		 $hex52= {545446545053455256}
		 $hex53= {555345525f50524956}
		 $hex54= {576f6c6533322e646c}
		 $hex55= {582d485454502d4174}
		 $hex56= {58505050595a495144}
		 $hex57= {5e422a73747970653d}
		 $hex58= {5f47745f52656d6f74}
		 $hex59= {6170692d6d732d7769}
		 $hex60= {633a2f676f2f737263}
		 $hex61= {6469636b637572736f}
		 $hex62= {6578742d6d732d7769}
		 $hex63= {68656c706c64722e64}
		 $hex64= {68696b69743e476c6f}
		 $hex65= {696e6465782e706870}
		 $hex66= {6d61696c746f3a4d6f}
		 $hex67= {6d7361636d33322e64}
		 $hex68= {6d73697376635f3332}
		 $hex69= {6e4b45524e454c3332}
		 $hex70= {6e566965775f446973}
		 $hex71= {6e65742f687474702e}
		 $hex72= {6e657473682e657865}
		 $hex73= {70726f6772616d3d62}
		 $hex74= {736f6674776172656d}
		 $hex75= {7370616e6973682d64}
		 $hex76= {737672672e70646257}
		 $hex77= {737973707265707379}
		 $hex78= {747970652e2e65712e}
		 $hex79= {747970652e2e686173}
		 $hex80= {76656e646f722f676f}
		 $hex81= {77696e726172736678}
		 $hex82= {7777772e6778676c2e}
		 $hex83= {7a684c6f6f6b55702e}
		 $hex84= {7b253038582d253034}
		 $hex85= {7b4531393042433739}
		 $hex86= {7c2a7c313233785878}

	condition:
		21 of them
}
