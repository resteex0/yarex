
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
		 date = "2022-01-22_17-55-50" 
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

		 $hex1= {246131303d20226e65}
		 $hex2= {246131313d20224e4f}
		 $hex3= {246131323d20225072}
		 $hex4= {246131333d20227376}
		 $hex5= {246131343d20227479}
		 $hex6= {246131353d20227479}
		 $hex7= {246131363d20227665}
		 $hex8= {246131373d20227665}
		 $hex9= {246131383d20227665}
		 $hex10= {246131393d20227665}
		 $hex11= {2461313d2022303839}
		 $hex12= {246132303d20227665}
		 $hex13= {246132313d20227665}
		 $hex14= {246132323d20227665}
		 $hex15= {246132333d20227665}
		 $hex16= {246132343d20227665}
		 $hex17= {246132353d20227665}
		 $hex18= {246132363d20227665}
		 $hex19= {246132373d20227665}
		 $hex20= {246132383d20227665}
		 $hex21= {246132393d20227665}
		 $hex22= {2461323d20227b2530}
		 $hex23= {246133303d20227665}
		 $hex24= {246133313d20227665}
		 $hex25= {246133323d20227665}
		 $hex26= {246133333d20225850}
		 $hex27= {246133343d20227a68}
		 $hex28= {2461333d20225e422a}
		 $hex29= {2461343d2022633a2f}
		 $hex30= {2461353d2022633a2f}
		 $hex31= {2461363d2022633a2f}
		 $hex32= {2461373d2022633a2f}
		 $hex33= {2461383d2022633a2f}
		 $hex34= {2461393d2022467265}
		 $hex35= {247331303d20226170}
		 $hex36= {247331313d20226170}
		 $hex37= {247331323d20226170}
		 $hex38= {247331333d20226170}
		 $hex39= {247331343d20226170}
		 $hex40= {247331353d20226170}
		 $hex41= {247331363d20226170}
		 $hex42= {247331373d20226170}
		 $hex43= {247331383d20226170}
		 $hex44= {247331393d20226170}
		 $hex45= {2473313d2022253032}
		 $hex46= {247332303d20226170}
		 $hex47= {247332313d20226170}
		 $hex48= {247332323d20226170}
		 $hex49= {247332333d20224153}
		 $hex50= {247332343d20224153}
		 $hex51= {247332353d20224241}
		 $hex52= {247332363d20224341}
		 $hex53= {247332373d2022433a}
		 $hex54= {247332383d2022433a}
		 $hex55= {247332393d20224375}
		 $hex56= {2473323d20227c2a7c}
		 $hex57= {247333303d2022433a}
		 $hex58= {247333313d2022433a}
		 $hex59= {247333323d20224359}
		 $hex60= {247333333d20224465}
		 $hex61= {247333343d20224465}
		 $hex62= {247333353d20224465}
		 $hex63= {247333363d20224465}
		 $hex64= {247333373d20226469}
		 $hex65= {247333383d2022446f}
		 $hex66= {247333393d2022446f}
		 $hex67= {2473333d2022212325}
		 $hex68= {247334303d20224472}
		 $hex69= {247334313d20227b45}
		 $hex70= {247334323d2022456d}
		 $hex71= {247334333d2022454d}
		 $hex72= {247334343d20226578}
		 $hex73= {247334353d20226578}
		 $hex74= {247334363d20226578}
		 $hex75= {247334373d20225f47}
		 $hex76= {247334383d20224861}
		 $hex77= {247334393d20226865}
		 $hex78= {2473343d2022253464}
		 $hex79= {247335303d20226869}
		 $hex80= {247335313d20222f48}
		 $hex81= {247335323d20224945}
		 $hex82= {247335333d2022696e}
		 $hex83= {247335343d20224b44}
		 $hex84= {247335353d20224b69}
		 $hex85= {247335363d20224c69}
		 $hex86= {247335373d20224c53}
		 $hex87= {247335383d20226d61}
		 $hex88= {247335393d20224d61}
		 $hex89= {2473353d2022352e32}
		 $hex90= {247336303d20226d73}
		 $hex91= {247336313d20226d73}
		 $hex92= {247336323d20224d59}
		 $hex93= {247336333d20226e65}
		 $hex94= {247336343d20224e65}
		 $hex95= {247336353d20226e4b}
		 $hex96= {247336363d20224e6f}
		 $hex97= {247336373d20226e56}
		 $hex98= {247336383d20222826}
		 $hex99= {247336393d20222826}
		 $hex100= {2473363d2022352e32}
		 $hex101= {247337303d20225061}
		 $hex102= {247337313d20223f3f}
		 $hex103= {247337323d2022506c}
		 $hex104= {247337333d20224070}
		 $hex105= {247337343d20227072}
		 $hex106= {247337353d20225345}
		 $hex107= {247337363d20225365}
		 $hex108= {247337373d20222e2e}
		 $hex109= {247337383d20222573}
		 $hex110= {247337393d2022736f}
		 $hex111= {2473373d20222f613e}
		 $hex112= {247338303d2022534f}
		 $hex113= {247338313d20227370}
		 $hex114= {247338323d20227379}
		 $hex115= {247338333d20225453}
		 $hex116= {247338343d20225453}
		 $hex117= {247338353d20225454}
		 $hex118= {247338363d20222955}
		 $hex119= {247338373d20225553}
		 $hex120= {247338383d20227769}
		 $hex121= {247338393d2022576f}
		 $hex122= {2473383d2022617069}
		 $hex123= {247339303d20222577}
		 $hex124= {247339313d20227777}
		 $hex125= {247339323d20222f25}
		 $hex126= {247339333d2022582d}
		 $hex127= {2473393d2022617069}

	condition:
		84 of them
}
