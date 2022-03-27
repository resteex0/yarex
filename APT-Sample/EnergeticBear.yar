
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
		 date = "2022-03-27_08-12-50" 
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

		 $hex1= {21??23??25??27??29??2b??2d??2f??31??33??21??23??25??27??29??2b??2d??2f??31??33??21??23??25??27??29??2b??2d??2f??31??33??}
		 $hex2= {25??30??32??64??2e??25??30??32??64??2e??25??30??32??64??5f??25??30??32??64??2e??25??30??32??64??2e??25??30??32??64??2e??}
		 $hex3= {25??34??64??2f??25??30??32??64??2f??25??30??32??64??20??25??30??32??64??3a??25??30??32??64??3a??25??30??32??64??57??69??}
		 $hex4= {25??73??3f??69??3d??25??73??26??6d??3d??25??73??26??66??3d??25??64??26??64??3d??25??53??25??73??3f??69??3d??25??73??26??}
		 $hex5= {25??77??73??25??30??33??64??25??77??73??25??77??5a??54??43??50??2f??49??50??20??64??72??69??76??65??72??0a??}
		 $hex6= {28??26??28??6f??62??6a??65??63??74??43??61??74??65??67??6f??72??79??3d??70??65??72??73??6f??6e??29??28??6f??62??6a??65??}
		 $hex7= {28??26??28??6f??62??6a??65??63??74??43??6c??61??73??73??3d??75??73??65??72??29??28??6f??62??6a??65??63??74??43??61??74??}
		 $hex8= {29??55??37??31??55??44??41??55??5f??51??55??5f??59??55??5f??61??55??5f??69??55??5f??71??55??5f??79??55??5f??0a??}
		 $hex9= {2e??2e??2e??2e??53??68??61??72??65??64??53??6f??75??72??63??65??43??70??70??4d??48??6f??6f??6b??64??69??73??61??73??6d??}
		 $hex10= {2f??25??78??2f??61??72??63??68??69??76??65??2f??25??30??32??64??25??30??32??64??25??30??32??64??25??30??32??64??2e??68??}
		 $hex11= {2f??48??6f??6d??65??2f??53??61??76??65??46??69??6c??65??3f??63??6f??6d??6d??61??6e??64??49??64??3d??43??6d??64??52??65??}
		 $hex12= {2f??61??3e??0a??}
		 $hex13= {30??38??39??50??61??72??61??64??6f??78??52??41??54??53??74??61??72??74??52??4d??43??61??6d??46??6c??6f??6f??64??65??72??}
		 $hex14= {35??2e??32??2e??33??37??39??30??2e??30??20??28??73??72??76??30??33??5f??72??74??6d??2e??30??33??30??33??32??34??2d??32??}
		 $hex15= {35??2e??32??2e??33??37??39??30??2e??32??32??30??20??28??73??72??76??30??33??5f??67??64??72??2e??30??34??30??39??31??38??}
		 $hex16= {3f??3f??70??69??70??65??14??31??5f??73??74??64??69??6e??3f??3f??70??69??70??65??14??31??5f??73??74??64??6f??75??74??0a??}
		 $hex17= {40??70??72??6b??4d??74??78??53??54??41??54??49??43??77??69??6e??64??69??72??57??69??6e??53??74??61??4f??62??6a??0a??}
		 $hex18= {41??53??50??41??43??4b??2e??45??58??45??43??4c??4f??53??45??44??46??4f??4c??44??45??52??41??53??50??61??63??6b??20??63??}
		 $hex19= {41??53??69??6a??6e??6f??4b??47??73??7a??64??70??6f??64??50??50??69??61??6f??61??67??68??6a??38??31??32??37??33??39??31??}
		 $hex20= {42??41??54??53??63??72??69??70??74??69??6e??67??46??42??71??49??4e??68??52??64??70??67??6e??71??41??54??78??4a??2e??68??}
		 $hex21= {43??3a??50??72??6f??67??72??61??6d??44??61??74??61??73??74??61??74??32??2e??64??61??74??0a??}
		 $hex22= {43??3a??57??69??6e??64??6f??77??73??54??65??6d??70??44??6f??77??6e??2e??74??78??74??0a??}
		 $hex23= {43??3a??64??64??64??77??65??72??32??2e??74??78??74??4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??20??}
		 $hex24= {43??41??50??45??53??50??4e??2e??44??4c??4c??57??49??4e??46??2e??44??4c??4c??4e??43??46??47??2e??44??4c??4c??6d??73??67??}
		 $hex25= {43??59??42??45??52??47??41??54??45??46??55??4c??4c??53??45??52??56??45??52??43??59??42??45??52??47??41??54??45??42??49??}
		 $hex26= {43??75??72??72??65??6e??74??43??6f??6e??74??72??6f??6c??53??65??74??43??6f??6e??74??72??6f??6c??4b??65??79??62??6f??61??}
		 $hex27= {44??65??76??69??63??65??49??44??54??50??72??6f??74??3f??3f??73??6c??49??44??54??50??72??6f??74??0a??}
		 $hex28= {44??65??76??69??63??65??4b??50??72??6f??63??65??73??73??48??61??63??6b??65??72??32??0a??}
		 $hex29= {44??65??76??69??63??65??53??74??72??65??61??6d??50??6f??72??74??61??6c??44??65??76??69??63??65??50??4e??54??46??49??4c??}
		 $hex30= {44??65??76??69??63??65??58??53??63??61??6e??50??46??44??6f??73??44??65??76??69??63??65??73??58??53??63??61??6e??50??46??}
		 $hex31= {44??6f??73??44??65??76??69??63??65??73??25??77??73??44??65??76??69??63??65??25??77??73??5f??25??77??73??0a??}
		 $hex32= {44??6f??73??44??65??76??69??63??65??73??70??6f??72??74??5f??6f??70??74??69??6d??69??7a??65??72??0a??}
		 $hex33= {44??72??69??76??65??72??73??75??73??62??6d??67??72??2e??74??6d??70??44??72??69??76??65??72??73??75??73??62??6d??67??72??}
		 $hex34= {45??4d??41??49??4c??3a??68??61??6f??71??40??6e??65??75??73??6f??66??74??2e??63??6f??6d??51??51??32??30??30??30??62??2e??}
		 $hex35= {45??6d??61??69??6c??3a??20??62??6c??61??63??6b??73??70??6c??69??74??6e??40??67??6d??61??69??6c??2e??63??6f??6d??0a??}
		 $hex36= {46??72??65??65??43??6f??6e??73??6f??6c??65??50??72??6f??63??65??73??73??20??57??72??69??74??65??50??61??72??61??6d??65??}
		 $hex37= {48??61??72??76??65??73??74??65??72??53??6f??63??6b??73??42??6f??74??2e??50??72??6f??70??65??72??74??69??65??73??2e??52??}
		 $hex38= {49??45??58??54??32??5f??49??44??43??5f??48??4f??52??5a??4c??49??4e??45??4d??4f??56??45??43??55??52??53??4f??52??6d??73??}
		 $hex39= {4b??44??53??54??4f??52??41??47??45??4b??44??53??54??4f??52??41??47??45??5f??36??34??4b??44??52??55??4e??44??52??56??33??}
		 $hex40= {4b??69??6c??73??53??68??65??41??53??68??65??44??53??68??65??43??46??6f??6c??73??46??69??6c??73??44??65??69??6e??0a??}
		 $hex41= {4c??53??63??61??6e??50??6f??72??74??2e??45??58??45??77??77??77??2e??68??6f??6e??6b??65??72??38??2e??63??6f??6d??0a??}
		 $hex42= {4c??69??62??72??61??72??69??65??73??0c??69??72??65??65??79??65??2e??76??62??73??26??0a??}
		 $hex43= {4d??59??49??4e??50??55??54??43??4f??4e??46??49??47??51??4c??69??6e??6b??45??56??45??4e??54??53??49??54??45??54??59??50??}
		 $hex44= {4d??61??78??69??6d??75??6d??50??6f??72??74??73??53??65??72??76??69??63??65??64??43??6f??6e??6e??65??63??74??4d??75??6c??}
		 $hex45= {4e??4f??4b??49??41??4e??39??35??2f??57??45??42??45??52??53??76??6d??70??61??49??61??69??4d??6a??6e??61??67??70??6b??76??}
		 $hex46= {4e??65??78??74??53??65??63??75??72??69??74??79??2e??4e??45??54??53??77??69??74??63??68??53??6e??69??66??66??65??72??20??}
		 $hex47= {4e??6f??74??20??73??75??70??70??6f??72??74??65??64??2e??53??79??73??74??65??6d??44??65??66??61??75??6c??74??45??55??44??}
		 $hex48= {50??61??72??61??6d??6f??72??65??37??35??36??43??6f??6e??74??65??78??34??33??5a??77??5f??26??6f??6e??65??40??6c??64??72??}
		 $hex49= {50??6c??75??67??69??6e??44??65??66??6c??61??74??65??72??2e??65??78??65??2e??44??65??66??6c??61??74??65??64??0a??}
		 $hex50= {50??72??6f??6a??65??63??74??73??4e??61??64??7a??6f??72??4d??6f??64??75??6c??65??73??4e??61??64??7a??6f??72??4e??61??64??}
		 $hex51= {53??45??4c??45??43??54??20??55??4e??49??43??4f??44??45??28??53??55??42??53??54??52??49??4e??47??28??28??73??79??73??74??}
		 $hex52= {53??4f??46??54??57??41??52??45??57??6f??77??36??34??33??32??4e??6f??64??65??4d??69??63??72??6f??73??6f??66??74??56??69??}
		 $hex53= {53??65??54??63??62??50??72??69??76??69??6c??65??67??65??77??69??6e??73??74??61??30??64??65??66??61??75??6c??74??0a??}
		 $hex54= {54??53??45??54??50??41??53??53??57??4f??52??44??46??4f??52??4d??54??47??45??54??4e??54??55??53??45??52??4e??41??4d??45??}
		 $hex55= {54??53??4e??49??46??46??45??52??46??52??4d??54??43??52??41??43??4b??53??45??54??46??52??4d??54??43??52??41??43??4b??46??}
		 $hex56= {54??54??46??54??50??53??45??52??56??45??52??46??52??4d??54??50??4f??52??54??53??43??41??4e??53??45??54??46??52??4d??54??}
		 $hex57= {55??53??45??52??5f??50??52??49??56??5f??47??55??45??53??54??55??53??45??52??5f??50??52??49??56??5f??41??44??4d??49??4e??}
		 $hex58= {57??6f??6c??65??33??32??2e??64??6c??6c??53??79??73??74??65??6d??33??32??6d??69??67??77??69??7a??53??79??73??74??65??6d??}
		 $hex59= {58??2d??48??54??54??50??2d??41??74??74??65??6d??70??74??73??40??43??6f??6d??6d??61??6e??64??4c??69??6e??65??4d??6f??64??}
		 $hex60= {58??50??50??50??59??5a??49??51??44??5b??4c??2d??66??36??2d??67??34??31??47??44??53??58??75??27??40??2c??7e??50??5e??50??}
		 $hex61= {5e??42??2a??73??74??79??70??65??3d??69??6e??66??6f??26??64??61??74??61??3d??3f??6d??6d??69??64??3d??26??73??74??61??74??}
		 $hex62= {5f??47??74??5f??52??65??6d??6f??74??65??5f??25??73??42??75??72??6e??77??6f??72??6b??64??6c??6c??2e??74??6d??70??0a??}
		 $hex63= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex64= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex65= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex66= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex67= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??6c??6f??63??61??6c??69??7a??61??74??69??6f??6e??2d??6c??}
		 $hex68= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??6c??6f??63??61??6c??69??7a??61??74??69??6f??6e??2d??6f??}
		 $hex69= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??70??72??6f??63??65??73??73??74??68??72??65??61??64??73??}
		 $hex70= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??72??65??67??69??73??74??72??79??2d??6c??31??2d??31??2d??}
		 $hex71= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex72= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex73= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex74= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex75= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex76= {61??70??69??2d??6d??73??2d??77??69??6e??2d??72??74??63??6f??72??65??2d??6e??74??75??73??65??72??2d??77??69??6e??64??6f??}
		 $hex77= {61??70??69??2d??6d??73??2d??77??69??6e??2d??73??65??63??75??72??69??74??79??2d??73??79??73??74??65??6d??66??75??6e??63??}
		 $hex78= {63??3a??2f??67??6f??2f??73??72??63??2f??69??6e??74??65??72??6e??61??6c??2f??73??79??73??63??61??6c??6c??2f??77??69??6e??}
		 $hex79= {63??3a??2f??67??6f??2f??73??72??63??2f??76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??72??67??2f??78??2f??}
		 $hex80= {64??69??63??6b??63??75??72??73??6f??72??2e??63??75??72??7b??30??7d??7c??7b??31??7d??7c??7b??32??7d??0a??}
		 $hex81= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6b??65??72??6e??65??6c??33??32??2d??70??61??63??6b??61??67??65??2d??63??75??}
		 $hex82= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}
		 $hex83= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??77??69??6e??64??6f??77??73??74??61??74??69??6f??}
		 $hex84= {68??65??6c??70??6c??64??72??2e??64??6c??6c??73??77??6d??61??2e??64??6c??6c??69??6f??6d??75??73??2e??64??6c??6c??61??74??}
		 $hex85= {68??69??6b??69??74??3e??47??6c??6f??62??61??6c??25??73??5f??5f??53??48??4f??57??5f??5f??47??6c??6f??62??61??6c??25??73??}
		 $hex86= {69??6e??64??65??78??2e??70??68??70??3f??63??3d??25??53??26??72??3d??25??78??26??75??3d??31??26??74??3d??25??53??0a??}
		 $hex87= {6d??61??69??6c??74??6f??3a??4d??6f??68??61??6d??6d??65??64??2e??73??61??72??61??68??40??67??72??61??74??6e??65??72??2e??}
		 $hex88= {6d??73??61??63??6d??33??32??2e??64??72??76??43??3a??57??69??6e??64??6f??77??73??1b??78??70??6c??6f??72??65??72??2e??65??}
		 $hex89= {6d??73??69??73??76??63??5f??33??32??40??50??52??4f??50??3d??2d??45??6d??62??65??64??64??69??6e??67??53??3a??28??4d??4c??}
		 $hex90= {6e??4b??45??52??4e??45??4c??33??32??2e??44??4c??4c??40??52??65??74??75??72??6e??56??61??6c??75??65??0a??}
		 $hex91= {6e??56??69??65??77??5f??44??69??73??6b??4c??6f??79??64??62??6e??56??69??65??77??5f??4b??65??79??4c??6f??79??64??62??6e??}
		 $hex92= {6e??65??74??2f??68??74??74??70??2e??28??2a??54??72??61??6e??73??70??6f??72??74??29??2e??28??6e??65??74??2f??68??74??74??}
		 $hex93= {6e??65??74??73??68??2e??65??78??65??72??6f??75??74??65??6d??6f??6e??2e??65??78??65??73??63??72??69??70??74??3d??64??69??}
		 $hex94= {70??72??6f??67??72??61??6d??3d??62??6f??74??26??63??6f??75??6e??74??72??79??3d??26??6e??61??6d??65??3d??26??6f??70??73??}
		 $hex95= {73??6f??66??74??77??61??72??65??6d??69??63??72??6f??73??6f??66??74??69??6e??74??65??72??6e??65??74??20??65??78??70??6c??}
		 $hex96= {73??70??61??6e??69??73??68??2d??64??6f??6d??69??6e??69??63??61??6e??20??72??65??70??75??62??6c??69??63??0a??}
		 $hex97= {73??76??72??67??2e??70??64??62??57??33??32??70??53??65??72??76??69??63??65??54??61??62??6c??65??49??6e??20??66??6f??72??}
		 $hex98= {73??79??73??70??72??65??70??73??79??73??70??72??65??70??2e??65??78??65??73??79??73??70??72??65??70??43??52??59??50??54??}
		 $hex99= {74??79??70??65??2e??2e??65??71??2e??5b??36??31??5d??76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??72??67??}
		 $hex100= {74??79??70??65??2e??2e??68??61??73??68??2e??5b??36??31??5d??76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??}
		 $hex101= {76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??72??67??2f??78??2f??6e??65??74??2f??68??74??74??70??32??2f??}
		 $hex102= {76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??72??67??2f??78??2f??6e??65??74??2f??6c??65??78??2f??68??74??}
		 $hex103= {76??65??6e??64??6f??72??2f??67??6f??6c??61??6e??67??5f??6f??72??67??2f??78??2f??74??65??78??74??2f??75??6e??69??63??6f??}
		 $hex104= {77??69??6e??72??61??72??73??66??78??6d??61??70??70??69??6e??67??66??69??6c??65??2e??74??6d??70??47??45??54??50??41??53??}
		 $hex105= {77??77??77??2e??67??78??67??6c??2e??63??6f??6d??26??77??77??77??2e??67??78??67??6c??2e??6e??65??74??0a??}
		 $hex106= {7a??68??4c??6f??6f??6b??55??70??2e??50??72??6f??70??65??72??74??69??65??73??4d??69??6d??69??6b??61??74??7a??52??75??6e??}
		 $hex107= {7b??25??30??38??58??2d??25??30??34??58??2d??25??30??34??78??2d??25??30??32??58??25??30??32??58??2d??25??30??32??58??25??}
		 $hex108= {7b??45??31??39??30??42??43??37??39??2d??30??32??44??43??2d??30??31??36??36??2d??34??43??46??31??2d??42??44??38??46??38??}
		 $hex109= {7c??2a??7c??31??32??33??78??58??78??28??4d??75??74??65??78??29??78??58??78??33??32??31??7c??2a??7c??36??2d??32??31??2d??}

	condition:
		131 of them
}