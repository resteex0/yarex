
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_RaccoonStealer 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_RaccoonStealer {
	meta: 
		 description= "vx_underground2_RaccoonStealer Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0406811e788b8b7e0b466000d39488eb"
		 hash2= "04d8e90bf866b46b340f904339df40b5"
		 hash3= "11411bed8081d51a7e7ac556a24e42aa"
		 hash4= "171625eb0cb811f1df8798436a942928"
		 hash5= "19cc436851674447feb94044399159f2"
		 hash6= "1c77baced3861967f62ec3190a4be7d1"
		 hash7= "1e249d1ade1a739b6cec129a3c23be53"
		 hash8= "1e4b4f6b2968b98c9fe5d3853bc95fd2"
		 hash9= "200f4423e9f93a1b71a5ef368ba5919f"
		 hash10= "2537f760b89a4cb6db60a6812f65d29c"
		 hash11= "283cd7c1de6f4f05ab545de5b709b680"
		 hash12= "488acb812eb5c16604d152f8f0268ae6"
		 hash13= "4f5cbf4eb9e615292820a8eb75b93eb9"
		 hash14= "57a71bd0532cbdd37c87a33c84d0c2d4"
		 hash15= "6a6bcfa2451c8a2eb94d79150c4c23a4"
		 hash16= "6e0e5e734a3654348fe0acbf25386e02"
		 hash17= "7582101f254419962c55ec27d36724ba"
		 hash18= "78fb7901211870dbb7fa0201810b8524"
		 hash19= "85ccac3064ee0b602935f2b9f5fb6656"
		 hash20= "9a613a082cf1ffa458f0f12923dc9490"
		 hash21= "a370aa7a71e6b5c129ba1dc32a6ca286"
		 hash22= "a72b8c2fdf7c1119fec2513671065498"
		 hash23= "b48aa7fe83538a4f46e6d92376b97415"
		 hash24= "b4b6891aeb21106225c1fb69954f859b"
		 hash25= "b7ee751e1006cce4ec7798cf2223b801"
		 hash26= "c5fc0f2f78cc225cf44b3b971e302471"
		 hash27= "cb449bb6d343d1775773449fbe1cf704"
		 hash28= "eef9be1c376b2031d057ab3f50ef9fe4"
		 hash29= "f012091742dad985c58f22a0d458a57c"
		 hash30= "f4112558cd3674e2668f5e10011a76f9"
		 hash31= "f42547787dce72e8461bddbd19999cb1"

	strings:

	
 		 $s1= "50736575646F437573746F6D41747472696275" fullword wide
		 $s2= "Af:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s3= ":ANALYTICS_GRAPH_PIE_CHART_PIE_GRAPH_STATISTICS_ICON_191083" fullword wide
		 $s4= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s5= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s6= "budihuruvonuv wicevigowusa" fullword wide
		 $s7= "_CrtIsValidHeapPointer(pUserData)" fullword wide
		 $s8= "demakajixazofayaviribepofugufupefonavimem" fullword wide
		 $s9= "ENetHttpStatusCode38205RAUBTcuHj01KjoyFwlnVA==" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrcfeoferr.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrc_filbuf.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrcinput.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrcprintf.c" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrcread.c" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrcscanf.c" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrcsetlocal.c" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrc_sftbuf.c" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrcstrtol.c" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrcstrtoq.c" fullword wide
		 $s50= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s52= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s53= "f:ddvctoolscrt_bldself_x86crtsrcungetc_nolock.inl" fullword wide
		 $s54= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s55= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s56= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s57= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s58= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s59= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s60= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s61= "fezekopupikayocicizojisowa zihebagaponaxo" fullword wide
		 $s62= "FNetHttpStatusCode38205HoMEDYpBTc0PSE0Lw8iGg==" fullword wide
		 $s63= "FNetHttpStatusCode38205yYIAjYDJDEjABAy" fullword wide
		 $s64= "funanatitoxemopatu wecelatiseta" fullword wide
		 $s65= "gekupamasusa tozidehiyuyafahepahuxocarebayay" fullword wide
		 $s66= "gukemikekugoxopohisaluyapimow" fullword wide
		 $s67= "INetHttpStatusCode382053pjWhouAQwjHzoUFAAQBQ0TAQAbdV1xLxAyWQ==" fullword wide
		 $s68= "INetHttpStatusCode382053pjWhouARAjHzoUFAAQBQ0TAQAbdV1xLxAyWQ==" fullword wide
		 $s69= "INetHttpStatusCode382053sQGTADBRUaKlErLxAUEwATBTAbdCJ0" fullword wide
		 $s70= "INetHttpStatusCode38205CUMEzATYigvAAA4Lx8cAg==" fullword wide
		 $s71= "INetHttpStatusCode38205HoMWQIDOz0jEC4qJHpjHDADBXAdBlV8" fullword wide
		 $s72= "INetHttpStatusCode38205HoyHzB1NzQbKjo3ET9nVA==" fullword wide
		 $s73= "INetHttpStatusCode38205SYIPzYpYiwaATIxLxA+OQ4oHSggdDoxF3puVA==" fullword wide
		 $s74= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $s75= "JNetHttpStatusCode382053oMWQIDOz0jEC4qJHpjHDADBXAdBlV8" fullword wide
		 $s76= "JNetHttpStatusCode382053oMWQV2ajEadVEyLx4+GTYpATIdMFV8" fullword wide
		 $s77= "karizevodasayohihohecezulamas" fullword wide
		 $s78= "lafolawilugehazocinogohigugalug" fullword wide
		 $s79= "levihufanogisojinasitogatopacaxuhozuwehu" fullword wide
		 $s80= "MessageQueryCollection Corporation." fullword wide
		 $s81= "=(*pnFloatStrSz)" fullword wide
		 $s82= "PRODUCT-ID: Codejock.Calendar.ActiveX.v15.2" fullword wide
		 $s83= "PRODUCT-ID: Codejock.Chart.ActiveX.v15.2" fullword wide
		 $s84= "PRODUCT-ID: Codejock.DockingPane.ActiveX.v15.2" fullword wide
		 $s85= "PRODUCT-ID: Codejock.FlowGraph.ActiveX.v15.2" fullword wide
		 $s86= "PRODUCT-ID: Codejock.Markup.ActiveX.v15.2" fullword wide
		 $s87= "PRODUCT-ID: Codejock.PropertyGrid.ActiveX.v15.2" fullword wide
		 $s88= "PRODUCT-ID: Codejock.ReportControl.ActiveX.v15.2" fullword wide
		 $s89= "PRODUCT-ID: Codejock.SyntaxEdit.ActiveX.v15.2" fullword wide
		 $s90= "PRODUCT-ID: Codejock.TaskPanel.ActiveX.v15.2" fullword wide
		 $s91= "riyovohuyujujemukupicivajodo" fullword wide
		 $s92= "sarihonicuzayuhoropitusuzonu" fullword wide
		 $s93= "Sazoluyelofop dukinobekakikur" fullword wide
		 $s94= "SEJUWUSIZABUTUXAKAYUPIGIGEYOKAHA" fullword wide
		 $s95= "sexebigulihijowawekowazini" fullword wide
		 $s96= "SynchronizationContextProperti.exe" fullword wide
		 $s97= "SystemCodeDomCodeStatementCollection22148" fullword wide
		 $s98= "SystemDataSqlClientSNIPacket70882" fullword wide
		 $s99= "VALIDATE-CODE: CHA-RTY-EKD-EME" fullword wide
		 $s100= "VALIDATE-CODE: DJN-TXA-SGX-EFY" fullword wide
		 $s101= "VALIDATE-CODE: DPV-TGO-RWX-NGL" fullword wide
		 $s102= "VALIDATE-CODE: HIF-MPA-DRR-OPF" fullword wide
		 $s103= "VALIDATE-CODE: HVN-LFW-DIX-XRR" fullword wide
		 $s104= "VALIDATE-CODE: JKL-NMB-QPO-DGZ" fullword wide
		 $s105= "VALIDATE-CODE: UCY-KMS-CII-OCF" fullword wide
		 $s106= "VALIDATE-CODE: WAD-FOY-VBC-AED" fullword wide
		 $s107= "VALIDATE-CODE: YU4-GH3-78G-BNP" fullword wide
		 $s108= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword wide
		 $s109= "vikoserujofafuhazivovejijuwaxu zinige" fullword wide
		 $s110= "WinForms_RecursiveFormCreate" fullword wide
		 $s111= "WinForms_SeeInnerException" fullword wide
		 $s112= "Wobetesido suvesebuxomelot" fullword wide
		 $s113= "zjixazavobutozixuhopa codirimejexivijujares" fullword wide
		 $a1= "cahenokejocijugujinugacokimugizirafehewisamiwetutonuwacogohatudo" fullword ascii
		 $a2= "C:citazixuxobatejibalilukxogom_hitumulotefavu-yoyodaxiw.pdb" fullword ascii
		 $a3= "C:ziyuplarupudehuvuw72dimamutopaze48wubatogexikoc_pobi.pdb" fullword ascii
		 $a4= "get_SystemNetSpnDictionaryValueCollectionGetEnumeratord92833" fullword ascii
		 $a5= "SystemNetMailSmtpReplyReaderFactoryReadLinesAsyncResult33045" fullword ascii
		 $a6= "SystemServiceModelChannelsPeerTransportPolicyConstants54639asd" fullword ascii
		 $a7= "SystemServiceModelDescriptionMetadataExchangeClientMode79897" fullword ascii
		 $a8= "SystemServiceModelDiagnosticsEndpointPerformanceCounters16460" fullword ascii
		 $a9= "SystemServiceModelPeerResolversPeerReferralPolicyHelper86896" fullword ascii

		 $hex1= {2461313d2022636168}
		 $hex2= {2461323d2022433a63}
		 $hex3= {2461333d2022433a7a}
		 $hex4= {2461343d2022676574}
		 $hex5= {2461353d2022537973}
		 $hex6= {2461363d2022537973}
		 $hex7= {2461373d2022537973}
		 $hex8= {2461383d2022537973}
		 $hex9= {2461393d2022537973}
		 $hex10= {24733130303d202256}
		 $hex11= {24733130313d202256}
		 $hex12= {24733130323d202256}
		 $hex13= {24733130333d202256}
		 $hex14= {24733130343d202256}
		 $hex15= {24733130353d202256}
		 $hex16= {24733130363d202256}
		 $hex17= {24733130373d202256}
		 $hex18= {24733130383d202276}
		 $hex19= {24733130393d202276}
		 $hex20= {247331303d2022663a}
		 $hex21= {24733131303d202257}
		 $hex22= {24733131313d202257}
		 $hex23= {24733131323d202257}
		 $hex24= {24733131333d20227a}
		 $hex25= {247331313d2022663a}
		 $hex26= {247331323d2022663a}
		 $hex27= {247331333d2022663a}
		 $hex28= {247331343d2022663a}
		 $hex29= {247331353d2022663a}
		 $hex30= {247331363d2022663a}
		 $hex31= {247331373d2022663a}
		 $hex32= {247331383d2022663a}
		 $hex33= {247331393d2022663a}
		 $hex34= {2473313d2022353037}
		 $hex35= {247332303d2022663a}
		 $hex36= {247332313d2022663a}
		 $hex37= {247332323d2022663a}
		 $hex38= {247332333d2022663a}
		 $hex39= {247332343d2022663a}
		 $hex40= {247332353d2022663a}
		 $hex41= {247332363d2022663a}
		 $hex42= {247332373d2022663a}
		 $hex43= {247332383d2022663a}
		 $hex44= {247332393d2022663a}
		 $hex45= {2473323d202241663a}
		 $hex46= {247333303d2022663a}
		 $hex47= {247333313d2022663a}
		 $hex48= {247333323d2022663a}
		 $hex49= {247333333d2022663a}
		 $hex50= {247333343d2022663a}
		 $hex51= {247333353d2022663a}
		 $hex52= {247333363d2022663a}
		 $hex53= {247333373d2022663a}
		 $hex54= {247333383d2022663a}
		 $hex55= {247333393d2022663a}
		 $hex56= {2473333d20223a414e}
		 $hex57= {247334303d2022663a}
		 $hex58= {247334313d2022663a}
		 $hex59= {247334323d2022663a}
		 $hex60= {247334333d2022663a}
		 $hex61= {247334343d2022663a}
		 $hex62= {247334353d2022663a}
		 $hex63= {247334363d2022663a}
		 $hex64= {247334373d2022663a}
		 $hex65= {247334383d2022663a}
		 $hex66= {247334393d2022663a}
		 $hex67= {2473343d202242663a}
		 $hex68= {247335303d2022663a}
		 $hex69= {247335313d2022663a}
		 $hex70= {247335323d2022663a}
		 $hex71= {247335333d2022663a}
		 $hex72= {247335343d2022663a}
		 $hex73= {247335353d2022663a}
		 $hex74= {247335363d2022663a}
		 $hex75= {247335373d2022663a}
		 $hex76= {247335383d2022663a}
		 $hex77= {247335393d2022663a}
		 $hex78= {2473353d20225f424c}
		 $hex79= {247336303d2022663a}
		 $hex80= {247336313d20226665}
		 $hex81= {247336323d2022464e}
		 $hex82= {247336333d2022464e}
		 $hex83= {247336343d20226675}
		 $hex84= {247336353d20226765}
		 $hex85= {247336363d20226775}
		 $hex86= {247336373d2022494e}
		 $hex87= {247336383d2022494e}
		 $hex88= {247336393d2022494e}
		 $hex89= {2473363d2022627564}
		 $hex90= {247337303d2022494e}
		 $hex91= {247337313d2022494e}
		 $hex92= {247337323d2022494e}
		 $hex93= {247337333d2022494e}
		 $hex94= {247337343d20226973}
		 $hex95= {247337353d20224a4e}
		 $hex96= {247337363d20224a4e}
		 $hex97= {247337373d20226b61}
		 $hex98= {247337383d20226c61}
		 $hex99= {247337393d20226c65}
		 $hex100= {2473373d20225f4372}
		 $hex101= {247338303d20224d65}
		 $hex102= {247338313d20223d28}
		 $hex103= {247338323d20225052}
		 $hex104= {247338333d20225052}
		 $hex105= {247338343d20225052}
		 $hex106= {247338353d20225052}
		 $hex107= {247338363d20225052}
		 $hex108= {247338373d20225052}
		 $hex109= {247338383d20225052}
		 $hex110= {247338393d20225052}
		 $hex111= {2473383d202264656d}
		 $hex112= {247339303d20225052}
		 $hex113= {247339313d20227269}
		 $hex114= {247339323d20227361}
		 $hex115= {247339333d20225361}
		 $hex116= {247339343d20225345}
		 $hex117= {247339353d20227365}
		 $hex118= {247339363d20225379}
		 $hex119= {247339373d20225379}
		 $hex120= {247339383d20225379}
		 $hex121= {247339393d20225641}
		 $hex122= {2473393d2022454e65}

	condition:
		81 of them
}
