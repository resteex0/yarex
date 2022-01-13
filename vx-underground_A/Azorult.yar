
/*
   YARA Rule Set
   Author: resteex
   Identifier: Azorult 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Azorult {
	meta: 
		 description= "Azorult Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-49-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "10d70826cad122454a101ba1e1ac4b2c"
		 hash2= "164076414dd3be991ebc9d4d17101296"
		 hash3= "4ba3a1e322a575dfa2716ea30118d106"
		 hash4= "6921baf9c8b503011bd5a68856fe405a"
		 hash5= "7de4b7acf01c315fb0efe48ac9eb4081"
		 hash6= "994d16ca9cb22b04a86920acf52977d6"
		 hash7= "997f26e502eb7d3c839b71ab5e77a647"
		 hash8= "a5ce2653f5f74c7ba7901f79cf9932a5"
		 hash9= "b934de9501d24cc375b698b028792fc8"
		 hash10= "c2b1e2483e49899114fea118f6a53993"
		 hash11= "d32cc02c92d1172ca4e8c3109e7909ed"
		 hash12= "e003da977b301d2cbfe38e2198db861b"

	strings:

	
 		 $s1= "6DTeigQMLm3WKEfaKtZ5eMtBgvoXVTSmitJN2r2sjbI=" fullword wide
		 $s2= "a kofipuyaj jecoralazomi'Wibuz bejumusunakafex zimagewo bozawoxaBirenedih hozipof wenejexuwekemo ba" fullword wide
		 $s3= "B/6e9IM0lv1deRotLVSMqfzR/7TnDRmYpcQdAF1sZQI=" fullword wide
		 $s4= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s5= "Bisasoleputari yudurudiraOHofagifikace sejipapolu wepi kayes ciyuwugep vebehaxuxe fegewegan dobojoma" fullword wide
		 $s6= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s7= "boihenlwiwubdkuvfcryiscyt" fullword wide
		 $s8= "cicozMuvobet pukacoradusocip rihukutegupajo suyic goseguzetogurub cok safukabagutoy sig lola dudi" fullword wide
		 $s9= "colakafi jovivekosorodirotufimipa rimipepimapokofo nudecudicococawocebamenih hefihejoho" fullword wide
		 $s10= "Copyrighz (C) 2020, wodkaguds" fullword wide
		 $s11= "(count == 0) || (string != NULL)" fullword wide
		 $s12= "_CrtDbgReport: String too long or Invalid characters in String" fullword wide
		 $s13= "_CrtDbgReport: String too long or IO Error" fullword wide
		 $s14= "_CrtIsValidHeapPointer(pUserData)" fullword wide
		 $s15= "dalawa bax tesogusuliz bilatiwesut bicijewipili kuya laxi" fullword wide
		 $s16= "((_Dst)) != NULL && ((_SizeInBytes)) > 0" fullword wide
		 $s17= "(dst != NULL && sizeInBytes > 0) || (dst == NULL && sizeInBytes == 0)" fullword wide
		 $s18= "((_Dst)) != NULL && ((_SizeInWords)) > 0" fullword wide
		 $s19= "duyojil0Cenivuxodiriy ciwepi delidic vaboxeruxuc yupereg1Yezuluzemu tijemefedojalib tewodi rolevuca" fullword wide
		 $s20= "e = mbstowcs_s(&ret, szOutMessage2, 4096, szOutMessage, ((size_t)-1))" fullword wide
		 $s21= "express_pictureviewerdone" fullword wide
		 $s22= "f7EQrLth9oRIDwYmOAgs8YdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $s23= "failure, see the Visual C++ documentation on asserts." fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtprebuildincludestrgtold12.inl" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcfeoferr.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrc_filbuf.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrcinput.c" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s50= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s52= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s53= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s54= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s55= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s56= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s57= "f:ddvctoolscrt_bldself_x86crtsrcprintf.c" fullword wide
		 $s58= "f:ddvctoolscrt_bldself_x86crtsrcread.c" fullword wide
		 $s59= "f:ddvctoolscrt_bldself_x86crtsrcscanf.c" fullword wide
		 $s60= "f:ddvctoolscrt_bldself_x86crtsrcsetlocal.c" fullword wide
		 $s61= "f:ddvctoolscrt_bldself_x86crtsrc_sftbuf.c" fullword wide
		 $s62= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s63= "f:ddvctoolscrt_bldself_x86crtsrcstrtol.c" fullword wide
		 $s64= "f:ddvctoolscrt_bldself_x86crtsrcstrtoq.c" fullword wide
		 $s65= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s66= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s67= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s68= "f:ddvctoolscrt_bldself_x86crtsrcungetc_nolock.inl" fullword wide
		 $s69= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s70= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s71= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s72= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s73= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s74= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s75= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s76= "For information on how your program can cause an assertion" fullword wide
		 $s77= "fRealloc || (!fRealloc && pNewBlock == pOldBlock)" fullword wide
		 $s78= "fuxogejuxayoyapor dizifejopupaguwomukalise punifecucabococimexivajicuxova kavicunuhewilohud" fullword wide
		 $s79= "ganikevafinuwarelegafip licozunovo yusanabekule" fullword wide
		 $s80= "gekupamasusa tozidehiyuyafahepahuxocarebayay" fullword wide
		 $s81= "&Get text entered to the secure edit" fullword wide
		 $s82= "gudoyas*Vekeyot dukopizac wafebehef zinisudayemuga5Wosuy pejosejahe fed yuyatasixikete mice zobuyuji" fullword wide
		 $s83= "(_HEAP_MAXREQ / count) >= size" fullword wide
		 $s84= "(_HEAP_MAXREQ / nNum) >= nSize" fullword wide
		 $s85= "hijahahifujizutoyazojiwute reputocudujiyihahomuji yutebu" fullword wide
		 $s86= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $s87= "_itoa_s(nLine, szLineMessage, 4096, 10)" fullword wide
		 $s88= "_itow_s(nLine, szLineMessage, 4096, 10)" fullword wide
		 $s89= "Izzhskyhzfrihdeepvfgx.Properties.Resources" fullword wide
		 $s90= "Izzhskyhzfrihdeepvfgx.Xgdkqbneuz.dll" fullword wide
		 $s91= "jbxF7RuFQxeAfcDNv/rzZDVrpmMZcGkuoYsgavDnpqA=" fullword wide
		 $s92= "Jus fudigohakoven vil maxawavanahapogayowipiwigawak" fullword wide
		 $s93= "kc3MFqKEmC1nSr//wc0XbIdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $s94= "lafolawilugehazocinogohigugalug" fullword wide
		 $s95= "_loc_update.GetLocaleT()->locinfo->mb_cur_max == 1 || _loc_update.GetLocaleT()->locinfo->mb_cur_max " fullword wide
		 $s96= "Microsoft Corporation. All rights reserved." fullword wide
		 $s97= "Microsoft Visual C++ Debug Library" fullword wide
		 $s98= ">Mij natafa niwoxucuvox yepir kijaxum lufe yojovekitu fobomiyig%Jed xememoke bojejaberexawu bekiluru" fullword wide
		 $s99= "Mudefeho voz_Disaponefujadiw tujanifemorez liwayiwuri gawul hor lipuzepasabemev poyaraf firom fatire" fullword wide
		 $s100= "(_osfile(filedes) & FOPEN)" fullword wide
		 $s101= "_pFirstBlock == pOldBlock" fullword wide
		 $s102= "pHead->nBlockUse == nBlockUse" fullword wide
		 $s103= "pHead->nLine == IGNORE_LINE && pHead->lRequest == IGNORE_REQ" fullword wide
		 $s104= "pigax yutalisavahenezemaz cizulakiboxarikagarufuwub kohopisena" fullword wide
		 $s105= "pOldBlock->nLine == IGNORE_LINE && pOldBlock->lRequest == IGNORE_REQ" fullword wide
		 $s106= "(Press Retry to debug the application)" fullword wide
		 $s107= ")) || ((ptloci->lc_category[category].wlocale == NULL) && (ptloci->lc_category[category].wrefcount =" fullword wide
		 $s108= "((ptloci->lc_category[category].wlocale != NULL) && (ptloci->lc_category[category].wrefcount != NULL" fullword wide
		 $s109= "(pwcs == NULL && sizeInWords == 0) || (pwcs != NULL && sizeInWords > 0)" fullword wide
		 $s110= "QButeyasad niji vojuduxeguwuv lewab teceridige xahav vuta canehisapodo wumoninuhut TasucanivKNumunah" fullword wide
		 $s111= "riyovohuyujujemukupicivajodo" fullword wide
		 $s112= "sarihonicuzayuhoropitusuzonu" fullword wide
		 $s113= "Sazoluyelofop dukinobekakikur" fullword wide
		 $s114= "Second Chance Assertion Failed: File " fullword wide
		 $s115= "SEJUWUSIZABUTUXAKAYUPIGIGEYOKAHA" fullword wide
		 $s116= "Sepiroxivomozab nofikelul sezi" fullword wide
		 $s117= "sizeInBytes > (size_t)(1 + 4 + ndec + 6)" fullword wide
		 $s118= "sizeInBytes > (size_t)(3 + (ndec > 0 ? ndec : 0) + 5 + 1)" fullword wide
		 $s119= "sizeInBytes > (size_t)((digits > 0 ? digits : 0) + 1)" fullword wide
		 $s120= "sizeInTChars > (size_t)(is_neg ? 2 : 1)" fullword wide
		 $s121= "sozucuwulurotikucuxicabeyodu soyoxucebihumutuf vidasapodevigupodu hek" fullword wide
		 $s122= "SRyXv11GajO3b9NkmyUQfRN/ySooED0AlaZqnHTDizfJOuaFtB2uF2juEZvXyn+l" fullword wide
		 $s123= "((state == ST_NORMAL) || (state == ST_TYPE))" fullword wide
		 $s124= "strcat_s(outmsg, (sizeof(outmsg) / sizeof(outmsg[0])), rterrs[tblindx].rterrtxt)" fullword wide
		 $s125= "strcat_s(szLineMessage, 4096, szUserMessage)" fullword wide
		 $s126= "strcpy_s(*env, cchars, p)" fullword wide
		 $s127= "strcpy_s(resultstr, resultsize, autofos.man)" fullword wide
		 $s128= "strcpy_s(szOutMessage, 4096, szLineMessage)" fullword wide
		 $s129= "String is not null terminated" fullword wide
		 $s130= "string != NULL && sizeInBytes > 0" fullword wide
		 $s131= "string != NULL && sizeInWords > 0" fullword wide
		 $s132= "System.Reflection.Assembly" fullword wide
		 $s133= "System.Reflection.PropertyInfo" fullword wide
		 $s134= "System.Resources.ResourceManager" fullword wide
		 $s135= "System.Security.Cryptography.ICryptoTransform" fullword wide
		 $s136= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s137= "System.Security.Cryptography.SymmetricAlgorithm" fullword wide
		 $s138= "TestSecureEdit - CSecureEdit demo application" fullword wide
		 $s139= "TestSecureEdit Version 1.0" fullword wide
		 $s140= "TojezaxohRudacohuyayov goseti popilamumezon muyuxe hodunokid yumakojo petiyuzuyone xapiduhibugu bimi" fullword wide
		 $s141= "tukonezihasaniwovadesicacugozakorekuxefolesojihoturegosojinazusisep" fullword wide
		 $s142= "ujici fehegiyumacuy rozixosagesav rewiwupubibad zolamo lirujoxipenoj7Gihiwidozi hekus vot seyaxa tul" fullword wide
		 $s143= "uk baxasubunecezay luvoxohunazukov zuzo fagileja xibi Resijarew" fullword wide
		 $s144= "v/Jajoniz huy tutiw xisereb geherurunokuku xoyodu?Fek yuxonekur dopubugahanuh suvuwimidiv hegazuwiji" fullword wide
		 $s145= "wcscat_s(szLineMessage, 4096, szUserMessage)" fullword wide
		 $s146= "wcscpy_s(szOutMessage, 4096, szLineMessage)" fullword wide
		 $s147= "wcstombs_s(&ret, szaOutMessage, 4096, szOutMessage, ((size_t)-1))" fullword wide
		 $s148= "wcstombs_s(((void *)0), szOutMessage2, 4096, szOutMessage, ((size_t)-1))" fullword wide
		 $s149= "Windows Media Player Launcher" fullword wide
		 $s150= "Wixosezacac cabahatewulija0Lomomu hodojomiheso yadima kicex pera ledabusume" fullword wide
		 $s151= "yJiEQqqPT84iigpvM0aPBfy3Wp7EtjvNyWJbd7B0d9I=" fullword wide
		 $s152= "ziy zoneresidPJegobuyubik girec ribuxufadiga tekezemacotayo coharemakazok yejalav momi xutufot:Fuyuc" fullword wide
		 $s153= "ZStxXG/0jnvkJf64PUY9TIdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $a1= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjec" fullword ascii
		 $a2= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobject" fullword ascii
		 $a3= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjhtml" fullword ascii
		 $a4= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjupdat" fullword ascii
		 $a5= "deftab708widowctrlftnbjaenddoctrackmoves0trackformatting1donotembedsysfont1relyonvml0donote" fullword ascii
		 $a6= "lbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjupd" fullword ascii
		 $a7= "mbedlingdata0grfdocevents0validatexml1showplaceholdtext0ignoremixedcontent0saveinvalidxml0show" fullword ascii
		 $a8= "noxlattoyenexpshrtnnoultrlspcdntblnsbdbnospaceforulformshadehorzdocdgmargindghspace180dgvs" fullword ascii
		 $a9= "tbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjhtm" fullword ascii

		 $hex1= {2461313d202262696e}
		 $hex2= {2461323d202262696e}
		 $hex3= {2461333d202262696e}
		 $hex4= {2461343d202262696e}
		 $hex5= {2461353d2022646566}
		 $hex6= {2461363d20226c6269}
		 $hex7= {2461373d20226d6265}
		 $hex8= {2461383d20226e6f78}
		 $hex9= {2461393d2022746269}
		 $hex10= {24733130303d202228}
		 $hex11= {24733130313d20225f}
		 $hex12= {24733130323d202270}
		 $hex13= {24733130333d202270}
		 $hex14= {24733130343d202270}
		 $hex15= {24733130353d202270}
		 $hex16= {24733130363d202228}
		 $hex17= {24733130373d202229}
		 $hex18= {24733130383d202228}
		 $hex19= {24733130393d202228}
		 $hex20= {247331303d2022436f}
		 $hex21= {24733131303d202251}
		 $hex22= {24733131313d202272}
		 $hex23= {24733131323d202273}
		 $hex24= {24733131333d202253}
		 $hex25= {24733131343d202253}
		 $hex26= {24733131353d202253}
		 $hex27= {24733131363d202253}
		 $hex28= {24733131373d202273}
		 $hex29= {24733131383d202273}
		 $hex30= {24733131393d202273}
		 $hex31= {247331313d20222863}
		 $hex32= {24733132303d202273}
		 $hex33= {24733132313d202273}
		 $hex34= {24733132323d202253}
		 $hex35= {24733132333d202228}
		 $hex36= {24733132343d202273}
		 $hex37= {24733132353d202273}
		 $hex38= {24733132363d202273}
		 $hex39= {24733132373d202273}
		 $hex40= {24733132383d202273}
		 $hex41= {24733132393d202253}
		 $hex42= {247331323d20225f43}
		 $hex43= {24733133303d202273}
		 $hex44= {24733133313d202273}
		 $hex45= {24733133323d202253}
		 $hex46= {24733133333d202253}
		 $hex47= {24733133343d202253}
		 $hex48= {24733133353d202253}
		 $hex49= {24733133363d202253}
		 $hex50= {24733133373d202253}
		 $hex51= {24733133383d202254}
		 $hex52= {24733133393d202254}
		 $hex53= {247331333d20225f43}
		 $hex54= {24733134303d202254}
		 $hex55= {24733134313d202274}
		 $hex56= {24733134323d202275}
		 $hex57= {24733134333d202275}
		 $hex58= {24733134343d202276}
		 $hex59= {24733134353d202277}
		 $hex60= {24733134363d202277}
		 $hex61= {24733134373d202277}
		 $hex62= {24733134383d202277}
		 $hex63= {24733134393d202257}
		 $hex64= {247331343d20225f43}
		 $hex65= {24733135303d202257}
		 $hex66= {24733135313d202279}
		 $hex67= {24733135323d20227a}
		 $hex68= {24733135333d20225a}
		 $hex69= {247331353d20226461}
		 $hex70= {247331363d20222828}
		 $hex71= {247331373d20222864}
		 $hex72= {247331383d20222828}
		 $hex73= {247331393d20226475}
		 $hex74= {2473313d2022364454}
		 $hex75= {247332303d20226520}
		 $hex76= {247332313d20226578}
		 $hex77= {247332323d20226637}
		 $hex78= {247332333d20226661}
		 $hex79= {247332343d2022663a}
		 $hex80= {247332353d2022663a}
		 $hex81= {247332363d2022663a}
		 $hex82= {247332373d2022663a}
		 $hex83= {247332383d2022663a}
		 $hex84= {247332393d2022663a}
		 $hex85= {2473323d202261206b}
		 $hex86= {247333303d2022663a}
		 $hex87= {247333313d2022663a}
		 $hex88= {247333323d2022663a}
		 $hex89= {247333333d2022663a}
		 $hex90= {247333343d2022663a}
		 $hex91= {247333353d2022663a}
		 $hex92= {247333363d2022663a}
		 $hex93= {247333373d2022663a}
		 $hex94= {247333383d2022663a}
		 $hex95= {247333393d2022663a}
		 $hex96= {2473333d2022422f36}
		 $hex97= {247334303d2022663a}
		 $hex98= {247334313d2022663a}
		 $hex99= {247334323d2022663a}
		 $hex100= {247334333d2022663a}
		 $hex101= {247334343d2022663a}
		 $hex102= {247334353d2022663a}
		 $hex103= {247334363d2022663a}
		 $hex104= {247334373d2022663a}
		 $hex105= {247334383d2022663a}
		 $hex106= {247334393d2022663a}
		 $hex107= {2473343d202242663a}
		 $hex108= {247335303d2022663a}
		 $hex109= {247335313d2022663a}
		 $hex110= {247335323d2022663a}
		 $hex111= {247335333d2022663a}
		 $hex112= {247335343d2022663a}
		 $hex113= {247335353d2022663a}
		 $hex114= {247335363d2022663a}
		 $hex115= {247335373d2022663a}
		 $hex116= {247335383d2022663a}
		 $hex117= {247335393d2022663a}
		 $hex118= {2473353d2022426973}
		 $hex119= {247336303d2022663a}
		 $hex120= {247336313d2022663a}
		 $hex121= {247336323d2022663a}
		 $hex122= {247336333d2022663a}
		 $hex123= {247336343d2022663a}
		 $hex124= {247336353d2022663a}
		 $hex125= {247336363d2022663a}
		 $hex126= {247336373d2022663a}
		 $hex127= {247336383d2022663a}
		 $hex128= {247336393d2022663a}
		 $hex129= {2473363d20225f424c}
		 $hex130= {247337303d2022663a}
		 $hex131= {247337313d2022663a}
		 $hex132= {247337323d2022663a}
		 $hex133= {247337333d2022663a}
		 $hex134= {247337343d2022663a}
		 $hex135= {247337353d2022663a}
		 $hex136= {247337363d2022466f}
		 $hex137= {247337373d20226652}
		 $hex138= {247337383d20226675}
		 $hex139= {247337393d20226761}
		 $hex140= {2473373d2022626f69}
		 $hex141= {247338303d20226765}
		 $hex142= {247338313d20222647}
		 $hex143= {247338323d20226775}
		 $hex144= {247338333d2022285f}
		 $hex145= {247338343d2022285f}
		 $hex146= {247338353d20226869}
		 $hex147= {247338363d20226973}
		 $hex148= {247338373d20225f69}
		 $hex149= {247338383d20225f69}
		 $hex150= {247338393d2022497a}
		 $hex151= {2473383d2022636963}
		 $hex152= {247339303d2022497a}
		 $hex153= {247339313d20226a62}
		 $hex154= {247339323d20224a75}
		 $hex155= {247339333d20226b63}
		 $hex156= {247339343d20226c61}
		 $hex157= {247339353d20225f6c}
		 $hex158= {247339363d20224d69}
		 $hex159= {247339373d20224d69}
		 $hex160= {247339383d20223e4d}
		 $hex161= {247339393d20224d75}
		 $hex162= {2473393d2022636f6c}

	condition:
		20 of them
}
