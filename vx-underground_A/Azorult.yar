
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
		 date = "2022-01-12_23-59-46" 
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
		 $s2= "B/6e9IM0lv1deRotLVSMqfzR/7TnDRmYpcQdAF1sZQI=" fullword wide
		 $s3= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s4= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s5= "f7EQrLth9oRIDwYmOAgs8YdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $s6= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s7= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s8= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s9= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtprebuildincludestrgtold12.inl" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrcfeoferr.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrc_filbuf.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrcinput.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcprintf.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrcread.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcscanf.c" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrcsetlocal.c" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrc_sftbuf.c" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrcstrtol.c" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrcstrtoq.c" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s50= "f:ddvctoolscrt_bldself_x86crtsrcungetc_nolock.inl" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s52= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s53= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s54= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s55= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s56= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s57= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s58= "ganikevafinuwarelegafip licozunovo yusanabekule" fullword wide
		 $s59= "gekupamasusa tozidehiyuyafahepahuxocarebayay" fullword wide
		 $s60= "hijahahifujizutoyazojiwute reputocudujiyihahomuji yutebu" fullword wide
		 $s61= "Izzhskyhzfrihdeepvfgx.Properties.Resources" fullword wide
		 $s62= "Izzhskyhzfrihdeepvfgx.Xgdkqbneuz.dll" fullword wide
		 $s63= "jbxF7RuFQxeAfcDNv/rzZDVrpmMZcGkuoYsgavDnpqA=" fullword wide
		 $s64= "kc3MFqKEmC1nSr//wc0XbIdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $s65= "SRyXv11GajO3b9NkmyUQfRN/ySooED0AlaZqnHTDizfJOuaFtB2uF2juEZvXyn+l" fullword wide
		 $s66= "strcat_s(szLineMessage, 4096, szUserMessage)" fullword wide
		 $s67= "strcpy_s(resultstr, resultsize, autofos.man)" fullword wide
		 $s68= "strcpy_s(szOutMessage, 4096, szLineMessage)" fullword wide
		 $s69= "System.Security.Cryptography.ICryptoTransform" fullword wide
		 $s70= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s71= "System.Security.Cryptography.SymmetricAlgorithm" fullword wide
		 $s72= "tukonezihasaniwovadesicacugozakorekuxefolesojihoturegosojinazusisep" fullword wide
		 $s73= "wcscat_s(szLineMessage, 4096, szUserMessage)" fullword wide
		 $s74= "wcscpy_s(szOutMessage, 4096, szLineMessage)" fullword wide
		 $s75= "yJiEQqqPT84iigpvM0aPBfy3Wp7EtjvNyWJbd7B0d9I=" fullword wide
		 $s76= "ZStxXG/0jnvkJf64PUY9TIdvnaKEOIeCWi6vaMXoTCc=" fullword wide
		 $a1= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjectbinbinbinbinbinbinbinbinbinbinbinbin" fullword ascii
		 $a2= "binbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjectbinbinbinbinbinbinbinbinbinbinbinbinbi" fullword ascii
		 $a3= "binbinbinbinbinbinbinbinbinbinbinobjhtmlbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjupd" fullword ascii
		 $a4= "deftab708widowctrlftnbjaenddoctrackmoves0trackformatting1donotembedsysfont1relyonvml0donotembedlingdata0grfdocevents0validatexml1showplace" fullword ascii
		 $a5= "nbinbinbinbinbinbinbinbinbinbinobjhtmlbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinbinobjupdat" fullword ascii
		 $a6= "noxlattoyenexpshrtnnoultrlspcdntblnsbdbnospaceforulformshadehorzdocdgmargindghspace180dgvspace180dghorigin1701dgvorigin1134dghshow1dgvsh" fullword ascii

		 $hex1= {2461313d202262696e}
		 $hex2= {2461323d202262696e}
		 $hex3= {2461333d202262696e}
		 $hex4= {2461343d2022646566}
		 $hex5= {2461353d20226e6269}
		 $hex6= {2461363d20226e6f78}
		 $hex7= {247331303d2022663a}
		 $hex8= {247331313d2022663a}
		 $hex9= {247331323d2022663a}
		 $hex10= {247331333d2022663a}
		 $hex11= {247331343d2022663a}
		 $hex12= {247331353d2022663a}
		 $hex13= {247331363d2022663a}
		 $hex14= {247331373d2022663a}
		 $hex15= {247331383d2022663a}
		 $hex16= {247331393d2022663a}
		 $hex17= {2473313d2022364454}
		 $hex18= {247332303d2022663a}
		 $hex19= {247332313d2022663a}
		 $hex20= {247332323d2022663a}
		 $hex21= {247332333d2022663a}
		 $hex22= {247332343d2022663a}
		 $hex23= {247332353d2022663a}
		 $hex24= {247332363d2022663a}
		 $hex25= {247332373d2022663a}
		 $hex26= {247332383d2022663a}
		 $hex27= {247332393d2022663a}
		 $hex28= {2473323d2022422f36}
		 $hex29= {247333303d2022663a}
		 $hex30= {247333313d2022663a}
		 $hex31= {247333323d2022663a}
		 $hex32= {247333333d2022663a}
		 $hex33= {247333343d2022663a}
		 $hex34= {247333353d2022663a}
		 $hex35= {247333363d2022663a}
		 $hex36= {247333373d2022663a}
		 $hex37= {247333383d2022663a}
		 $hex38= {247333393d2022663a}
		 $hex39= {2473333d202242663a}
		 $hex40= {247334303d2022663a}
		 $hex41= {247334313d2022663a}
		 $hex42= {247334323d2022663a}
		 $hex43= {247334333d2022663a}
		 $hex44= {247334343d2022663a}
		 $hex45= {247334353d2022663a}
		 $hex46= {247334363d2022663a}
		 $hex47= {247334373d2022663a}
		 $hex48= {247334383d2022663a}
		 $hex49= {247334393d2022663a}
		 $hex50= {2473343d20225f424c}
		 $hex51= {247335303d2022663a}
		 $hex52= {247335313d2022663a}
		 $hex53= {247335323d2022663a}
		 $hex54= {247335333d2022663a}
		 $hex55= {247335343d2022663a}
		 $hex56= {247335353d2022663a}
		 $hex57= {247335363d2022663a}
		 $hex58= {247335373d2022663a}
		 $hex59= {247335383d20226761}
		 $hex60= {247335393d20226765}
		 $hex61= {2473353d2022663745}
		 $hex62= {247336303d20226869}
		 $hex63= {247336313d2022497a}
		 $hex64= {247336323d2022497a}
		 $hex65= {247336333d20226a62}
		 $hex66= {247336343d20226b63}
		 $hex67= {247336353d20225352}
		 $hex68= {247336363d20227374}
		 $hex69= {247336373d20227374}
		 $hex70= {247336383d20227374}
		 $hex71= {247336393d20225379}
		 $hex72= {2473363d2022663a64}
		 $hex73= {247337303d20225379}
		 $hex74= {247337313d20225379}
		 $hex75= {247337323d20227475}
		 $hex76= {247337333d20227763}
		 $hex77= {247337343d20227763}
		 $hex78= {247337353d2022794a}
		 $hex79= {247337363d20225a53}
		 $hex80= {2473373d2022663a64}
		 $hex81= {2473383d2022663a64}
		 $hex82= {2473393d2022663a64}

	condition:
		10 of them
}
