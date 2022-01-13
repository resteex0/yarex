
/*
   YARA Rule Set
   Author: resteex
   Identifier: Babuk 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Babuk {
	meta: 
		 description= "Babuk Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-13_15-14-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0be16d0732b1d4402bdedd4e108ed38e"
		 hash2= "2d642a20de66c7f9132790ecc2b0cfc6"
		 hash3= "75a6690d9a4a89bd0cf6ceebcffd3c41"
		 hash4= "aee27a5ebedadf12beed294f59026162"

	strings:

	
 		 $s1= "aHR0cDovL2NoZWNraXAuZHluZG5zLm9yZw==" fullword wide
		 $s2= "aHR0cHM6Ly9ldGhlcmJvbnVzLm5ldC9jcnlwdG8uZXhl" fullword wide
		 $s3= "aHR0cHM6Ly9pcGxvZ2dlci5vcmcvMUZQTTc3" fullword wide
		 $s4= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s5= "Cf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s6= "eyIsIHN0cmluZy5FbXB0eSkuUmVwbGFjZSgifQ==" fullword wide
		 $s7= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s8= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s9= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtsrcatof.c" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrcmemmove_s.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcsetlocal.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrcstrtol.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s50= "@f:ddvctoolscrt_bldself_x86crtsrcxstring" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s52= "jixazavobutozixuhopa codirimejexivijujares" fullword wide
		 $s53= "JVNZU1RFTURSSVZFJVxcV2luZG93c1xcU3lzdGVtMzI=" fullword wide
		 $s54= "JVVTRVJQUk9GSUxFJVxcQXBwRGF0YVxcTG9jYWxcXFRlbXBcXEFjdGlvbi5iYXQ=" fullword wide
		 $s55= "JVVTRVJQUk9GSUxFJVxcQXBwRGF0YVxcTG9jYWxcXFRlbXBcXFJlbW92ZS5iYXQ=" fullword wide
		 $s56= "Q29uc2VudFByb21wdEJlaGF2aW9yQWRtaW4=" fullword wide
		 $s57= "QVNVTkNCLW5HZHY1NFZkZ2VmNHZEZzY0OThiM3l0Mw==" fullword wide
		 $s58= "vikoserujofafuhazivovejijuwaxu zinige" fullword wide
		 $s59= "Y2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsICUy" fullword wide
		 $s60= "zfezekopupikayocicizojisowa zihebagaponaxo" fullword wide

		 $hex1= {247331303d2022663a}
		 $hex2= {247331313d2022663a}
		 $hex3= {247331323d2022663a}
		 $hex4= {247331333d2022663a}
		 $hex5= {247331343d2022663a}
		 $hex6= {247331353d2022663a}
		 $hex7= {247331363d2022663a}
		 $hex8= {247331373d2022663a}
		 $hex9= {247331383d2022663a}
		 $hex10= {247331393d2022663a}
		 $hex11= {2473313d2022614852}
		 $hex12= {247332303d2022663a}
		 $hex13= {247332313d2022663a}
		 $hex14= {247332323d2022663a}
		 $hex15= {247332333d2022663a}
		 $hex16= {247332343d2022663a}
		 $hex17= {247332353d2022663a}
		 $hex18= {247332363d2022663a}
		 $hex19= {247332373d2022663a}
		 $hex20= {247332383d2022663a}
		 $hex21= {247332393d2022663a}
		 $hex22= {2473323d2022614852}
		 $hex23= {247333303d2022663a}
		 $hex24= {247333313d2022663a}
		 $hex25= {247333323d2022663a}
		 $hex26= {247333333d2022663a}
		 $hex27= {247333343d2022663a}
		 $hex28= {247333353d2022663a}
		 $hex29= {247333363d2022663a}
		 $hex30= {247333373d2022663a}
		 $hex31= {247333383d2022663a}
		 $hex32= {247333393d2022663a}
		 $hex33= {2473333d2022614852}
		 $hex34= {247334303d2022663a}
		 $hex35= {247334313d2022663a}
		 $hex36= {247334323d2022663a}
		 $hex37= {247334333d2022663a}
		 $hex38= {247334343d2022663a}
		 $hex39= {247334353d2022663a}
		 $hex40= {247334363d2022663a}
		 $hex41= {247334373d2022663a}
		 $hex42= {247334383d2022663a}
		 $hex43= {247334393d2022663a}
		 $hex44= {2473343d20225f424c}
		 $hex45= {247335303d20224066}
		 $hex46= {247335313d2022663a}
		 $hex47= {247335323d20226a69}
		 $hex48= {247335333d20224a56}
		 $hex49= {247335343d20224a56}
		 $hex50= {247335353d20224a56}
		 $hex51= {247335363d20225132}
		 $hex52= {247335373d20225156}
		 $hex53= {247335383d20227669}
		 $hex54= {247335393d20225932}
		 $hex55= {2473353d202243663a}
		 $hex56= {247336303d20227a66}
		 $hex57= {2473363d2022657949}
		 $hex58= {2473373d2022663a64}
		 $hex59= {2473383d2022663a64}
		 $hex60= {2473393d2022663a64}

	condition:
		7 of them
}
