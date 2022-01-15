
/*
   YARA Rule Set
   Author: resteex
   Identifier: Poseidon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Poseidon {
	meta: 
		 description= "Poseidon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-16-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2145d54164c32faba44164ea7c9add33"
		 hash2= "2d3432f1a866db2424f1192ca9edf0d8"
		 hash3= "387113b0f63bcd56a4aae7ec08e9936f"
		 hash4= "3fb907a9612019e72aed25ab2e18607a"
		 hash5= "4e7de5020ec9b8957761c9b7277ae0f1"
		 hash6= "4fd2bb5f54a0c8095fd6542eb9034b44"
		 hash7= "52cd2524c6f0e569127d6486e278bad5"
		 hash8= "5b160c024e10ab184288c6aa7eaf0ad0"
		 hash9= "63e5fa6cb5305b00a8146d0865d63b17"
		 hash10= "6ab8f3fa3e8c80a7cccd4a264e3cb0d5"
		 hash11= "79c4c03a6662b31d47a957bb41d049ca"
		 hash12= "a316dcbae71721527033f57c85cdf503"
		 hash13= "a586db30ab21a02eee9e8ab2ebe8a2b5"
		 hash14= "fba75377b29fbaf70d9bbee37a96310c"

	strings:

	
 		 $s1= "B8B4B0B,B B" fullword wide
		 $s2= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s3= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s4= "_CrtIsValidHeapPointer(pUserData)" fullword wide
		 $s5= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s6= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s7= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s8= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s9= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrcfopen.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrcfwrite.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrclocalref.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrclseek.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcmbsnbcmp.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrcmbsnbicm.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcmbsstr.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrc_open.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcopen.c" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrcprintf.c" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrcread.c" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrcsetmode.c" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrc_sftbuf.c" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrcsprintf.c" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s50= "f:ddvctoolscrt_bldself_x86crtsrcstrnicmp.c" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s52= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s53= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s54= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s55= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s56= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s57= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s58= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s59= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s60= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s61= "http://www.actualtools.com" fullword wide
		 $s62= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $s63= "SCSI_ATA_TRANSLATION (SAT)" fullword wide
		 $a1= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword ascii
		 $a2= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword ascii
		 $a3= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword ascii
		 $a4= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword ascii
		 $a5= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword ascii
		 $a6= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword ascii
		 $a7= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword ascii
		 $a8= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword ascii
		 $a9= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword ascii

		 $hex1= {2461313d2022663a64}
		 $hex2= {2461323d2022663a64}
		 $hex3= {2461333d2022663a64}
		 $hex4= {2461343d2022663a64}
		 $hex5= {2461353d2022663a64}
		 $hex6= {2461363d2022663a64}
		 $hex7= {2461373d2022663a64}
		 $hex8= {2461383d2022663a64}
		 $hex9= {2461393d2022663a64}
		 $hex10= {247331303d2022663a}
		 $hex11= {247331313d2022663a}
		 $hex12= {247331323d2022663a}
		 $hex13= {247331333d2022663a}
		 $hex14= {247331343d2022663a}
		 $hex15= {247331353d2022663a}
		 $hex16= {247331363d2022663a}
		 $hex17= {247331373d2022663a}
		 $hex18= {247331383d2022663a}
		 $hex19= {247331393d2022663a}
		 $hex20= {2473313d2022423842}
		 $hex21= {247332303d2022663a}
		 $hex22= {247332313d2022663a}
		 $hex23= {247332323d2022663a}
		 $hex24= {247332333d2022663a}
		 $hex25= {247332343d2022663a}
		 $hex26= {247332353d2022663a}
		 $hex27= {247332363d2022663a}
		 $hex28= {247332373d2022663a}
		 $hex29= {247332383d2022663a}
		 $hex30= {247332393d2022663a}
		 $hex31= {2473323d202242663a}
		 $hex32= {247333303d2022663a}
		 $hex33= {247333313d2022663a}
		 $hex34= {247333323d2022663a}
		 $hex35= {247333333d2022663a}
		 $hex36= {247333343d2022663a}
		 $hex37= {247333353d2022663a}
		 $hex38= {247333363d2022663a}
		 $hex39= {247333373d2022663a}
		 $hex40= {247333383d2022663a}
		 $hex41= {247333393d2022663a}
		 $hex42= {2473333d20225f424c}
		 $hex43= {247334303d2022663a}
		 $hex44= {247334313d2022663a}
		 $hex45= {247334323d2022663a}
		 $hex46= {247334333d2022663a}
		 $hex47= {247334343d2022663a}
		 $hex48= {247334353d2022663a}
		 $hex49= {247334363d2022663a}
		 $hex50= {247334373d2022663a}
		 $hex51= {247334383d2022663a}
		 $hex52= {247334393d2022663a}
		 $hex53= {2473343d20225f4372}
		 $hex54= {247335303d2022663a}
		 $hex55= {247335313d2022663a}
		 $hex56= {247335323d2022663a}
		 $hex57= {247335333d2022663a}
		 $hex58= {247335343d2022663a}
		 $hex59= {247335353d2022663a}
		 $hex60= {247335363d2022663a}
		 $hex61= {247335373d2022663a}
		 $hex62= {247335383d2022663a}
		 $hex63= {247335393d2022663a}
		 $hex64= {2473353d2022663a64}
		 $hex65= {247336303d2022663a}
		 $hex66= {247336313d20226874}
		 $hex67= {247336323d20226973}
		 $hex68= {247336333d20225343}
		 $hex69= {2473363d2022663a64}
		 $hex70= {2473373d2022663a64}
		 $hex71= {2473383d2022663a64}
		 $hex72= {2473393d2022663a64}

	condition:
		48 of them
}
