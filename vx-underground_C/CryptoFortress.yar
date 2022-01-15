
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoFortress 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoFortress {
	meta: 
		 description= "CryptoFortress Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_23-12-35" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "26f13c4ad8c1ccf81e80a556cf6db0af"
		 hash2= "7551c8026938b4acd149b1551393715f"
		 hash3= "e6dda3e06fd32fc3670d13098f3e22c9"

	strings:

	
 		 $s1= "11.00.9600.16428 (winblue_gdr.131013-1700)" fullword wide
		 $s2= "{8856F961-340A-11D0-A96B-00C04FD705A2}" fullword wide
		 $s3= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s4= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s5= "cf:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s6= "Contact: www.softwareok.de" fullword wide
		 $s7= "_CrtIsValidHeapPointer(pUserData)" fullword wide
		 $s8= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s9= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrclocalref.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s42= "http://www.softwareok.com" fullword wide
		 $s43= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $a1= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword ascii
		 $a2= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword ascii
		 $a3= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword ascii
		 $a4= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword ascii

		 $hex1= {2461313d2022663a64}
		 $hex2= {2461323d2022663a64}
		 $hex3= {2461333d2022663a64}
		 $hex4= {2461343d2022663a64}
		 $hex5= {247331303d2022663a}
		 $hex6= {247331313d2022663a}
		 $hex7= {247331323d2022663a}
		 $hex8= {247331333d2022663a}
		 $hex9= {247331343d2022663a}
		 $hex10= {247331353d2022663a}
		 $hex11= {247331363d2022663a}
		 $hex12= {247331373d2022663a}
		 $hex13= {247331383d2022663a}
		 $hex14= {247331393d2022663a}
		 $hex15= {2473313d202231312e}
		 $hex16= {247332303d2022663a}
		 $hex17= {247332313d2022663a}
		 $hex18= {247332323d2022663a}
		 $hex19= {247332333d2022663a}
		 $hex20= {247332343d2022663a}
		 $hex21= {247332353d2022663a}
		 $hex22= {247332363d2022663a}
		 $hex23= {247332373d2022663a}
		 $hex24= {247332383d2022663a}
		 $hex25= {247332393d2022663a}
		 $hex26= {2473323d20227b3838}
		 $hex27= {247333303d2022663a}
		 $hex28= {247333313d2022663a}
		 $hex29= {247333323d2022663a}
		 $hex30= {247333333d2022663a}
		 $hex31= {247333343d2022663a}
		 $hex32= {247333353d2022663a}
		 $hex33= {247333363d2022663a}
		 $hex34= {247333373d2022663a}
		 $hex35= {247333383d2022663a}
		 $hex36= {247333393d2022663a}
		 $hex37= {2473333d202242663a}
		 $hex38= {247334303d2022663a}
		 $hex39= {247334313d2022663a}
		 $hex40= {247334323d20226874}
		 $hex41= {247334333d20226973}
		 $hex42= {2473343d20225f424c}
		 $hex43= {2473353d202263663a}
		 $hex44= {2473363d2022436f6e}
		 $hex45= {2473373d20225f4372}
		 $hex46= {2473383d2022663a64}
		 $hex47= {2473393d2022663a64}

	condition:
		31 of them
}
