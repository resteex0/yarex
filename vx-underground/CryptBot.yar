
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_CryptBot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_CryptBot {
	meta: 
		 description= "vx_underground2_CryptBot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "28032b139b5cd56d34239af205c7b8d4"
		 hash2= "2fa9185ceeb1d25e8bde77a4cf3f70d4"
		 hash3= "979d1d97ef97c7ae5737a88e87757ec4"
		 hash4= "b6c970046cdf3da19838d0114c993372"
		 hash5= "bcd4db4df2b58bfb92a5c7e7395abd99"
		 hash6= "dc2faa416f839bf688d9ff10efacbb30"
		 hash7= "dce4b1e6a5f9b6d836913013606371ce"
		 hash8= "deb1c7b83dfe3a38de11c81c355b862c"

	strings:

	
 		 $s1= "Bf:ddvctoolscrt_bldself_x86crtsrcdbgrpt.c" fullword wide
		 $s2= "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword wide
		 $s3= "_CrtIsValidHeapPointer(pUserData)" fullword wide
		 $s4= "f:ddvctoolscrt_bldself_x86crtprebuildconvcfout.c" fullword wide
		 $s5= "f:ddvctoolscrt_bldself_x86crtprebuildconvcvt.c" fullword wide
		 $s6= "f:ddvctoolscrt_bldself_x86crtprebuildconvx10fout.c" fullword wide
		 $s7= "f:ddvctoolscrt_bldself_x86crtprebuildehtypname.cpp" fullword wide
		 $s8= "f:ddvctoolscrt_bldself_x86crtprebuildtrancontrlfp.c" fullword wide
		 $s9= "f:ddvctoolscrt_bldself_x86crtsrcclose.c" fullword wide
		 $s10= "f:ddvctoolscrt_bldself_x86crtsrccommit.c" fullword wide
		 $s11= "f:ddvctoolscrt_bldself_x86crtsrccrt0msg.c" fullword wide
		 $s12= "f:ddvctoolscrt_bldself_x86crtsrcdbgdel.cpp" fullword wide
		 $s13= "f:ddvctoolscrt_bldself_x86crtsrcdbgheap.c" fullword wide
		 $s14= "f:ddvctoolscrt_bldself_x86crtsrcdbgrptt.c" fullword wide
		 $s15= "f:ddvctoolscrt_bldself_x86crtsrcerrmode.c" fullword wide
		 $s16= "f:ddvctoolscrt_bldself_x86crtsrcexpand.c" fullword wide
		 $s17= "f:ddvctoolscrt_bldself_x86crtsrcfclose.c" fullword wide
		 $s18= "f:ddvctoolscrt_bldself_x86crtsrcfeoferr.c" fullword wide
		 $s19= "f:ddvctoolscrt_bldself_x86crtsrc_filbuf.c" fullword wide
		 $s20= "f:ddvctoolscrt_bldself_x86crtsrcfileno.c" fullword wide
		 $s21= "f:ddvctoolscrt_bldself_x86crtsrc_flsbuf.c" fullword wide
		 $s22= "f:ddvctoolscrt_bldself_x86crtsrc_fptostr.c" fullword wide
		 $s23= "f:ddvctoolscrt_bldself_x86crtsrc_freebuf.c" fullword wide
		 $s24= "f:ddvctoolscrt_bldself_x86crtsrc_getbuf.c" fullword wide
		 $s25= "f:ddvctoolscrt_bldself_x86crtsrcinput.c" fullword wide
		 $s26= "f:ddvctoolscrt_bldself_x86crtsrcintelfp8.c" fullword wide
		 $s27= "f:ddvctoolscrt_bldself_x86crtsrcisatty.c" fullword wide
		 $s28= "f:ddvctoolscrt_bldself_x86crtsrcisctype.c" fullword wide
		 $s29= "f:ddvctoolscrt_bldself_x86crtsrclseeki64.c" fullword wide
		 $s30= "f:ddvctoolscrt_bldself_x86crtsrcmalloc.h" fullword wide
		 $s31= "f:ddvctoolscrt_bldself_x86crtsrcmbstowcs.c" fullword wide
		 $s32= "f:ddvctoolscrt_bldself_x86crtsrcmbtowc.c" fullword wide
		 $s33= "f:ddvctoolscrt_bldself_x86crtsrcmemcpy_s.c" fullword wide
		 $s34= "f:ddvctoolscrt_bldself_x86crtsrcosfinfo.c" fullword wide
		 $s35= "f:ddvctoolscrt_bldself_x86crtsrcoutput.c" fullword wide
		 $s36= "f:ddvctoolscrt_bldself_x86crtsrcprintf.c" fullword wide
		 $s37= "f:ddvctoolscrt_bldself_x86crtsrcread.c" fullword wide
		 $s38= "f:ddvctoolscrt_bldself_x86crtsrcscanf.c" fullword wide
		 $s39= "f:ddvctoolscrt_bldself_x86crtsrcsetlocal.c" fullword wide
		 $s40= "f:ddvctoolscrt_bldself_x86crtsrc_sftbuf.c" fullword wide
		 $s41= "f:ddvctoolscrt_bldself_x86crtsrcstdenvp.c" fullword wide
		 $s42= "f:ddvctoolscrt_bldself_x86crtsrcstrtol.c" fullword wide
		 $s43= "f:ddvctoolscrt_bldself_x86crtsrcstrtoq.c" fullword wide
		 $s44= "f:ddvctoolscrt_bldself_x86crtsrctcscat_s.inl" fullword wide
		 $s45= "f:ddvctoolscrt_bldself_x86crtsrctcscpy_s.inl" fullword wide
		 $s46= "f:ddvctoolscrt_bldself_x86crtsrctcsncpy_s.inl" fullword wide
		 $s47= "f:ddvctoolscrt_bldself_x86crtsrcungetc_nolock.inl" fullword wide
		 $s48= "f:ddvctoolscrt_bldself_x86crtsrcvsprintf.c" fullword wide
		 $s49= "f:ddvctoolscrt_bldself_x86crtsrcvswprint.c" fullword wide
		 $s50= "f:ddvctoolscrt_bldself_x86crtsrcwcstombs.c" fullword wide
		 $s51= "f:ddvctoolscrt_bldself_x86crtsrcwctomb.c" fullword wide
		 $s52= "f:ddvctoolscrt_bldself_x86crtsrcwinsig.c" fullword wide
		 $s53= "f:ddvctoolscrt_bldself_x86crtsrcwrite.c" fullword wide
		 $s54= "f:ddvctoolscrt_bldself_x86crtsrcxtoa.c" fullword wide
		 $s55= "gekupamasusa tozidehiyuyafahepahuxocarebayay" fullword wide
		 $s56= "isleadbyte(_dbcsBuffer(fh))" fullword wide
		 $s57= "levihufanogisojinasitogatopacaxuhozuwehu" fullword wide
		 $s58= "=(*pnFloatStrSz)" fullword wide
		 $s59= "riyovohuyujujemukupicivajodo" fullword wide
		 $s60= "sarihonicuzayuhoropitusuzonu" fullword wide
		 $s61= "Sazoluyelofop dukinobekakikur" fullword wide
		 $s62= "verosiwagasedavijozegulozakeawkutafojajocoxelufayifelif" fullword wide
		 $s63= "Wobetesido suvesebuxomelot" fullword wide
		 $a1= "C:yigewinepihigsusazuvzojefuxgizuhoponagengediyome35 fi.pdb" fullword ascii

		 $hex1= {2461313d2022433a79}
		 $hex2= {247331303d2022663a}
		 $hex3= {247331313d2022663a}
		 $hex4= {247331323d2022663a}
		 $hex5= {247331333d2022663a}
		 $hex6= {247331343d2022663a}
		 $hex7= {247331353d2022663a}
		 $hex8= {247331363d2022663a}
		 $hex9= {247331373d2022663a}
		 $hex10= {247331383d2022663a}
		 $hex11= {247331393d2022663a}
		 $hex12= {2473313d202242663a}
		 $hex13= {247332303d2022663a}
		 $hex14= {247332313d2022663a}
		 $hex15= {247332323d2022663a}
		 $hex16= {247332333d2022663a}
		 $hex17= {247332343d2022663a}
		 $hex18= {247332353d2022663a}
		 $hex19= {247332363d2022663a}
		 $hex20= {247332373d2022663a}
		 $hex21= {247332383d2022663a}
		 $hex22= {247332393d2022663a}
		 $hex23= {2473323d20225f424c}
		 $hex24= {247333303d2022663a}
		 $hex25= {247333313d2022663a}
		 $hex26= {247333323d2022663a}
		 $hex27= {247333333d2022663a}
		 $hex28= {247333343d2022663a}
		 $hex29= {247333353d2022663a}
		 $hex30= {247333363d2022663a}
		 $hex31= {247333373d2022663a}
		 $hex32= {247333383d2022663a}
		 $hex33= {247333393d2022663a}
		 $hex34= {2473333d20225f4372}
		 $hex35= {247334303d2022663a}
		 $hex36= {247334313d2022663a}
		 $hex37= {247334323d2022663a}
		 $hex38= {247334333d2022663a}
		 $hex39= {247334343d2022663a}
		 $hex40= {247334353d2022663a}
		 $hex41= {247334363d2022663a}
		 $hex42= {247334373d2022663a}
		 $hex43= {247334383d2022663a}
		 $hex44= {247334393d2022663a}
		 $hex45= {2473343d2022663a64}
		 $hex46= {247335303d2022663a}
		 $hex47= {247335313d2022663a}
		 $hex48= {247335323d2022663a}
		 $hex49= {247335333d2022663a}
		 $hex50= {247335343d2022663a}
		 $hex51= {247335353d20226765}
		 $hex52= {247335363d20226973}
		 $hex53= {247335373d20226c65}
		 $hex54= {247335383d20223d28}
		 $hex55= {247335393d20227269}
		 $hex56= {2473353d2022663a64}
		 $hex57= {247336303d20227361}
		 $hex58= {247336313d20225361}
		 $hex59= {247336323d20227665}
		 $hex60= {247336333d2022576f}
		 $hex61= {2473363d2022663a64}
		 $hex62= {2473373d2022663a64}
		 $hex63= {2473383d2022663a64}
		 $hex64= {2473393d2022663a64}

	condition:
		42 of them
}
