
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_VikingHorde 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_VikingHorde {
	meta: 
		 description= "Android_VikingHorde Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "390e66ffaccaa557a8d5c43c8f3a20a9"

	strings:

	
 		 $s1= ">@@3" fullword wide
		 $s2= ";6/(%%).4663/+))+.1331/,++,.0110/-,*& " fullword wide
		 $s3= "6%/(-%'7RH.&;RYSBGlV]cagjuiiZdWS_oxtq^bt" fullword wide
		 $s4= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword wide
		 $s5= "8EKLVadO@LF;3*':G>54GVckkwwxupd" fullword wide
		 $s6= ";96312469:98643356788761" fullword wide
		 $s7= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword wide
		 $s8= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword wide
		 $s9= "BFJGRV[LXXAEG`fj[YbvsbuymfjrzujZCX`ZDBIZaS=?-'" fullword wide
		 $s10= "+'.;CCBFFUFPKE6:HO_fmrmmob`_tidZOPQABJMFHJDF4''" fullword wide
		 $s11= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword wide
		 $s12= ";@HLNJNTQG62" fullword wide
		 $s13= "':LWXO@2)->NURF7,&(1;EJHBAFOX_`UNIHJPUY?" fullword wide
		 $s14= "o]OIMYgrwtk`WSVelomhaY[^dhjifb_]^`cegfdb`W " fullword wide
		 $s15= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword wide
		 $s16= "wj_Z]dnwzyskebcgmrutplhffilpqqoljhijlnoonlkjn" fullword wide
		 $a1= "!896=:G>I[IfSXM[\\WOqRdTaTw]hMl>mHb=_IW@N9V:b-^5P" fullword ascii
		 $a2= ";96312469:98643356788761" fullword ascii
		 $a3= ">?AABCEGIKMNPQRTUWY[^`acdfgikmoprsuwyz|~" fullword ascii
		 $a4= "AHNPOJE@>@CGKLKHECABDFHIIGE:" fullword ascii
		 $a5= "DD?6,'&*18==:5/,+-1699741/./24665420002355432111234432-%" fullword ascii
		 $a6= "t_LBCN_mvul`TNNT^gllg`YTTX^cggd_[YXZ^accb_][[^`aa`_]`|" fullword ascii

		 $hex1= {2461313d2022213839}
		 $hex2= {2461323d20223b3936}
		 $hex3= {2461333d20223e3f41}
		 $hex4= {2461343d202241484e}
		 $hex5= {2461353d202244443f}
		 $hex6= {2461363d2022745f4c}
		 $hex7= {247331303d20222b27}
		 $hex8= {247331313d20224444}
		 $hex9= {247331323d20223b40}
		 $hex10= {247331333d2022273a}
		 $hex11= {247331343d20226f5d}
		 $hex12= {247331353d2022745f}
		 $hex13= {247331363d2022776a}
		 $hex14= {2473313d20223e4040}
		 $hex15= {2473323d20223b362f}
		 $hex16= {2473333d202236252f}
		 $hex17= {2473343d2022213839}
		 $hex18= {2473353d202238454b}
		 $hex19= {2473363d20223b3936}
		 $hex20= {2473373d20223e3f41}
		 $hex21= {2473383d202241484e}
		 $hex22= {2473393d202242464a}

	condition:
		2 of them
}
