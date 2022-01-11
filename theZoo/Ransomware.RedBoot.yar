
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_RedBoot 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_RedBoot {
	meta: 
		 description= "Ransomware_RedBoot Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-28-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "e0340f456f76993fc047bc715dfdae6a"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "VS_VERSION_INFO" fullword wide
		 $a1= "C]]]]]]]]]]]]]]]]]]]]]]]]]]]]>" fullword ascii
		 $a2= "C_]a`a]]ac]a]a]a]a`aaaac]]>" fullword ascii
		 $a3= "C]]HIIIIIIIIIIH]aLLLLLLa" fullword ascii
		 $a4= "C]]I****,+...-IQ`LLLLLLca" fullword ascii
		 $a5= "DKLKKKLKKLKKKKLKLKLKLMKKKKLKL>" fullword ascii
		 $a6= ">]FIIIIIIIIIIFQ`LLLLLL_TRRR]>" fullword ascii
		 $a7= ">]]I11255880::IQ`````aac" fullword ascii
		 $a8= ">_]I66;;80-&&7IQ`LLLLLL`" fullword ascii
		 $a9= ">>>>>>>>>>>>>>>>>>>>>>>>>>>>J" fullword ascii
		 $a10= "J>>>>>>>>>>>>>>>>ACA>>>>>>>>>G" fullword ascii
		 $a11= "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj" fullword ascii
		 $a12= "jqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj" fullword ascii
		 $a13= "jurrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrruj" fullword ascii
		 $a14= "juuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" fullword ascii
		 $a15= "juuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuj" fullword ascii
		 $a16= "knnnnnnnnnnnnnnnnnkv~z~zzzzzzzzxzxxxx" fullword ascii
		 $a17= ">_]]QQQQQQRQRQQQ_``__STTRRRR]>" fullword ascii
		 $a18= ">S]]]]]]]]]]]]]]]]]]]]]]]]]]]>" fullword ascii
		 $a19= ">S]]a]aaa]]]]]]a```____R_R_U]>" fullword ascii
		 $a20= "STUVWXYZ[]^_`abcdefghijk" fullword ascii
		 $a21= "vvvvvvvvvvvvvvzvvvv~zz~zzzzzwzwzvzvz" fullword ascii

		 $hex1= {246131303d20224a3e}
		 $hex2= {246131313d20226a6a}
		 $hex3= {246131323d20226a71}
		 $hex4= {246131333d20226a75}
		 $hex5= {246131343d20226a75}
		 $hex6= {246131353d20226a75}
		 $hex7= {246131363d20226b6e}
		 $hex8= {246131373d20223e5f}
		 $hex9= {246131383d20223e53}
		 $hex10= {246131393d20223e53}
		 $hex11= {2461313d2022435d5d}
		 $hex12= {246132303d20225354}
		 $hex13= {246132313d20227676}
		 $hex14= {2461323d2022435f5d}
		 $hex15= {2461333d2022435d5d}
		 $hex16= {2461343d2022435d5d}
		 $hex17= {2461353d2022444b4c}
		 $hex18= {2461363d20223e5d46}
		 $hex19= {2461373d20223e5d5d}
		 $hex20= {2461383d20223e5f5d}
		 $hex21= {2461393d20223e3e3e}
		 $hex22= {2473313d202246696c}
		 $hex23= {2473323d202256535f}

	condition:
		2 of them
}
