
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Zeus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Zeus {
	meta: 
		 description= "vx_underground2_Zeus Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-18-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0d83a54f6bb735aa81496e24932f448c"
		 hash2= "13c909eaace915f8b48d39846ce23142"
		 hash3= "177e77d48bdf6424eaf0bbbff2905236"
		 hash4= "192604735374ec0a4866a8c577ad88c4"
		 hash5= "1c2b60fca3318323b8c81db952057b76"
		 hash6= "2ab252c9b35bb25faabb4312f5df87ec"
		 hash7= "2c0244c28036f9cb5f9a703c8b329f2f"
		 hash8= "2c1aaa16883b9ba5779a6bfe3415392c"
		 hash9= "32eb917be0bb13f9ab91246a9c98478d"
		 hash10= "3875000b4efead5484b9b844d5948089"
		 hash11= "39a9900ce617dac1cb0a204f9aadc533"
		 hash12= "3dbadcf0df7f1f3e160998b9082df043"
		 hash13= "46e86d95e0ebb61e28d58e58d8093247"
		 hash14= "48ddf433e490326f82dd3fc2893f6085"
		 hash15= "493b3700a1ac3b5b872bf2a516bcb701"
		 hash16= "597cd9de5c897171900a1dbb99b3eda5"
		 hash17= "5ce8fc3cf9e0630c5722d679e528ec6b"
		 hash18= "637efca1d9b90a4c09e60fea58982ed8"
		 hash19= "ad87bd90a45109cac2eb704bfe71ee2a"
		 hash20= "bce5a9b056dd24fdf576b19683cbfae4"
		 hash21= "c0bff76c3057d7b028d1d870e9585461"
		 hash22= "d3b07384d113edec49eaa6238ad5ff00"
		 hash23= "dad3b507b3519774672e6221a254f560"
		 hash24= "e7999f70e4c15eaec90c3df629de662c"
		 hash25= "fcf5d8a49af306f35cfdf637bbaebcae"

	strings:

	
 		 $s1= "{04389C9D-BF5E-825A-5EF5-91F6312971C1}" fullword wide
		 $s2= "{4E381C9C-9145-4E61-BCDB-0AF99E661E6A}" fullword wide
		 $s3= "{617C2E8D-FDDA-4619-FB6F-CF2CBF8F070A}" fullword wide
		 $s4= "{729A5DE2-30AB-91AB-7D88-B6C93CCA69D8}" fullword wide
		 $s5= ":bf32d3b0b662ef49.exe.Config" fullword wide
		 $s6= "bf32d3b0b662ef49.exe.Manifest" fullword wide
		 $s7= "?C:bf32d3b0b662ef49.exe" fullword wide
		 $s8= "??C:bf32d3b0b662ef49.exe.Config" fullword wide
		 $s9= "??C:bf32d3b0b662ef49.exe.Manifest" fullword wide
		 $s10= "C:UsersJohnAppDataRoaming" fullword wide
		 $s11= "DOCUME~1URNXYMAVLOCALS~1Temp" fullword wide
		 $s12= "EGISTRYUSERS-1-5-21-2052111302-484763869-725345543-1003" fullword wide
		 $s13= "ftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword wide
		 $s14= "SOFTWAREMicrosoftOzohti" fullword wide

		 $hex1= {247331303d2022433a}
		 $hex2= {247331313d2022444f}
		 $hex3= {247331323d20224547}
		 $hex4= {247331333d20226674}
		 $hex5= {247331343d2022534f}
		 $hex6= {2473313d20227b3034}
		 $hex7= {2473323d20227b3445}
		 $hex8= {2473333d20227b3631}
		 $hex9= {2473343d20227b3732}
		 $hex10= {2473353d20223a6266}
		 $hex11= {2473363d2022626633}
		 $hex12= {2473373d20223f433a}
		 $hex13= {2473383d20223f3f43}
		 $hex14= {2473393d20223f3f43}

	condition:
		9 of them
}
