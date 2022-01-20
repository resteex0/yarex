
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_20Nov2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_20Nov2013 {
	meta: 
		 description= "CryptoLocker_20Nov2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-19" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "7f9c454a2e016e533e181d53eba113bc"

	strings:

	
 		 $a1= "f:ddvctoolsvc7libsshipatlmfcincludeafxwin1.inl" fullword ascii
		 $a2= "f:ddvctoolsvc7libsshipatlmfcincludeafxwin2.inl" fullword ascii
		 $a3= "f:ddvctoolsvc7libsshipatlmfcsrcmfcauxdata.cpp" fullword ascii

		 $hex1= {2461313d2022663a64}
		 $hex2= {2461323d2022663a64}
		 $hex3= {2461333d2022663a64}

	condition:
		2 of them
}
