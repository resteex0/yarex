
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GoziGroup 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GoziGroup {
	meta: 
		 description= "APT_Sample_GoziGroup Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-56-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "531bfea83204df3fab21f07a9751bcb7"
		 hash2= "68c00c7706169601ead8a0383a812525"
		 hash3= "7137532f7c07b66b72b5873a1929db34"
		 hash4= "ead038e42b00e08e4293917e00d40e75"
		 hash5= "f947d58595fc0567fb9bfa3c7f609ebc"

	strings:

	
 		 $s1= "10.00.9600.16428 (winblue_gdr.131013" fullword wide
		 $s2= "11.00.9600.16428 (wr2_df.121013" fullword wide
		 $a1= ";http://crl.comodoca.com/COMODORSACertificationAuthority.crl0q" fullword ascii
		 $a2= "http://crl.starfieldtech.com/repository/sf_issuing_ca-g2.crt0T" fullword ascii

		 $hex1= {2461313d20223b6874}
		 $hex2= {2461323d2022687474}
		 $hex3= {2473313d202231302e}
		 $hex4= {2473323d202231312e}

	condition:
		2 of them
}