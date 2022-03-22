
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
		 date = "2022-03-22_14-16-31" 
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

		 $hex1= {31302e30302e393630}
		 $hex2= {31312e30302e393630}
		 $hex3= {3b687474703a2f2f63}
		 $hex4= {687474703a2f2f6372}

	condition:
		2 of them
}
