
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Ransomeware_WannaCryDLL_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Ransomeware_WannaCryDLL_bin {
	meta: 
		 description= "APT_Sample_Ransomeware_WannaCryDLL_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-25-03" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "30fe2f9a048d7a734c8d9233f64810ba"

	strings:

	
 		 $s1= "\\172.16.99.5IPC$" fullword wide
		 $s2= "\\192.168.56.20IPC$" fullword wide

		 $hex1= {31??37??32??2e??31??36??2e??39??39??2e??35??49??50??43??24??0a??}
		 $hex2= {31??39??32??2e??31??36??38??2e??35??36??2e??32??30??49??50??43??24??0a??}

	condition:
		2 of them
}
