
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_DarkVNC 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_DarkVNC {
	meta: 
		 description= "vx_underground2_DarkVNC Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-54-43" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04a90cf2b506cf0bd5307d7b83a3a27c"
		 hash2= "0ce983adc03d11b814c4b6fba6b07e6f"
		 hash3= "2e1f8ba82ccb23aae886dfa4b3fbac59"
		 hash4= "40141dd7e3d58c4fd81ddbb324657b51"
		 hash5= "5c40b21128bca2550a7908241f03c520"
		 hash6= "6655a6560da84b845818e02b3e6cdcb7"
		 hash7= "8a9a5887b53b45b83b4092af19cc81af"
		 hash8= "9121bd6bc0deeb3d1108642cf6075af4"

	strings:

	
 		 $s1= "Wobetesido suvesebuxomelot" fullword wide
		 $a1= "C:budipab20hudizihok_hakoyavugaywizuwixupef-zodojijes.pdb" fullword ascii
		 $a2= "C:tuzaxiyusocokut cubolehakitufoda53him_fuhozugofedwo.pdb" fullword ascii

		 $hex1= {2461313d2022433a62}
		 $hex2= {2461323d2022433a74}
		 $hex3= {2473313d2022576f62}

	condition:
		2 of them
}
