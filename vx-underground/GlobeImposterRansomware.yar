
/*
   YARA Rule Set
   Author: resteex
   Identifier: GlobeImposterRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_GlobeImposterRansomware {
	meta: 
		 description= "GlobeImposterRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-04-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "336c536090d2612d7de2907568011887"
		 hash2= "5c0d16c91f9096b6d402ce5ce0a8d27f"

	strings:

	
 		 $s1= "__~___d_e__e___wa_m_wg___ata__a}__z_wb_}a__wwn__w_g_" fullword wide
		 $s2= "dwt_qa_pbwebes_d___bwq_b___b" fullword wide
		 $s3= "WinForms_RecursiveFormCreate" fullword wide
		 $s4= "WinForms_SeeInnerException" fullword wide
		 $a1= "__~___d_e__e___wa_m_wg___ata__a}__z_wb_}a__wwn__w_g_" fullword ascii

		 $hex1= {2461313d20225f5f7e}
		 $hex2= {2473313d20225f5f7e}
		 $hex3= {2473323d2022647774}
		 $hex4= {2473333d202257696e}
		 $hex5= {2473343d202257696e}

	condition:
		3 of them
}
