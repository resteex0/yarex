
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_ZeusBankingVersion_26Nov2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_ZeusBankingVersion_26Nov2013 {
	meta: 
		 description= "theZoo_ZeusBankingVersion_26Nov2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-20" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ea039a854d20d7734c5add48f1a51c34"

	strings:

	
 		 $a1= "DungBadebankBangGelthoboCocaBozotsksWheyVaryShoghoseNipsCadisi" fullword ascii
		 $a2= "SlabKitsSlayseptPfftjiffSabsdeskOafsNowtMemsKirnKepiMiffDunt" fullword ascii

		 $hex1= {2461313d202244756e}
		 $hex2= {2461323d2022536c61}

	condition:
		1 of them
}
