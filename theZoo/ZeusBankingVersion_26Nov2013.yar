
/*
   YARA Rule Set
   Author: resteex
   Identifier: ZeusBankingVersion_26Nov2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ZeusBankingVersion_26Nov2013 {
	meta: 
		 description= "ZeusBankingVersion_26Nov2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-45-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ea039a854d20d7734c5add48f1a51c34"

	strings:

	
 		 $a1= "AsksmaceaglyBubuPulsKaifTeasMistPeelGhisPrimChaoLyreroeno" fullword ascii
		 $a2= "DungBadebankBangGelthoboCocaBozotsksWheyVaryShoghoseNipsCadisi" fullword ascii
		 $a3= "ExitRollWoodGumsgamaSloerevsWussletssinkYearZitiryesHypout" fullword ascii
		 $a4= "IzararfsFlamWostAirsconsMouefemelallPoretweeSacsOxidMinx" fullword ascii
		 $a5= "MeanOrrabirogirtWorkGawpSassPirnVinoLotaPledEidefe" fullword ascii
		 $a6= "SlabKitsSlayseptPfftjiffSabsdeskOafsNowtMemsKirnKepiMiffDunt" fullword ascii
		 $a7= "SuitplieGunsMaidBaitFeusJiaotodycolyAlbsLuneToyspe" fullword ascii
		 $a8= "ZetaBeduPirnhipsjailTingSrisTeleAposhuskNameHoerflagemuwo" fullword ascii

		 $hex1= {2461313d202241736b}
		 $hex2= {2461323d202244756e}
		 $hex3= {2461333d2022457869}
		 $hex4= {2461343d2022497a61}
		 $hex5= {2461353d20224d6561}
		 $hex6= {2461363d2022536c61}
		 $hex7= {2461373d2022537569}
		 $hex8= {2461383d20225a6574}

	condition:
		5 of them
}
