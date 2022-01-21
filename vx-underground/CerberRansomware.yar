
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_CerberRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_CerberRansomware {
	meta: 
		 description= "vx_underground2_CerberRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-49" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "ae99e6a451bc53830be799379f5c1104"
		 hash2= "e278d253cae5bc102190e33f99596966"

	strings:

	
 		 $s1= "D:boost_1_64_0boost/filesystem/operations.hpp" fullword wide
		 $s2= "D:boost_1_64_0boost/smart_ptr/shared_ptr.hpp" fullword wide
		 $a1= ".?AV?$VariableKeyLength@$0BA@$0BA@$0CA@$07$03$0A@@CryptoPP@@" fullword ascii
		 $a2= "N8CryptoPP12AbstractRingINS_7IntegerEE20MultiplicativeGroupTE" fullword ascii
		 $a3= "N8CryptoPP17DL_PrivateKey_GFPINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a4= "N8CryptoPP17DL_PrivateKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a5= "N8CryptoPP27AlgorithmParametersTemplateIPKNS_13PrimeSelectorEEE" fullword ascii
		 $a6= "N8CryptoPP30PK_FixedLengthCryptoSystemImplINS_12PK_DecryptorEEE" fullword ascii
		 $a7= "N8CryptoPP30PK_FixedLengthCryptoSystemImplINS_12PK_EncryptorEEE" fullword ascii
		 $a8= "N8CryptoPP32DL_ElgamalLikeSignatureAlgorithmINS_8ECPPointEEE" fullword ascii
		 $a9= "N8CryptoPP32DL_ElgamalLikeSignatureAlgorithmINS_9EC2NPointEEE" fullword ascii
		 $a10= "PN8CryptoPP16DL_PublicKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii
		 $a11= "PN8CryptoPP17DL_PrivateKeyImplINS_22DL_GroupParameters_DSAEEE" fullword ascii

		 $hex1= {246131303d2022504e}
		 $hex2= {246131313d2022504e}
		 $hex3= {2461313d20222e3f41}
		 $hex4= {2461323d20224e3843}
		 $hex5= {2461333d20224e3843}
		 $hex6= {2461343d20224e3843}
		 $hex7= {2461353d20224e3843}
		 $hex8= {2461363d20224e3843}
		 $hex9= {2461373d20224e3843}
		 $hex10= {2461383d20224e3843}
		 $hex11= {2461393d20224e3843}
		 $hex12= {2473313d2022443a62}
		 $hex13= {2473323d2022443a62}

	condition:
		8 of them
}
