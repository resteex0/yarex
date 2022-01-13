
/*
   YARA Rule Set
   Author: resteex
   Identifier: AtomSilo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_AtomSilo {
	meta: 
		 description= "AtomSilo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_23-59-43" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5559e9f5e1645f8554ea020a29a5a3ee"
		 hash2= "81f01a9c29bae0cfa1ab015738adc5cc"

	strings:

	
 		 $s1= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s2= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s3= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s4= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s5= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s6= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s7= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= ".?AV?$ClonableImpl@VSHA1@CryptoPP@@V?$AlgorithmImpl@V?$IteratedHash@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@VHashTransformation@2@@Cry" fullword ascii
		 $a2= ".?AV?$ClonableImpl@VSHA256@CryptoPP@@V?$AlgorithmImpl@V?$IteratedHash@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@VHashTransformation@2@@C" fullword ascii
		 $a3= ".?AV?$TF_CryptoSystemBase@VPK_Encryptor@CryptoPP@@V?$TF_Base@VRandomizedTrapdoorFunction@CryptoPP@@VPK_EncryptionMessageEncodingMethod@2@@2@@CryptoPP@" fullword ascii
		 $a4= ".?AV?$TF_ObjectImplBase@VTF_SignerBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15" fullword ascii
		 $a5= ".?AV?$TF_ObjectImplBase@VTF_VerifierBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v" fullword ascii
		 $a6= ".?AV?$TF_ObjectImpl@VTF_SignerBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_Sig" fullword ascii
		 $a7= ".?AV?$TF_ObjectImpl@VTF_VerifierBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_S" fullword ascii
		 $a8= ".?AV?$TF_SignatureSchemeBase@VPK_Signer@CryptoPP@@V?$TF_Base@VRandomizedTrapdoorFunctionInverse@CryptoPP@@VPK_SignatureMessageEncodingMethod@2@@2@@Cry" fullword ascii

		 $hex1= {2461313d20222e3f41}
		 $hex2= {2461323d20222e3f41}
		 $hex3= {2461333d20222e3f41}
		 $hex4= {2461343d20222e3f41}
		 $hex5= {2461353d20222e3f41}
		 $hex6= {2461363d20222e3f41}
		 $hex7= {2461373d20222e3f41}
		 $hex8= {2461383d20222e3f41}
		 $hex9= {2473313d2022617069}
		 $hex10= {2473323d2022617069}
		 $hex11= {2473333d2022617069}
		 $hex12= {2473343d2022617069}
		 $hex13= {2473353d2022617069}
		 $hex14= {2473363d2022657874}
		 $hex15= {2473373d2022657874}

	condition:
		1 of them
}
