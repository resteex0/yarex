
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
		 date = "2022-01-12_19-49-01" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5559e9f5e1645f8554ea020a29a5a3ee"
		 hash2= "81f01a9c29bae0cfa1ab015738adc5cc"

	strings:

	
 		 $s1= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s5= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s6= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s7= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s8= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s9= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0.dll" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s17= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s18= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $a1= ".?AV?$AlgorithmImpl@V?$IteratedHash@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@VHashTra" fullword ascii
		 $a2= ".?AV?$AlgorithmImpl@V?$SimpleKeyingInterfaceImpl@V?$TwoBases@VBlockCipher@CryptoPP@@URijndael_Info@2" fullword ascii
		 $a3= ".?AV?$AlgorithmImpl@VTF_DecryptorBase@CryptoPP@@V?$TF_ES@URSA@CryptoPP@@V?$OAEP@VSHA1@CryptoPP@@VP13" fullword ascii
		 $a4= ".?AV?$AlgorithmImpl@VTF_EncryptorBase@CryptoPP@@V?$TF_ES@URSA@CryptoPP@@V?$OAEP@VSHA1@CryptoPP@@VP13" fullword ascii
		 $a5= ".?AV?$AlgorithmImpl@VTF_SignerBase@CryptoPP@@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@2@@Crypto" fullword ascii
		 $a6= ".?AV?$AlgorithmImpl@VTF_VerifierBase@CryptoPP@@V?$TF_SS@URSA@CryptoPP@@UPKCS1v15@2@VSHA1@2@H@2@@Cryp" fullword ascii
		 $a7= ".?AV?$ClonableImpl@VSHA1@CryptoPP@@V?$AlgorithmImpl@V?$IteratedHash@IU?$EnumToType@W4ByteOrder@Crypt" fullword ascii
		 $a8= ".?AV?$ClonableImpl@VSHA256@CryptoPP@@V?$AlgorithmImpl@V?$IteratedHash@IU?$EnumToType@W4ByteOrder@Cry" fullword ascii
		 $a9= ".?AV?$IteratedHash@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@VHashTransformation@2@@Cr" fullword ascii
		 $a10= ".?AV?$IteratedHashWithStaticTransform@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@$0BE@V" fullword ascii
		 $a11= ".?AV?$IteratedHashWithStaticTransform@IU?$EnumToType@W4ByteOrder@CryptoPP@@$00@CryptoPP@@$0EA@$0CA@V" fullword ascii
		 $a12= ".?AV?$SimpleKeyingInterfaceImpl@V?$TwoBases@VBlockCipher@CryptoPP@@URijndael_Info@2@@CryptoPP@@V12@@" fullword ascii
		 $a13= ".?AV?$TF_Base@VRandomizedTrapdoorFunction@CryptoPP@@VPK_EncryptionMessageEncodingMethod@2@@CryptoPP@" fullword ascii
		 $a14= ".?AV?$TF_Base@VRandomizedTrapdoorFunctionInverse@CryptoPP@@VPK_SignatureMessageEncodingMethod@2@@Cry" fullword ascii
		 $a15= ".?AV?$TF_CryptoSystemBase@VPK_Decryptor@CryptoPP@@V?$TF_Base@VTrapdoorFunctionInverse@CryptoPP@@VPK_" fullword ascii
		 $a16= ".?AV?$TF_CryptoSystemBase@VPK_Encryptor@CryptoPP@@V?$TF_Base@VRandomizedTrapdoorFunction@CryptoPP@@V" fullword ascii
		 $a17= ".?AV?$TF_ObjectImplBase@VTF_SignerBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP" fullword ascii
		 $a18= ".?AV?$TF_ObjectImplBase@VTF_VerifierBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@Crypto" fullword ascii
		 $a19= ".?AV?$TF_ObjectImpl@VTF_SignerBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@UP" fullword ascii
		 $a20= ".?AV?$TF_ObjectImpl@VTF_VerifierBase@CryptoPP@@U?$TF_SignatureSchemeOptions@V?$TF_SS@URSA@CryptoPP@@" fullword ascii
		 $a21= ".?AV?$TF_SignatureSchemeBase@VPK_Signer@CryptoPP@@V?$TF_Base@VRandomizedTrapdoorFunctionInverse@Cryp" fullword ascii
		 $a22= ".?AV?$TF_SignatureSchemeBase@VPK_Verifier@CryptoPP@@V?$TF_Base@VTrapdoorFunction@CryptoPP@@VPK_Signa" fullword ascii
		 $a23= "KCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_SignatureMessageEncodingMethod@2@VSHA1@2@@2@VInvertib" fullword ascii
		 $a24= "PP@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_SignatureMessageEncodingMethod@2@VSHA1@2@@2@VRS" fullword ascii
		 $a25= "@@UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_SignatureMessageEncodingMethod@2@VSHA1@2@@2@VInve" fullword ascii
		 $a26= "UPKCS1v15@2@VSHA1@2@H@CryptoPP@@URSA@2@VPKCS1v15_SignatureMessageEncodingMethod@2@VSHA1@2@@2@VRSAFun" fullword ascii

		 $hex1= {246131303d20222e3f}
		 $hex2= {246131313d20222e3f}
		 $hex3= {246131323d20222e3f}
		 $hex4= {246131333d20222e3f}
		 $hex5= {246131343d20222e3f}
		 $hex6= {246131353d20222e3f}
		 $hex7= {246131363d20222e3f}
		 $hex8= {246131373d20222e3f}
		 $hex9= {246131383d20222e3f}
		 $hex10= {246131393d20222e3f}
		 $hex11= {2461313d20222e3f41}
		 $hex12= {246132303d20222e3f}
		 $hex13= {246132313d20222e3f}
		 $hex14= {246132323d20222e3f}
		 $hex15= {246132333d20224b43}
		 $hex16= {246132343d20225050}
		 $hex17= {246132353d20224040}
		 $hex18= {246132363d20225550}
		 $hex19= {2461323d20222e3f41}
		 $hex20= {2461333d20222e3f41}
		 $hex21= {2461343d20222e3f41}
		 $hex22= {2461353d20222e3f41}
		 $hex23= {2461363d20222e3f41}
		 $hex24= {2461373d20222e3f41}
		 $hex25= {2461383d20222e3f41}
		 $hex26= {2461393d20222e3f41}
		 $hex27= {247331303d20226170}
		 $hex28= {247331313d20226170}
		 $hex29= {247331323d20226170}
		 $hex30= {247331333d20226170}
		 $hex31= {247331343d20226170}
		 $hex32= {247331353d20226170}
		 $hex33= {247331363d20226578}
		 $hex34= {247331373d20226578}
		 $hex35= {247331383d20226578}
		 $hex36= {2473313d2022617069}
		 $hex37= {2473323d2022617069}
		 $hex38= {2473333d2022617069}
		 $hex39= {2473343d2022617069}
		 $hex40= {2473353d2022617069}
		 $hex41= {2473363d2022617069}
		 $hex42= {2473373d2022617069}
		 $hex43= {2473383d2022617069}
		 $hex44= {2473393d2022617069}

	condition:
		5 of them
}
