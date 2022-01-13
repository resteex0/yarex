
/*
   YARA Rule Set
   Author: resteex
   Identifier: Android_Bzy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Android_Bzy {
	meta: 
		 description= "Android_Bzy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-29-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "2581005272be81f0fece45b5695441fa"
		 hash2= "cdc77f3dfabdea5c5278ac9e50841ff3"
		 hash3= "df458189d71732af0e96d745e06153fb"

	strings:

	
 		 $a1= "_ZN3art14CompilerDriver10CompileAllEP8_jobjectRKSt6vectorIPKNS_7DexFileESaIS6_EERNS_4base12TimingLog" fullword ascii
		 $a2= "_ZN3art14CompilerDriver8WriteElfERKSsbRKSt6vectorIPKNS_7DexFileESaIS6_EERNS_9OatWriterEPN9unix_file6" fullword ascii
		 $a3= "_ZNSt4priv8_Rb_treeIN3art11StringPieceESt4lessIS2_ESt4pairIKS2_PKhENS_10_Select1stIS9_EENS_11_MapTra" fullword ascii
		 $a4= "_ZNSt4priv8_Rb_treeISsSt4lessISsESsNS_9_IdentityISsEENS_11_SetTraitsTISsEESaISsEE13insert_uniqueERKS" fullword ascii
		 $a5= "_ZNSt4priv8_Rb_treeISsSt4lessISsESsNS_9_IdentityISsEENS_11_SetTraitsTISsEESaISsEE8_M_eraseEPNS_18_Rb" fullword ascii
		 $a6= "_ZNSt4priv8_Rb_treeISsSt4lessISsESsNS_9_IdentityISsEENS_11_SetTraitsTISsEESaISsEE9_M_insertEPNS_18_R" fullword ascii
		 $a7= "_ZSt18_M_ignore_bufferedIcSt11char_traitsIcENSt4priv14_Is_not_wspaceIS1_EENS2_20_Scan_for_not_wspace" fullword ascii
		 $a8= "_ZSt18__stlp_string_fillIcSt11char_traitsIcEEbRSt13basic_ostreamIT_T0_EPSt15basic_streambufIS3_S4_Ei" fullword ascii
		 $a9= "_ZSt20_M_ignore_unbufferedIcSt11char_traitsIcENSt4priv14_Is_not_wspaceIS1_EEEvPSt13basic_istreamIT_T" fullword ascii

		 $hex1= {2461313d20225f5a4e}
		 $hex2= {2461323d20225f5a4e}
		 $hex3= {2461333d20225f5a4e}
		 $hex4= {2461343d20225f5a4e}
		 $hex5= {2461353d20225f5a4e}
		 $hex6= {2461363d20225f5a4e}
		 $hex7= {2461373d20225f5a53}
		 $hex8= {2461383d20225f5a53}
		 $hex9= {2461393d20225f5a53}

	condition:
		1 of them
}
