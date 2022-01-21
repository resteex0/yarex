
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_HawkEye_Keylogger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_HawkEye_Keylogger {
	meta: 
		 description= "vx_underground2_HawkEye_Keylogger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-59-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "019a689dcc5128d85718bd043197b311"
		 hash2= "027e6819e54bf93a0a79419d92047946"
		 hash3= "06743a9a276758e67e7a6f66d662fca6"
		 hash4= "06d2238a45998d15733aad0567b5ed1d"
		 hash5= "087be68dde98f4f243a9caccf2ba119d"
		 hash6= "112444bfba5d7931dd173f0606a82e3b"
		 hash7= "1641b030c7cab3369abf294972d29f39"
		 hash8= "1e5c2a9c10d6719ce9017dbdc74f141c"
		 hash9= "20884d73f1d0847d10b34fe490062815"
		 hash10= "2582ca4e6687084d8d032d4f1cba525c"
		 hash11= "30028e1e24febcf077d6db602b010805"
		 hash12= "4b311f1e344ceda09fbc8ea58067e338"
		 hash13= "4da4e24086338bd0451bec5230d9ca86"
		 hash14= "4efc57e86d070dcabd078e23ec147c08"
		 hash15= "5504cb0b827226ef0d4067ff511bca1d"
		 hash16= "59a6db3dad5444042c0f69fc905f1c11"
		 hash17= "59c8d2b1592137e27c1ca85e3773f068"
		 hash18= "65479f2bc8ce65fb489e1984a98e9e78"
		 hash19= "7abba2c4190c7101d16bc6c1ea136ca0"
		 hash20= "9e87cb1c1ca1545e9b0293231324becf"
		 hash21= "a4442ce59064bab5d49f33de37fc04e6"
		 hash22= "adde5c8d98e9c099677d7e81164d7e61"
		 hash23= "be11151eac8ecaad89e8b4fdc8510e7c"
		 hash24= "e232417590b6fc4bd783c5ca66ea6d7c"
		 hash25= "eb2844fa3256355b4ac74612d1358626"

	strings:

	
 		 $s1= "avKYHXKNlaYSjhGawGCNQeBDLVQrJb" fullword wide
		 $s2= "AW7C6G+fWY8EggUCG9vdPq0pEotxnO5n/z1ashiFyLfyEa+7U8tNyzgIDM+Kzcyb" fullword wide
		 $s3= "BkoQFDtOLgEbgdorIcdmvqVkFYqkbI" fullword wide
		 $s4= "CbvuYHXKOmOYTkhGaBpmBQeCmvVQrt" fullword wide
		 $s5= "cLbOSqfdXolKfFLHSViGIQZVwOgCUP" fullword wide
		 $s6= "DTGKiXVPgdCWtCvKNauvIRMoGXqMGt" fullword wide
		 $s7= "eRVtifaroNhINKUXlJKTcXCRiFWRHl" fullword wide
		 $s8= "fvimODBrMJeDZfbmpGacktpUiEWojZ" fullword wide
		 $s9= "hJurmHEZtUZWgjBVWfojOduRjdUBJK" fullword wide
		 $s10= "hlNCwqLIdBYdaloFZajsnThCVnhYFN" fullword wide
		 $s11= "hlNCwqLIdBYealoFZbjsoThCVniYFN" fullword wide
		 $s12= "iD78KVOXDCazpWDCrXGoFsMk8K+GZ/Np60nGgX7OoRUjh5RFxPzyZh/X9TAEWw88" fullword wide
		 $s13= "IlOcifwY3or99iUoI2Vp52Cpm+PPiaEAOKrFj6Y3HY8=" fullword wide
		 $s14= "KiXVPgdCWtDvKNauwIRNoGXqMHtaij" fullword wide
		 $s15= "KpJswYNKFVToMjokvCQkluHCdsNgBs" fullword wide
		 $s16= "lChBkoQFDtOLgEbgdorIcdmvqVkFYq" fullword wide
		 $s17= "PCGeTRLcZuTpvrGJWqsENJkCUmIDpW" fullword wide
		 $s18= "QdMcPTrgdYpmLfGLISVjHIRaVwPgDV" fullword wide
		 $s19= "rehJusmHEZuUaWhkCVXfpkPdvRjeUB" fullword wide
		 $s20= "SiVZBmkevsRlMSOZcpNOXgbHVmJbWM" fullword wide
		 $s21= "sqkFDYsSYUfiwUVeniNctPhcSvIIHL" fullword wide
		 $s22= "tBZOLGXUpNkpmwDRlmvIDetOhCtjRZ" fullword wide
		 $s23= "uOBFdSPKaYtRotpEHVpqDMHiBSlGBn" fullword wide
		 $s24= "uqgvGCEFIVOWFdUezXZlEyf.exe" fullword wide
		 $s25= "VQJtj252WgdoFCIte0rBgee4o5/2HiTgTi2tTQakd/SfPAbTiBIu263OQevYVMx9" fullword wide
		 $s26= "VYwljdurQlLRNYbpMOWgbGUmIaVLoB" fullword wide
		 $s27= "wK5OAbQLdkW8AmRWP/HCMnuejaFaeSCno970PrhwwWc=" fullword wide
		 $s28= "WmZdFqniDwVpQVSdftRSbkfKZqNfZQ" fullword wide
		 $s29= "wNsMvDbQOIZWrPmsoDGTnoBKFhvQjF" fullword wide
		 $s30= "XGWJNlaYSjgFZwFCNQdBCLUPrJatPJ" fullword wide
		 $s31= "Xkyq0O/C5p+aJFdEMegENFAxpqT8TAGbDrfg7BUnqfncPzzTzKEMm/azUpp1QqHF" fullword wide
		 $a1= "stk||}icv|urcuwJOOXLZzibdQCSt{gOMY]fxhqSosrRw`hKOZqmy[FCgttgu{" fullword ascii
		 $a2= "v{ZFZJOY~dUHBjEVN^Jr[F`yWUQDZChpdhzp~{iiQwosg`aY_u{kgohxv@d~dvsp" fullword ascii

		 $hex1= {2461313d202273746b}
		 $hex2= {2461323d2022767b5a}
		 $hex3= {247331303d2022686c}
		 $hex4= {247331313d2022686c}
		 $hex5= {247331323d20226944}
		 $hex6= {247331333d2022496c}
		 $hex7= {247331343d20224b69}
		 $hex8= {247331353d20224b70}
		 $hex9= {247331363d20226c43}
		 $hex10= {247331373d20225043}
		 $hex11= {247331383d20225164}
		 $hex12= {247331393d20227265}
		 $hex13= {2473313d202261764b}
		 $hex14= {247332303d20225369}
		 $hex15= {247332313d20227371}
		 $hex16= {247332323d20227442}
		 $hex17= {247332333d2022754f}
		 $hex18= {247332343d20227571}
		 $hex19= {247332353d20225651}
		 $hex20= {247332363d20225659}
		 $hex21= {247332373d2022774b}
		 $hex22= {247332383d2022576d}
		 $hex23= {247332393d2022774e}
		 $hex24= {2473323d2022415737}
		 $hex25= {247333303d20225847}
		 $hex26= {247333313d2022586b}
		 $hex27= {2473333d2022426b6f}
		 $hex28= {2473343d2022436276}
		 $hex29= {2473353d2022634c62}
		 $hex30= {2473363d2022445447}
		 $hex31= {2473373d2022655256}
		 $hex32= {2473383d2022667669}
		 $hex33= {2473393d2022684a75}

	condition:
		22 of them
}
