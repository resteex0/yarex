
/*
   YARA Rule Set
   Author: resteex
   Identifier: HawkEye_Keylogger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_HawkEye_Keylogger {
	meta: 
		 description= "HawkEye_Keylogger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_01-42-12" 
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

	
 		 $s1= "0MAjJQnz8GQlT4YAngEoIwl5dRyvhwGay0BPED0rwOgtl15cPBQExlrvANZmxNNy" fullword wide
		 $s2= "12459cidCduFlzurJLN9g9KdXQJ3mffnILjTLnWR6MvdfoR6zGKI2vjXeoTEo4Cd" fullword wide
		 $s3= "2vxxDNTZgbPAmO+/4H/cNbNi+fnEBP9B1y3Nn1SO8NLDqm32A67LOgQZUXYZd/9M" fullword wide
		 $s4= "5CkY276Zaba+A55K0XiqG4KH9OCsvHTuTrZlTxfdpxfsm3dxe8m3YzKRuL4C62mw" fullword wide
		 $s5= "6L7bBPFExvXd1o1O3kSuuRSeyTGgnou9VN2XVF9+pisB0Kuuzz04ufYsbsx3hK3R" fullword wide
		 $s6= "6qYo55cesnmsxTBOven1ZGn4MXnPmfdrlbO9wWrjK+ITOODNVmSQ73MtJHxQ1rW+" fullword wide
		 $s7= "9ahAhyLQPI5C6NPUeduEI1A3kdZYY8KJdIibGEI672A/Jpf1y5yGFsUhZlCTeZhU" fullword wide
		 $s8= "AMB2zvp8ItwICh2GByUx6gAlA7Huo0eW/BPAjfFdc5YuXWqwsY4HUjbPe4CNTvWe" fullword wide
		 $s9= "AW7C6G+fWY8EggUCG9vdPq0pEotxnO5n/z1ashiFyLfyEa+7U8tNyzgIDM+Kzcyb" fullword wide
		 $s10= "CeMkDRfxNvY8ml5e80hI3u+OMW9B1+EhE5u5luAqYhg0sNhbcK5LGYkkL7MSQ3Rs" fullword wide
		 $s11= "dxSC035RtTHDALy19GKTGPxSlVhPdOi3PjOkVeaKhb1czDCaGLptiqZFPgw13USe" fullword wide
		 $s12= "/eU15ZdsqI0EHN3UABLhYXq9aqBhCHNwPjZYa3Tw+WqwNV0tba9NyyGi3xpElUvP" fullword wide
		 $s13= "iD78KVOXDCazpWDCrXGoFsMk8K+GZ/Np60nGgX7OoRUjh5RFxPzyZh/X9TAEWw88" fullword wide
		 $s14= "IlOcifwY3or99iUoI2Vp52Cpm+PPiaEAOKrFj6Y3HY8=" fullword wide
		 $s15= "jQJVb/uuYsc1udVrABjHJ/NUn68MWarTFSvmzqQxQfVThSofl5WkMHB72iH0F2WQ" fullword wide
		 $s16= "Ky70HUto4vVZlK+XL9GPggWFV03lwjr8PiE6I77gPZSW3KgCnww1HZYrs8XqkBwi" fullword wide
		 $s17= "MS+1JE9PgJR03GqvP+3z1+2ReTFC5PeIcZjjf82k1BaleBB39HXdgCKabdb664gX" fullword wide
		 $s18= "Sbi6DRwaDQ5i7XJcHudguIii3mbRjH8xh1i9FBBCY9DaEaq6Nn4Gaj1Tbkgj22br" fullword wide
		 $s19= "UezqWd56j5TXfCW7TI9EVVmOUTJ1UYjNJETmpqPnSucJ7hrobKjPUupgly+FMYci" fullword wide
		 $s20= "v+qHjD7BkV1HxSnpLXr/42+kMNHuuHKsD/iBJRv9eY11JNsegVs5g41BU48PZGfq" fullword wide
		 $s21= "VQJtj252WgdoFCIte0rBgee4o5/2HiTgTi2tTQakd/SfPAbTiBIu263OQevYVMx9" fullword wide
		 $s22= "wK5OAbQLdkW8AmRWP/HCMnuejaFaeSCno970PrhwwWc=" fullword wide
		 $s23= "Xkyq0O/C5p+aJFdEMegENFAxpqT8TAGbDrfg7BUnqfncPzzTzKEMm/azUpp1QqHF" fullword wide
		 $s24= "Ybz2nJCMjMvUR5EX1TgXtvJ1wNORE0ptLKTDOmtql0oTtaHi+UvR3YOtfOEmbVZZ" fullword wide
		 $a1= "0MAjJQnz8GQlT4YAngEoIwl5dRyvhwGay0BPED0rwOgtl15cPBQExlrvANZmxNNy" fullword ascii
		 $a2= "12459cidCduFlzurJLN9g9KdXQJ3mffnILjTLnWR6MvdfoR6zGKI2vjXeoTEo4Cd" fullword ascii
		 $a3= "2vxxDNTZgbPAmO+/4H/cNbNi+fnEBP9B1y3Nn1SO8NLDqm32A67LOgQZUXYZd/9M" fullword ascii
		 $a4= "5CkY276Zaba+A55K0XiqG4KH9OCsvHTuTrZlTxfdpxfsm3dxe8m3YzKRuL4C62mw" fullword ascii
		 $a5= "6L7bBPFExvXd1o1O3kSuuRSeyTGgnou9VN2XVF9+pisB0Kuuzz04ufYsbsx3hK3R" fullword ascii
		 $a6= "6qYo55cesnmsxTBOven1ZGn4MXnPmfdrlbO9wWrjK+ITOODNVmSQ73MtJHxQ1rW+" fullword ascii
		 $a7= "9ahAhyLQPI5C6NPUeduEI1A3kdZYY8KJdIibGEI672A/Jpf1y5yGFsUhZlCTeZhU" fullword ascii
		 $a8= "AMB2zvp8ItwICh2GByUx6gAlA7Huo0eW/BPAjfFdc5YuXWqwsY4HUjbPe4CNTvWe" fullword ascii
		 $a9= "AW7C6G+fWY8EggUCG9vdPq0pEotxnO5n/z1ashiFyLfyEa+7U8tNyzgIDM+Kzcyb" fullword ascii
		 $a10= "CeMkDRfxNvY8ml5e80hI3u+OMW9B1+EhE5u5luAqYhg0sNhbcK5LGYkkL7MSQ3Rs" fullword ascii
		 $a11= "dxSC035RtTHDALy19GKTGPxSlVhPdOi3PjOkVeaKhb1czDCaGLptiqZFPgw13USe" fullword ascii
		 $a12= "/eU15ZdsqI0EHN3UABLhYXq9aqBhCHNwPjZYa3Tw+WqwNV0tba9NyyGi3xpElUvP" fullword ascii
		 $a13= "iD78KVOXDCazpWDCrXGoFsMk8K+GZ/Np60nGgX7OoRUjh5RFxPzyZh/X9TAEWw88" fullword ascii
		 $a14= "jQJVb/uuYsc1udVrABjHJ/NUn68MWarTFSvmzqQxQfVThSofl5WkMHB72iH0F2WQ" fullword ascii
		 $a15= "Ky70HUto4vVZlK+XL9GPggWFV03lwjr8PiE6I77gPZSW3KgCnww1HZYrs8XqkBwi" fullword ascii
		 $a16= "MS+1JE9PgJR03GqvP+3z1+2ReTFC5PeIcZjjf82k1BaleBB39HXdgCKabdb664gX" fullword ascii
		 $a17= "Sbi6DRwaDQ5i7XJcHudguIii3mbRjH8xh1i9FBBCY9DaEaq6Nn4Gaj1Tbkgj22br" fullword ascii
		 $a18= "UezqWd56j5TXfCW7TI9EVVmOUTJ1UYjNJETmpqPnSucJ7hrobKjPUupgly+FMYci" fullword ascii
		 $a19= "v+qHjD7BkV1HxSnpLXr/42+kMNHuuHKsD/iBJRv9eY11JNsegVs5g41BU48PZGfq" fullword ascii
		 $a20= "VQJtj252WgdoFCIte0rBgee4o5/2HiTgTi2tTQakd/SfPAbTiBIu263OQevYVMx9" fullword ascii
		 $a21= "Xkyq0O/C5p+aJFdEMegENFAxpqT8TAGbDrfg7BUnqfncPzzTzKEMm/azUpp1QqHF" fullword ascii
		 $a22= "Ybz2nJCMjMvUR5EX1TgXtvJ1wNORE0ptLKTDOmtql0oTtaHi+UvR3YOtfOEmbVZZ" fullword ascii

		 $hex1= {246131303d20224365}
		 $hex2= {246131313d20226478}
		 $hex3= {246131323d20222f65}
		 $hex4= {246131333d20226944}
		 $hex5= {246131343d20226a51}
		 $hex6= {246131353d20224b79}
		 $hex7= {246131363d20224d53}
		 $hex8= {246131373d20225362}
		 $hex9= {246131383d20225565}
		 $hex10= {246131393d2022762b}
		 $hex11= {2461313d2022304d41}
		 $hex12= {246132303d20225651}
		 $hex13= {246132313d2022586b}
		 $hex14= {246132323d20225962}
		 $hex15= {2461323d2022313234}
		 $hex16= {2461333d2022327678}
		 $hex17= {2461343d202235436b}
		 $hex18= {2461353d2022364c37}
		 $hex19= {2461363d2022367159}
		 $hex20= {2461373d2022396168}
		 $hex21= {2461383d2022414d42}
		 $hex22= {2461393d2022415737}
		 $hex23= {247331303d20224365}
		 $hex24= {247331313d20226478}
		 $hex25= {247331323d20222f65}
		 $hex26= {247331333d20226944}
		 $hex27= {247331343d2022496c}
		 $hex28= {247331353d20226a51}
		 $hex29= {247331363d20224b79}
		 $hex30= {247331373d20224d53}
		 $hex31= {247331383d20225362}
		 $hex32= {247331393d20225565}
		 $hex33= {2473313d2022304d41}
		 $hex34= {247332303d2022762b}
		 $hex35= {247332313d20225651}
		 $hex36= {247332323d2022774b}
		 $hex37= {247332333d2022586b}
		 $hex38= {247332343d20225962}
		 $hex39= {2473323d2022313234}
		 $hex40= {2473333d2022327678}
		 $hex41= {2473343d202235436b}
		 $hex42= {2473353d2022364c37}
		 $hex43= {2473363d2022367159}
		 $hex44= {2473373d2022396168}
		 $hex45= {2473383d2022414d42}
		 $hex46= {2473393d2022415737}

	condition:
		5 of them
}
