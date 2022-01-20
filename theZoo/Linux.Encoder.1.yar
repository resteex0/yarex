
/*
   YARA Rule Set
   Author: resteex
   Identifier: Linux_Encoder_1 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Linux_Encoder_1 {
	meta: 
		 description= "Linux_Encoder_1 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-42-33" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1e19b857a5f5a9680555fa9623a88e99"
		 hash2= "22dc1db1a876721727cca37c21d31655"
		 hash3= "60e0f1362da65e11bb268be5b1ad1053"
		 hash4= "934b91c62fec7c99e56dc564e89831cb"
		 hash5= "fb8eac22caa97d5fe5f96e3f79455096"

	strings:

	
 		 $a1= "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" fullword ascii
		 $a2= "/usr/home/freebsd/mbedtls-2.1.2/library/asn1parse.c" fullword ascii
		 $a3= "/usr/home/freebsd/mbedtls-2.1.2/library/asn1write.c" fullword ascii
		 $a4= "/usr/home/freebsd/mbedtls-2.1.2/library/blowfish.c" fullword ascii
		 $a5= "/usr/home/freebsd/mbedtls-2.1.2/library/camellia.c" fullword ascii
		 $a6= "/usr/home/freebsd/mbedtls-2.1.2/library/cipher_wrap.c" fullword ascii
		 $a7= "/usr/home/freebsd/mbedtls-2.1.2/library/ctr_drbg.c" fullword ascii
		 $a8= "/usr/home/freebsd/mbedtls-2.1.2/library/ecp_curves.c" fullword ascii
		 $a9= "/usr/home/freebsd/mbedtls-2.1.2/library/entropy_poll.c" fullword ascii
		 $a10= "/usr/home/freebsd/mbedtls-2.1.2/library/hmac_drbg.c" fullword ascii
		 $a11= "/usr/home/freebsd/mbedtls-2.1.2/library/ripemd160.c" fullword ascii
		 $a12= "/usr/src/lib/libc/../../contrib/tzcode/stdtime/asctime.c" fullword ascii
		 $a13= "/usr/src/lib/libc/../../contrib/tzcode/stdtime/localtime.c" fullword ascii

		 $hex1= {246131303d20222f75}
		 $hex2= {246131313d20222f75}
		 $hex3= {246131323d20222f75}
		 $hex4= {246131333d20222f75}
		 $hex5= {2461313d2022616263}
		 $hex6= {2461323d20222f7573}
		 $hex7= {2461333d20222f7573}
		 $hex8= {2461343d20222f7573}
		 $hex9= {2461353d20222f7573}
		 $hex10= {2461363d20222f7573}
		 $hex11= {2461373d20222f7573}
		 $hex12= {2461383d20222f7573}
		 $hex13= {2461393d20222f7573}

	condition:
		8 of them
}
