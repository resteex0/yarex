
/*
   YARA Rule Set
   Author: resteex
   Identifier: AsyncRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_AsyncRAT {
	meta: 
		 description= "AsyncRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-12_19-48-58" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "046d726bc1454f1bfbbd0acdd4999ddf"
		 hash2= "20474c96100028e9c1196951bf30f787"
		 hash3= "4e1616f999146ad847eccf8e6facdc89"
		 hash4= "56536b8675c047fce4af23fc1b2b6d61"

	strings:

	
 		 $s1= "0duyMze6Uq+Ad6QNrjOnfNsbdb+qlzEDhVsngeDbIjEtQqTklxhLr6bWgbz0xDf6Ag5wVRhaidiHN32qDA==" fullword wide
		 $s2= "/0N/7Qvw230yCNmZL1DSHaseSpJwHLh6Xf0lQWgfqQmlhFM+rXREB85KGfoyjXGWZ0xY95BJXhCLz9MXfdtCtSFTxkVF+UWNq4vQ" fullword wide
		 $s3= "4U8eEoHdSwn9ckQsReRLHgro4MdEWP5lBO6UHrtZrZpR2QIFZvv9ldeC5HOqNW4CCk/yQ7MvgKajHhaO5GThKw==" fullword wide
		 $s4= "4wK4pBri7f2UJDUYSIGr/7wgg9trYRTjFIpJV4jbrrW1pKbWqG5yriPRZ7NsPJWC6frQF5BgGvDKaCemq/2JdA==" fullword wide
		 $s5= "5BhutYCI7cMgXZ+HSSXbv+GX2XSaZPkWHGXgVii2qDmY1HeSKyMRSs0cGf2s1S/Ai6FJBl9fRhqRyccV50Pwxghb3prrGgGNi+RF" fullword wide
		 $s6= "5EeUWudKWRWbylJcz3lLIKeOYMtthSboq9mgEg4UZWiG3a0dKkpR9PGSIdAvaLX78GyZR5TibIs42NRyBLkMRlwa8Awo/EXCZRHK" fullword wide
		 $s7= "7b9b1da8-2443-41df-a85e-bf57919f1186" fullword wide
		 $s8= "7BK8/L8dwlOhaL4i3SWeLefvGCEK" fullword wide
		 $s9= "7OyiI4bx4ex9tYYCdoRNVmbFKacF5I2wMSD66KbjoJbgqSTVYp4RMa13Um/NCTaRJYbFzlbzoRJdSh+TJ4YAzh3RgjSyDk58OY+h" fullword wide
		 $s10= "- abort() has been called" fullword wide
		 $s11= "aIusTJFZKxYCRNlNumfruS1uyjAuGcEvFJJbcshDtsaDTx2ie05B51ZKmui01EZaQanWQIUbgwIWImfXD+Rx0Kxw8abxib/OnZ3w" fullword wide
		 $s12= "ASHAMPOO_OPTMI.Properties.Resources" fullword wide
		 $s13= "AstroGrep_Setup_v4.4.7.exe" fullword wide
		 $s14= "ASTROGREP_SETUP_V4.4.7.EXE" fullword wide
		 $s15= "- Attempt to initialize the CRT more than once." fullword wide
		 $s16= "- Attempt to use MSIL code from this assembly during native code initialization" fullword wide
		 $s17= "aVP2A7H/1yIjn7T/cO87aWQq2RYbjSYfQouCiFmi2iv+60Y4VK6YgZv1VCecUSz+jyeJDrCIWBeafwOl7znCnw==" fullword wide
		 $s18= "BG/kZnvp1pNne01w/dDztwOiwNpg5cVgCsHgIxL/rBduTMCDjyFgHrdqlZEx5JS6XKNqAj1sBicC/1t3H7uU9ql/2d8qpogt8By3" fullword wide
		 $s19= "Bl9tUGW9qrkMDNf5tGxAdAJMr7+IAqJu5IsIBdleNiU3ImffMARkIL/WytZNaFjp5FTVBBnLkQy2GwuZeziqCfCBBDB1aY7fCQtZ" fullword wide
		 $s20= "Cabvk6hB5Co0iLVyS7YfyasB55Ow+OIASItfqSGv93x7yd6PFUFAbRtwJk77oYLrJfdczyrUfnIGJ8bk3mD4cA==" fullword wide
		 $s21= "/clr) function from a native constructor or from DllMain." fullword wide
		 $s22= "d8109cf1-42b8-4b2f-86d9-f7979615a2c1" fullword wide
		 $s23= "d9KGy8KMvhPo/e7ngbpQODVrG7rWZ5jAkxY1RtFAUvXXppD4ZQG+CGu0ve80tNU/dIVHWI6J74kY1h6draQh+zLrO63jzLO2szPM" fullword wide
		 $s24= "eeUck8GNsyx8WHqW6DHeMgQYSOay5tDU3QVd4nA6VePHiyAoGo1NkluauABdvACMi+1S2U2HuC2K/kpvIO78Ey4fi03DIWOdKwjA" fullword wide
		 $s25= "(ext8,ext16,ex32) type $c7,$c8,$c9" fullword wide
		 $s26= "f1c6iqzCiny1TFHzmLYdc8K1wTNOoZQB2VrICC9kmng3ZtSHTR+rkuKM6or+X1sCAmuuJkjiNTowtmPDBpYXqTvV7rM1udwyAcV4" fullword wide
		 $s27= "- floating point support not loaded" fullword wide
		 $s28= "fqvy9ac8aS4V9xuOiI9DekDLADJSo2duLCTWsgdFMI1IXAw6kOUzpbfStUlDntS77T24jUA+RJjyq8V+zTPRU95cl1Gwb6sXmPM8" fullword wide
		 $s29= "get_AllowOnlyFipsAlgorithms" fullword wide
		 $s30= "hL3DbU3G3ZUtoM9pd3yORe5TrOOHAW/YPjKiNIulAz1F5c98QRABd147y8uNmOmEbwG69p92AtKMHm+BBQ4L65yjFchPEu7LDz2I" fullword wide
		 $s31= "hmOqeMdTBFUSwirpbew7zEotZcJq3ddagHSQ1PR1xIwXELISEvpaWqRzst3Kk7wl4MPtpF3SWi2uZNrZLA97zJyH6eZhAZW7ygTY" fullword wide
		 $s32= "hZR0XLAt7QC1QzPIAw9XorjUZ0kvRAcbpvQuVEcHEQiSk8vjduCV1X1n4dc/wRVppbPJPZvjK1Mh2Zcpzgpu9MS0vVjuu5Y4xvPv" fullword wide
		 $s33= "Invalid message authentication code (MAC)." fullword wide
		 $s34= "kczehjDruNkypEoeROrhPO7WBtP3kTCTcrc0V7jmBHciZiKGhIEnyE0TZf5b5BMVm1WqS5jnH5T9hkgpB7CdGaJCRnzt285c6Q3Y" fullword wide
		 $s35= "KHndGehExORa3FHp9Y7gmFLK9XNaMMM27XaZUPbOdtv//APfKv2ZgLnzkSMmqS7RaH5wTGSHg9bbn5qOzKHCjaHF3XzpV5evIVci" fullword wide
		 $s36= "kUOJOgt3khql2gcFntn0lRf5qnjU5191obsQRwt+1eejqgrS56W+CwQqERHl5LKvyzyVe0CgGVcMNGNh2UxDBzpva8YZIipVZJ4c" fullword wide
		 $s37= "lMV4Zr9k2StSbSw5wLwWi64tgxw+uegbANufZPeN4w0NGIamJVcHW8v6lYQcDRd+jT039C0WmKA8bVYqRm+rh3FjXyh6tbHW4sNh" fullword wide
		 $s38= "LqAr0a96bejTy0gL0EM+fafDTGfBnpIy3rL4eZ3f5vWEwIkP5XpbjlLWdXOw5JoUho71glN6elqv9tRnzekVw6QYg8KU/otB6KhQ" fullword wide
		 $s39= "masterKey can not be null or empty." fullword wide
		 $s40= "@Microsoft Visual C++ Runtime Library" fullword wide
		 $s41= "NGowqIIaRfZK9xE4MaYAMZJNSBiADXG98tScxjas+TYluA/Nyk7JqsIeKhWHRmXvZLhCzwhMhg58B1Wf4D6HcA==" fullword wide
		 $s42= "- not enough space for arguments" fullword wide
		 $s43= "- not enough space for environment" fullword wide
		 $s44= "- not enough space for locale information" fullword wide
		 $s45= "- not enough space for lowio initialization" fullword wide
		 $s46= "- not enough space for _onexit/atexit table" fullword wide
		 $s47= "- not enough space for stdio initialization" fullword wide
		 $s48= "- not enough space for thread data" fullword wide
		 $s49= "nuRnoisreVtnerruCswodniWtfosorciMerawtfoS" fullword wide
		 $s50= "o/Xn/cSL5J8Elj5me1Jvu5jPcdGocK39F+b7iN3rH9xYXCpn82fCDRksHIog4f12H8eaL6r5cN5hTfF8L8OuV5vt5cSMpqiDwMJn" fullword wide
		 $s51= "pdco7151c+y+nY3s1EBhyFlLh6AET832+hhvA5YIgtBixfREJ37RPLohibVqUMOLsfWSlJePkgO+DS3hSjMukU4ikBnh4T0JEv2O" fullword wide
		 $s52= "Please wait while Setup is loading..." fullword wide
		 $s53= "pLM+ApsBRJmqPsJOaMcK/N0JPvKfiGFssRM3iAWWgjQwHcMXxOppbe+KNOQyQELK4QczZlV/WoyhBcqnq09p/pA3PPYkhLdwTBY8" fullword wide
		 $s54= "Program and source copyright (c) AstroComma Incorporated" fullword wide
		 $s55= "- pure virtual function call" fullword wide
		 $s56= "Pz6HTRErqFL8GU8m8cRnBSLEFfTLsFAK3PpjoYr5p1LilKhivCm3eDI8rg7Kce9LS6XJsshf1zVjdvXbhKM8t7tS4s80MhTDXOjV" fullword wide
		 $s57= "QHy8sfXkGmhL4GfCIxO4J1WB7dWaURp1TcEzVJkn3+Ahjg1xP+UJRRGNLO2H1f8OBBUg1zZFbOawMqFIJs9TzA==" fullword wide
		 $s58= "QlziySFwY4R7hQZ+puteC/VfFXS01L9036I7tYE0KxiYs7I2+ca2JaCP3h8LwE/f6s9Dwy0sU0Rj4S/j3SQmY6zUSCxm8LKYK+/m" fullword wide
		 $s59= "qs8NwkAsOhzOePCuRvr3RaaGTAe8RLyIindb+T/yse5WVsI=" fullword wide
		 $s60= "R3oLaKXfDr6rAO99i7NEiwrOhtYr7FQkF66mH80NeUrbSGM+wSwyQY2Bz8neKR3fz49dNiaC8H/QRRz9YPVBEA==" fullword wide
		 $s61= "RvqIMWuetijphaJZAJE6FoIGlFfHd25BS7fS+/kn3XyLxV5NuiPDP84jJByv/aNjcL32QvZRFQOVa9fjv0ooG5j+NGJ1TRck/hQa" fullword wide
		 $s62= "s4NcrkmMSbyDJuTV5upHFtQTHEWn5NENVUlmYlJ6TKa+s//A3iAZYjuvrXC49N8rcL1SO9rbwRyV03Hb11LVlwxo+vw2CNsDQcUs" fullword wide
		 $s63= "Select * from AntivirusProduct" fullword wide
		 $s64= "Select * from Win32_ComputerSystem" fullword wide
		 $s65= "sL+KJ+XFqA4EPxUJr6OXTBtFT3xCMBE+Fy9Pme3WBIcjpair31ibEC7Vc/FOFQw8NuYqHJJRJmJ6UlncQs18i1mJJcvpVtGa8OyX" fullword wide
		 $s66= "ss8k62VXgzXiU1pEDwMGzrWCoqzDd1xct9tMaVj5T2rRQXNJQTuxij2Ad1muU/o4NID8d7DUfS0RBQg1LhXEfwvlTigh547Pji4H" fullword wide
		 $s67= "System.Security.Cryptography.CryptoConfig" fullword wide
		 $s68= "This application and its source code are freely distributable." fullword wide
		 $s69= "This indicates a bug in your application." fullword wide
		 $s70= "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (" fullword wide
		 $s71= "Unable to change value to false while a transparent BackColor is in use." fullword wide
		 $s72= "- unable to initialize heap" fullword wide
		 $s73= "- unable to open console device" fullword wide
		 $s74= "- unexpected multithread lock error" fullword wide
		 $s75= "UXyiZqIK8ogznGKiCpNKUkwfOGCL/GjdkWDuSqopmPdskyodHMaouKM2Cm1eqtCpXpGCo5Xuy+XSiscemoxxUnjPYsNP9Kfp+MKd" fullword wide
		 $s76= "VZuKLsMCMDJNr3unwJ0A4GXx/QxjgoHld10w0sr5PlE6nxOr16yIqis1YgbnpOYyVmLpI9gD8t7NHQ3Z1lRLOv5W83gbhwqgWGQR" fullword wide
		 $s77= "WmdPVEloU1Z6U1RTb3N2NElUWXJ6YWlsSFhXT0h5RU0=" fullword wide
		 $s78= "wV1Tz2c2oqfZbqRG8Q4mijRcCRtX2SxEYaPM8+AWJTkizNIJkX8jIl/1ZgjoE4hHbFj07q1QqrumfmRpDKruIsOdUH3WF7M/XX4z" fullword wide
		 $s79= "xq29q/w/O/2Qurw1KqcNi0qjBhE3CGmOZa/3I2DqBxV4OWMuK/3AiJ2F5ojQ5/lv7197Wwh2D5xbUgJ/LC8uVQpbeGhqdqk0a+2x" fullword wide
		 $s80= "!Y!9YFAY^QY^YY^aY^iY^qY^yY^" fullword wide
		 $s81= "Z4qZAuOHtOe42EEdbCZqhnY0ed8gY0LH7KQoPsXve4QOqCi5pz5sSN2bdtD1Pe5SRf5Q0/VDvmOm8jBhiI4F9kJxtK0uEJEqrUeY" fullword wide
		 $s82= "zlfXwjl3Nu+xPuI3ZpNflpgLMt7Dh6Rt0cOJs2uyl0Z+/JvtsAj5X4YgN7tWLk9iJoWZTU1PHspkTBCanNtB6A==" fullword wide

		 $hex1= {247331303d20222d20}
		 $hex2= {247331313d20226149}
		 $hex3= {247331323d20224153}
		 $hex4= {247331333d20224173}
		 $hex5= {247331343d20224153}
		 $hex6= {247331353d20222d20}
		 $hex7= {247331363d20222d20}
		 $hex8= {247331373d20226156}
		 $hex9= {247331383d20224247}
		 $hex10= {247331393d2022426c}
		 $hex11= {2473313d2022306475}
		 $hex12= {247332303d20224361}
		 $hex13= {247332313d20222f63}
		 $hex14= {247332323d20226438}
		 $hex15= {247332333d20226439}
		 $hex16= {247332343d20226565}
		 $hex17= {247332353d20222865}
		 $hex18= {247332363d20226631}
		 $hex19= {247332373d20222d20}
		 $hex20= {247332383d20226671}
		 $hex21= {247332393d20226765}
		 $hex22= {2473323d20222f304e}
		 $hex23= {247333303d2022684c}
		 $hex24= {247333313d2022686d}
		 $hex25= {247333323d2022685a}
		 $hex26= {247333333d2022496e}
		 $hex27= {247333343d20226b63}
		 $hex28= {247333353d20224b48}
		 $hex29= {247333363d20226b55}
		 $hex30= {247333373d20226c4d}
		 $hex31= {247333383d20224c71}
		 $hex32= {247333393d20226d61}
		 $hex33= {2473333d2022345538}
		 $hex34= {247334303d2022404d}
		 $hex35= {247334313d20224e47}
		 $hex36= {247334323d20222d20}
		 $hex37= {247334333d20222d20}
		 $hex38= {247334343d20222d20}
		 $hex39= {247334353d20222d20}
		 $hex40= {247334363d20222d20}
		 $hex41= {247334373d20222d20}
		 $hex42= {247334383d20222d20}
		 $hex43= {247334393d20226e75}
		 $hex44= {2473343d202234774b}
		 $hex45= {247335303d20226f2f}
		 $hex46= {247335313d20227064}
		 $hex47= {247335323d2022506c}
		 $hex48= {247335333d2022704c}
		 $hex49= {247335343d20225072}
		 $hex50= {247335353d20222d20}
		 $hex51= {247335363d2022507a}
		 $hex52= {247335373d20225148}
		 $hex53= {247335383d2022516c}
		 $hex54= {247335393d20227173}
		 $hex55= {2473353d2022354268}
		 $hex56= {247336303d20225233}
		 $hex57= {247336313d20225276}
		 $hex58= {247336323d20227334}
		 $hex59= {247336333d20225365}
		 $hex60= {247336343d20225365}
		 $hex61= {247336353d2022734c}
		 $hex62= {247336363d20227373}
		 $hex63= {247336373d20225379}
		 $hex64= {247336383d20225468}
		 $hex65= {247336393d20225468}
		 $hex66= {2473363d2022354565}
		 $hex67= {247337303d20225468}
		 $hex68= {247337313d2022556e}
		 $hex69= {247337323d20222d20}
		 $hex70= {247337333d20222d20}
		 $hex71= {247337343d20222d20}
		 $hex72= {247337353d20225558}
		 $hex73= {247337363d2022565a}
		 $hex74= {247337373d2022576d}
		 $hex75= {247337383d20227756}
		 $hex76= {247337393d20227871}
		 $hex77= {2473373d2022376239}
		 $hex78= {247338303d20222159}
		 $hex79= {247338313d20225a34}
		 $hex80= {247338323d20227a6c}
		 $hex81= {2473383d202237424b}
		 $hex82= {2473393d2022374f79}

	condition:
		10 of them
}
