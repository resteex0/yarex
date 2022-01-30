# Yarex

yarex is new face of uniq yara rule and is the YARA signature and IOC database for our scanners [resteex_scanner]

yarex is a project created to make the possibility of static malware analysis open and available to the public. yarex the objective to achivement the zero risk with conduct yarex in threat hunting or incident response or researching .

## Focus of Yarex

1. High quality YARA rules and IOCs with minimal false positives
2. Clear structure
3. Consistent rule format

#free High Quality YARA Rules Feed and **yarex is open and welcoming visitors!** [CODE-OF-CONDUCT][https://github.com/resteex0/yarex/blob/main/CONTRIBUTING.md]

If you are about to interact with our community please make sure to read our `CODE-OF-CONDUCT.md` prior to doing so. If you plan to contribute, first - thank you. However, do make sure to follow the standards on `CONTRIBUTING.md

If you liked my rules and want generating free public custom yara rules not detected with rules already in [https://github.com/resteex0/yarex] or want to build big data yara rule databse with my generator with custom malware files as minum 10000 sample , please zipping your malware files at minumum 10000 sample with any instruction to run it or sys env info, i will ignour any true postive with my yara rules and not accepted ,

please contact me with resteex0@gmail.com
or publish you malware files samples or links with our issue link https://github.com/resteex0/yarex/issues

## Getting Started

#requirements:
<code>sudo apt-get install yara</code><br>

# option 1

<code>sudo git clone https://github.com/resteex0/yarex.git --recursive</code><br>
<code>sudo cd yarex</code><br>
<code>sudo ls yarex/theZoo|awk '{print $9}'|while read A ; do yara yarex/theZoo/$A test3 2>&1;done</code><br>

# option 2 (recommended if researching or auditing)

<code>sudo git clone https://github.com/resteex0/yarex.git --recursive</code><br>
<code>cd yarex</code><br>
<code>unzip -Pinfected testsample.zip</code><br>
<code>cd ..</code><br>
<code>sudo yarex/./resteex_scanner.sh yarex yarex/testsample</code><br>

##Auditing and calibration 

after option 2 as first should be have detect as some :

<code>resteex_Win32_ZeroCleare yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_RedDelta yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_StrongPity yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_Unnamed_SpecMelt yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_FASTCash yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_All_ElectroRAT yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_SofacyCarberp yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_KerrDown yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_LuckyCat yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_FamousSparrow yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_MosesStaff yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Emotet yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Razy yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_REvil yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_AtomSilo yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Medusa_Locker yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Pysa yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Remcos yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Amavaldo yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Conti yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_YanluowangRansomware yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Cobalt_Strike yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Curator_Ransomware yarex/testsample/0468127a19daf4c7bc41015c5640fe1f</code><br>
<code>resteex_Win32_ZeroCleare yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_RedDelta yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_StrongPity yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_Unnamed_SpecMelt yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_FASTCash yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_All_ElectroRAT yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_SofacyCarberp yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_KerrDown yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_LuckyCat yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Win32_FamousSparrow yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_MosesStaff yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Emotet yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Razy yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Babadeda yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_REvil yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_AtomSilo yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Medusa_Locker yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Pysa yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Remcos yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Amavaldo yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Conti yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_YanluowangRansomware yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Cobalt_Strike yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>
<code>resteex_Curator_Ransomware yarex/testsample/0ceead2afcdee2a35dfa14e2054806231325dd291f9aa714af44a0495b677efc</code><br>

<a href="https://asciinema.org/a/461995" target="_blank"><img src="https://asciinema.org/a/461995.svg" /></a>

## achievements of project untile now

my project is very uniq yara rules in the world.
we was lunch until now this branch.

1- yarex_theZoo https://otx.alienvault.com/pulse/61ea1ee4e71f59a454d5b0f3<br>
2- yarex_vx-underground https://otx.alienvault.com/pulse/61e2696b21b826d5a5ac6719<br>
3- yarex_malware-sample-library https://otx.alienvault.com/pulse/61ea44d19102056f62733697<br>
4- yarex_Malware-Feed https://otx.alienvault.com/pulse/61ea9c061eb0c62aef1df72d<br>
5- yarex_APTMalware https://otx.alienvault.com/pulse/61ebb686fb654ea04bf28cd4<br>
6- yarex_APT-Sample https://otx.alienvault.com/pulse/61ec8f270e57ec3c02764e51<br>




the vision is  big hug to filling the voids of open uniq yara rules of almost malware database in the world as soon , this amids to decrease attacks and threat with increasing antivirus engines and EDR system detections and hunting to achieve the best optimization of it jobs .

this my dream to closet the attacks to small area and begin new era of cyber secure

## FAQs

### can getting free custom yara rules?

yea , see above https://github.com/resteex0/yarex/blob/main/README.md#free-high-quality-yara-rules-feed

### How can I help with bugs in rules?

so sorry , our rules is very uniq rules in the world , generating by our generator [resteex generator] very uniq to generating highly quality rules , is private and not for sell but accepted regex vision for improving generation in future

## Disclaimer

yarex is to allow the study and detect of malware and enable people who are interested in malware analysis (or maybe even as a part of their job) to have access to live malware, analyse the ways they operate, and maybe even to block specific malware within their own environment.

**Please remember that these are live and dangerous malware! They come encrypted and locked for a reason!  Do NOT run them unless you are absolutely sure of what you are doing! They are to be used only for educational purposes or in production env. to detect and clean (and we mean that!) !!!**dangerous malware!!!** , the rules is core of EDR or antivirus systems .

We recommend running them in a VM which has no internet connection (or an internal virtual network if you must) and without guest additions or any equivalents. Some of them are worms and will automatically try to spread out. Running them unconstrained means that you **will infect yourself or others with vicious and

our generator and rules very unique source code line and private , not matching with any another generator in the world , we keep the copyrights of designer and developing of yarex . 

out terminology of static classification analysis of malware is yara rule not belifing and not trust with traditional methods in market for yara generation as this link https://www.varonis.com/blog/yara-rules , static identofaction with high quality true postive with minimize false positive as possible .

many malware researching houses trust with traditional methods without think out of boxs .

https://www.varonis.com/blog/yara-rules
<code>Conditions

The strings section defines the search criteria that will be used for a YARA rule, the conditions section defines the criteria for the rule to trigger a successful match. There are multiple conditions that can be used which I will outline.

    uint16(0) == 0x5A4D – Checking the header of a file is a great condition to include in your YARA rules. This condition is stipulating that the file must be a Windows executable, this is because the hex values 4D 5A are always located at the start of an executable file header. This is reversed in YARA due to endianness.
    uint32(0)==0x464c457f) or (uint32(0) == 0xfeedfacf) or (uint32(0) == 0xcffaedfe) or (uint32(0) == 0xfeedface) or (uint32(0) == 0xcefaedfe) – Used to identify Linux binaries by checking the file header.
    (#a == 6) – String count is equal to 6.
    (#a > 6)  – String count is greater than 6

There are a few different ways to specify the file size condition.

    (filesize>512)
    (filesize<5000000)
    (filesize<5MB)

Once the strings have been declared within a rule you can then customize how many matches need to be triggered as a condition for the rule to return what it deems a successful condition.

    2 of ($a,$b,$c)
    3 of them
    4 of ($a*)
    all of them
    any of them
    $a and not $b

Where possible try and use 2-3 groups of conditions in order to avoid generating false positives and to also create a reliable rule.</code>


## project mains issue and bugs

1- the resteex generator generate sometimes uniq yara rules but have more than valid 100 variable of $strings ; we conduct on this issue to fixed in future , but the rule useful when scanning locally because yara engine accpet at maxiumu 1000 variable of $strings and our rules under this , this issue realted to https://otx.alienvault.com uploading and running . pleaes if anyone have vision for solving please follow and connect us as per CONTRIBUTING.md instructions .

2- we intial practies trainging with malware samples @vx-underground_A and will fix as stable rules in future 

## THANX to

https://avatars.githubusercontent.com/u/2851492?v=4 as inspiring style of yara rule formating from https://github.com/Neo23x0/yarGen , not any code line or another

https://github.com/ytisf/theZoo big thanx alot for ytisf team as big effort and benchmark in malware researching.

https://www.vx-underground.org/ thanks to database collection of malware

https://github.com/mstfknn/malware-sample-library 

https://github.com/MalwareSamples/Malware-Feed

https://github.com/cyber-research/APTMalware

https://github.com/Cherishao/APT-Sample

## releases

Yarex v0.20220115 https://github.com/resteex0/yarex/releases/tag/%23yarex

## License

https://github.com/resteex0/yarex/blob/main/LICENSE
