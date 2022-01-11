
# resteex_yara_rules

resteex_yara_rules is the YARA signature and IOC database for our scanners [resteex_scanner]

resteex_yara_rules is a project created to make the possibility of static malware analysis open and available to the public. resteex_yara_rules the objective to achivement the zero risk with conduct resteex_yara_rules in threat hunting or incident response or researching .

## Focus of resteex_yara_rules

1. High quality YARA rules and IOCs with minimal false positives
2. Clear structure
3. Consistent rule format

## Directory Structure

- resteex_yara_rules
                    -theZoo


## free High Quality YARA Rules Feed and **resteex_yara_rules is open and welcoming visitors!** [CODE-OF-CONDUCT][https://github.com/resteex0/resteex_yara_rules/blob/main/CONTRIBUTING.md]

If you are about to interact with our community please make sure to read our `CODE-OF-CONDUCT.md` prior to doing so. If you plan to contribute, first - thank you. However, do make sure to follow the standards on `CONTRIBUTING.md

If you liked my rules and want generating free public custom yara rules not detected with rules already in [https://github.com/resteex0/resteex_yara_rules] or want to build big data yara rule databse with my generator with custom malware files as minum 10000 sample , please zipping your malware files at minumum 10000 sample with any instruction to run it or sys env info, i will ignour any true postive with my yara rules and not accepted ,

please contact me with resteex0@gmail.com
or publish you malware files samples or links with our issue link https://github.com/resteex0/resteex_yara_rules/issues

## Getting Started

#requirements:
<code>sudo apt-get install yara</code><br>

#option 1

<code>sudo git clone https://github.com/resteex0/resteex_yara_rules.git</code><br>
<code>sudo cd resteex_yara_rules</code><br>
<code>sudo ls resteex_yara_rules/theZoo|awk '{print $9}'|while read A ; do yara resteex_yara_rules/theZoo/$A test3 2>&1;done</code><br>

#option 2 (recommended)

<code>sudo git clone https://github.com/resteex0/resteex_yara_rules.git</code><br>
<code>sudo cd resteex_yara_rules</code><br>
<code>sudo ./resteex_scanner.sh resteex_yara_rules test3</code><br>

##Auditing and calibration 

after option 2 as first should be have detect as some :

<code>resteex_Form_A test3/AntiExe.A/Anti_Exe_BOOT.txt
resteex_EquationGroup_EquationLaser test3/BlackEnergy2.1/rootkit.ex1
resteex_Ransomware_WannaCry test3/BlackEnergy2.1/rootkit.ex1
resteex_TrojanWin32_Duqu_Stuxnet test3/BlackEnergy2.1/rootkit.ex1
resteex_EquationGroup_GrayFish test3/BlackEnergy2.1/rootkit.ex1
resteex_Win32_Zurgop test3/BlackEnergy2.1/rootkit.ex1
resteex_Trojan_Win32_Bechiro_BCD test3/BlackEnergy2.1/rootkit.ex1
resteex_Win32_Stuxnet_A_Duqu_C_Media test3/BlackEnergy2.1/rootkit.ex1
resteex_Nitlove test3/BlackEnergy2.1/rootkit.ex1
resteex_Trojan_Bladabindi test3/BlackEnergy2.1/rootkit.ex1
resteex_Somoto test3/BlackEnergy2.1/rootkit.ex1
resteex_EquationGroup_GROK test3/BlackEnergy2.1/rootkit.ex1
resteex_Ransomware_RedBoot test3/BlackEnergy2.1/rootkit.ex1
resteex_Artemis test3/BlackEnergy2.1/rootkit.ex1
resteex_Win32_Unclassified test3/BlackEnergy2.1/rootkit.ex1
resteex_Trojan_Regin test3/BlackEnergy2.1/rootkit.ex1</code>


## FAQs

### can getting free custom yara rules?

yea , see above https://github.com/resteex0/resteex_yara_rules/blob/main/README.md#free-high-quality-yara-rules-feed

### How can I help with bugs in rules?

so sorry , our rules is very uniq rules in the world , generating by our generator [resteex generator] very uniq to generating highly quality rules , is private and not for sell

## Disclaimer

resteex_yara_rulespurpose is to allow the study and detect of malware and enable people who are interested in malware analysis (or maybe even as a part of their job) to have access to live malware, analyse the ways they operate, and maybe even to block specific malware within their own environment.

**Please remember that these are live and dangerous malware! They come encrypted and locked for a reason!  Do NOT run them unless you are absolutely sure of what you are doing! They are to be used only for educational purposes or in production env. to detect and clean (and we mean that!) !!!**dangerous malware!!!** , the rules is core EDR or antivirus .

We recommend running them in a VM which has no internet connection (or an internal virtual network if you must) and without guest additions or any equivalents. Some of them are worms and will automatically try to spread out. Running them unconstrained means that you **will infect yourself or others with vicious and

## License

https://github.com/resteex0/resteex_yara_rules/blob/main/LICENSE
