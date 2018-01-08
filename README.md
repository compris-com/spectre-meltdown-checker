# Spectre-Meltdown-Checker

Spectre-Meltdown-Checker is currently a Windows utility for checking the state of the software mitigations against CVE-2017-5754 (Meltdown) and hardware mitigations against CVE-2017-5715 (Spectre). It uses two new information classes that were added to the NtQuerySystemInformation API call as part of the recent patches introduced in January 2018 and reports the data as seen by the Windows Kernel. 
This module implements a checker app for CVE-2017-5754 and CVE-2017-5715.
It does not require Windows Powershell or any plugins but runs as simple
binary.
It is currently optimized for Microsoft Windows 7-10, but there are plans
to add a Linux version. On Windows it uses the best-working exploit code
(from Eugnis) and combines it with Windows 7-10 processor feature detection
code from Alex Ionescu.

An [official](https://support.microsoft.com/en-us/help/4073119/windows-client-guidance-for-it-pros-to-protect-against-speculative-exe) Microsoft Powershell Cmdlet Module now exists as well.

## Screenshots

![Screenshot](SpecuCheckColors.png)

## Introduction

On January 3rd 2018, Intel, AMD and ARM Holdings, as well as a number of OS Vendors reported a series of vulnerabilities that were discovered by Google Project Zero:

* Variant 1: Bounds check bypass (CVE-2017-5753)
* Variant 2: Branch target injection (CVE-2017-5715)
* Variant 3: Rogue data cache load (CVE-2017-5754)

Microsoft released patches for Windows 7 SP1 and higher later that same day. These patches, depending on architecture, OS version, boot settings and a number of hardware-related properties, apply a number of software and hardware mitigations against these issues. The enablement state of these mitigations, their availability, and configuration is stored by the Windows kernel in a number of global variables, and exposed to user-mode callers through an undocumented system call.

Spectre-Meltdown-Checker takes advantage of this system call in order to confirm if a system has indeed been patched (non-patched systems will fail the call) and what the status of the mitigations are, which can be used to determine potential performance pitfalls.

## Details of the vulnerabilities

Spectre breaks the isolation between different applications. It allows an attacker to trick error-free programs, which follow best practices, into leaking their secrets. In fact, the safety checks of said best practices actually increase the attack surface and may make applications more susceptible to Spectre.
We're putting the characters from 0 to 100 into memory and then we're trying to read it using the exploit. If the system is vulnerable, you'll see same text in the output, read from memory.
***
In this code, if the compiled instructions in `victim_function()` were executed in strict program order, the function would only read from `array1[0..15]` since array1 size = 16. 
However, when executed speculatively, out-of-bounds reads are possible. The read memory `byte()` function makes several training calls to `victim_function()` to make the branch predictor expect valid values for x, then calls with an out-of-bounds x. The conditional branch mis-predicts, and the ensuing speculative execution reads a secret byte using the out-of-bounds x. The speculative code then reads from `array2[array1[x] * 512]`, leaking the value of `array1[x]` into the cache state. To complete the attack, a simple flush+probe is used to identify which cache line in `array2` was loaded, revealing the memory contents. The attack is repeated several times, so even if the target byte was initially uncached, the first iteration will bring it into the cache. 
The unoptimized code reads approximately 10KB/second on an i7 Surface Pro 3.

## Motivation

There was originally a lot of noise, hype, and marketing around this issue, and not a sufficient amount of documentation on how to see if you were affected, and at what performance overhead. Spectre-Meltdown-Checker aimed to make that data easily accessible to users and IT departments, to avoid having to use a Windows debugger or reverse engineer the APIs themselves.

Since then, Microsoft has done great work to expose that data from the kernel-mode in a concise matter, which succinctly indicates the kernel's support and usage of the various mitigating technologies and hardware features, and released a PowerShell CmdLet Module to retrieve that data. Spectre-Meltdown-Checker does not require the installation of such CmdLets, e.g. for environments where it might be a security issue.
It also uses the best available exploit code to check for the issues without doing any harm.

## Installation on Windows

To run Spectre-Meltdown-Checker, simply execute it on the command-line:

`c:\Spectre-Meltdown-Checker.exe`

Which will result in an informational screen indicating which features/mitigations are enabled. If you see the text:

`Your system either does not have the appropriate patch, or it may not support the information class required`

This indicates that your system is not currently patched to mitigate against these vulnerabilities.

## References

Alex Ionescu: If you would like to know more about my research or work, I invite you check out my blog at [http://www.alex-ionescu.com](http://www.alex-ionescu.com) as well as my training & consulting company, Winsider Seminars & Solutions Inc., at [http://www.windows-internals.com](http://www.windows-internals.com).

Compris Technologies: An IT consulting company with focus on IT security and IT architecture consulting. Contact: [http://www.compris.com] (http://www.compris.com).

You should also definitely read the incredibly informative [Project Zero Post](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html).

Finally, for additional information on the appropriate and required Windows patches, please read the [Microsoft Advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002).

Further infos:

1. Meltdown paper: <https://meltdownattack.com/meltdown.pdf>
2. Meltdown exploit info: <https://meltdownattack.com> 
3. Spectre paper: <https://spectreattack.com/spectre.pdf> 
4. Spectre exploit info: <https://spectreattack.com> 
5. CVE-2017-5753: <http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-5753> 
6. CVE-2017-5715: <http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-5715> 
7. Eugnis Spectre Attack, Basis 1: https://github.com/Eugnis/spectre-attack 
8. SpecuCheck, Basis 2: https://github.com/ionescu007/SpecuCheck 
9. This repository: https://github.com/compris-com/spectre-meltdown-checker 


## Caveats

Spectre-Meltdown-Checker relies on undocumented system calls and information classes which are subject to change. Additionally, Spectre-Meltdown-Checker in its second part returns the information that the Windows Kernel is storing about the state of the mitigations and hardware features -- based on policy settings (registry, boot parameters) or other compatibility flags, the Windows Kernel's state may not match the true hardware state.

Spectre-Meltdown-Checker is only a research tool.

## License

```
Copyright 2018 Alex Ionescu, Eugnis and Thomas Poetter. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met: 
1. Redistributions of source code must retain the above copyright notice, this list of conditions and
   the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
   and the following disclaimer in the documentation and/or other materials provided with the 
   distribution. 

THIS SOFTWARE IS PROVIDED BY ALEX IONESCU / Eugnis / Thomas Poetter ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX IONESCU
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Alex Ionescu / Eugnis / Thomas Poetter.
```
