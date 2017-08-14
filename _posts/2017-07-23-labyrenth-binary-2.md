---
layout: default
title:  "Labyrenth 2017 Binary Track Walkthrough - Gotta go fast! edition: Level 2"
date:   July 23, 2017
---

# Level 2: LabyTime.exe

### Description:
```
You walk to the south...
A goblin made of gears blocks your way, forcing you to complete a
challenge to continue.
7z Download
7z Password: labyrenth
Hint: Alice, follow the clockmaker into the rabbit hole ->
labytime.com
Author(s): @theenergystory, @apatrid

http://dl.labyrenth.com/totp/d5214f8a516fb9b6d25cf7ba0a8c8df01720710c39cc3a8f53f2acf44100c7a5.7z
```
[Alternate binary download link](https://github.com/fevral/theJunkyard/tree/master/labyrenth2017/binary)

## Step 0: Hints
Well, ok...what's at labytime.com?

![labytime](/images/labyrenth2017/binary/2-labytime.png)

and inspecting the page source reveals nothing more. Presumably, we will submit whatever flag we find to this website and get the real flag in return or some confirmation that we have the right flag.

## Step 1: Initial triage & recon

Good finds on the usual file and strings:
```
$ file LabyTime.exe 
LabyTime.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

and the highlights from strings, and strings -e l:

```
24.56.178.140
128.138.140.44
128.138.141.172
216.228.192.69
216.229.0.179
198.111.152.100
64.113.32.5
IsDebuggerPresent
OutputDebugStringW
MessageBoxW
PAN{!?!BetterBeLittleCrazyThanLittleSmart!?!}
Time is tight so start from 0 sec and use the dbg hints
LabyTime CTF challenge
```

Hmm OutputDebugStringW and the 'use the dbg hints'

Tracking down the "Time is tight" string (see [Level 1](/2017/07/24/labyrenth-binary-1) strings xref approach), we end up at what looks like the main functionality. We rename this function (0x401970) ctfMain.


Again, there are many calls to dwords that have yet to be populated.


We explore the neighbourhood again, and find the import resolver function early on

```
.text:00401970 push    ebp
.text:00401971 mov     ebp, esp
.text:00401973 sub     esp, 4Ch
.text:00401976 call    sub_401040
.text:0040197B test    eax, eax
.text:0040197D jnz     short loc_40
```

Taking a quick look inside, it does a whole bunch of:

```
.text:004011D8 mov     ecx, offset unk_4162D0
.text:004011DD call    sub_401000
.text:004011E2 push    eax             ; lpProcName
.text:004011E3 push    edi             ; hModule
.text:004011E4 call    esi ; GetProcAddress
.text:004011E6 mov     dword_417184, eax
.text:004011EB test    eax, eax
.text:004011ED jz      short loc_401220
```

It loads some encrypted string...passes it to sub_401000 to decrypt, and then resolves the address, storing it in one of the dwords.

## Step 2: Dynamic Analysis

Ok...let's just run the this thing until we return from the import resolver and see what's going on. It wouldn't hurt to have [fakenet](https://practicalmalwareanalysis.com/fakenet/), [fakenet-ng](https://github.com/fireeye/flare-fakenet-ng), or [wireshark](https://www.wireshark.org/download.html) running, because of those ip addresses we saw in the strings. We'll explore these once we've resolved all these mystery dwords.

With ScyllaHide ready to cover our dynamic approach, we click on 0x40197D and pres F4 to run to cursor.

Program rebased, it's no problem, but you can rebase if you'd like (Edit-> Segments -> Rebase program). We go on a renaming and MSDN reading spree with our new information.

Before we dig into the neighbouring functions, we take note of a few interesting things about this one.

This is the func that never ends:


![it-goes-on-and-on](/images/labyrenth2017/binary/2-it-goes-on-and-on.png)

yes, it goes on and on, my friends.

...but even more important is the start of the basic block that leads to this loop:

```
.text:00E51986
.text:00E51986 loc_E51986:
.text:00E51986 push    esi
.text:00E51987 push    offset sub_E51AB0
.text:00E5198C push    1
.text:00E5198E call    AddVectoredExceptionHandler
.text:00E51994 mov     esi, [ebp+hInstance]
.text:00E51997 push    7F00h
.text:000E199C push    0
.text:000E199E mov     [ebp+var_4C], 30h
.text:000E19A5 mov     [ebp+var_48], 23h
.text:000E19AC mov     [ebp+var_44], offset sub_E1B10
.text:000E19B3 mov     [ebp+var_40], 0
.text:000E19BA mov     [ebp+var_3C], 0
.text:000E19C1 mov     [ebp+var_38], esi
.text:000E19C4 call    LoadIconW
.text:000E19CA push    7F00h
```

[Adding vectored exception handlers](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679274(v=vs.85).aspx)...

Inside the function registered as the exception handler (sub_E51AB0), the bettercrazythansmart string makes an appearance. We rename with a best guess, or at least a unique name, set a breakpoint at the top in case exceptions are triggered, then we go take another look at ctfMain.

...and what is this sub_E1B10? We take a look inside:


![jump-table](/images/labyrenth2017/binary/2-jump-table.png)

a jump table, and this weird few blocks to the left...it isn't obvious how this code will ever be reached.

We go on another renaming spree, and find that the seemingly unreachable code calls some interesting functions:


![get-rect](/images/labyrenth2017/binary/2-get-rect.png)

We head over to MSDN to get rect, but not before setting a breakpoint on [TextOutA](https://msdn.microsoft.com/en-us/library/windows/desktop/dd145133(v=vs.85).aspx).

Back in ctfMain, we set a breakpoint just before the TranslateMessage/DispatchMessage loop...and let's see what happens when we run it.


![privilged-instruction](/images/labyrenth2017/binary/2-privileged-instruction.png)

Hmm...ok then.

We click ok and find ourselves in this interesting situation:

```
.text:000E1878 mov     dword ptr [ebp-98h], 0
.text:000E1882 call    sub_E2E00
.text:000E1887 add     esp, 4
.text:000E188A lea     edx, [ebp-0ACh]
.text:000E1890 lea     ecx, [ebp-50h]
.text:000E1893 call    sub_E2EB0
.text:000E1898 cli
.text:000E1899 mov     ebx, [ebp-0B4h]
.text:000E189F xor     edi, edi
.text:000E18A1 mov     esi, offset a?Betterbelittl     ; "!?!BetterBeLittleCrazyThanLittleSmart!?"...
.text:000E18A6 jmp     short loc_E18B0
```

the cli instruction at 0xE1898 is where EIP currently points to, this is the instruction that triggered the exception.

Why?

We google a bit "cli instruction x86 privileged instruction"

and we [learn](https://en.wikipedia.org/wiki/Interrupt_flag#Privilege_level)

```
CLI and STI are privileged instructions, which trigger a general protection fault if an unprivileged application attempts to execute it
```

Ok...but why?

Back to google throwing in a sprinkling of "malware" in our previous search query:

Answers!
- [1](https://securityintelligence.com/tilon-son-of-silon/)
- [2](https://repo.zenk-security.com/Reversing%20.%20cracking/Control%20Flow%20Obfuscations%20in%20Malwares.pdf)
- [3](https://deepflash.blogspot.ca/2013/12/anti-debugging-tricks-and-control-flow.html)

So it's a control flow obfuscation technique, and this program was designed to run in this weird way. Maybe that's how we reach that TextOutA code we were curious about earlier.


So, we continue with F8, and IDA wants to know what do:

![change-definition](/images/labyrenth2017/binary/2-change-definition.png)

Click on change exception definition, and select Pass to application, with logging.

![log-exception](/images/labyrenth2017/binary/2-log-exception.png)

The next time we hit this exception, IDA's debugger will just let the program handle this, and we can see where it goes.

Clicking "Yes Pass to app" this time, takes us to the breakpoint we set at the top of the exception handler.

We step through, and when it returns, we are in ntdll. We're not terribly interested in being inside library functions, so we press Ctrl+F7 to run until return, until we are back in the user code.

...but along the way:


![illegal-exception](/images/labyrenth2017/binary/2-illegal-exception.png)

there is an attempt to execute an illegal instruction.

This time, there isn't much to know about this 0xFF opcode that triggered the illegal instruction. It's likely just part of the control flow obfuscation and just another excuse to dive back into the exception handler and take a different branch this time.

We change the exception definition to let the application handle it, and continue debugging.

Debugger -> Debugger Options -> Edit exceptions 

We locate ILLEGAL and set it up the same as privileged.

![illegal-definition](/images/labyrenth2017/binary/2-illegal-definition.png)

Indeed, the exception handler takes a different branch this time.

![different-branch](/images/labyrenth2017/binary/2-different-branch.png)

We Ctrl+F7 back to user code and end up back in the exception handler. We keep stepping and...


```
.text:000E1C23
.text:000E1C23 loc_E1C23:
.text:000E1C23 push    1
.text:000E1C25 lea     eax, betterCrazy[edi]
.text:000E1C2B push    eax
.text:000E1C2C push    0Ch
.text:000E1C2E push    esi
.text:000E1C2F push    ebx
.text:000E1C30 call    TextOutA
.text:000E1C36 add     esi, 0Ah
.text:000E1C39 lea     edi, [edi+1]
.text:000E1C3C cmp     esi, 1CEh
.text:000E1C42 jl      short loc_E1C2
```

We hit TextOutA. We know the fourth argument (see MSDN link above) is the string that will be written. It is whatever was loaded into eax.

Double-clicking eax:

```
.data:000F6190 betterCrazy db  50h ; P                 ; DATA XREF: sub_E1B10+115o
.data:000F6191 db  41h ; A
.data:000F6192 db  4Eh ; N
.data:000F6193 db  7Bh ; {
.data:000F6194 a?Betterbelittl db '40dcf8e2e8c58971a4694c3ac0decc6e7d983232}',0
```

That...looks very much like a flag. It can look a little better if we click on the start of the string and let IDA know that it is a string by pressing a

```
.data:000F6190 betterCrazy db 'PAN{40dcf8e2e8c58971a4694c3ac0decc6e7d983232}',0
```

We seem to be stuck in a loop, so we go ahead and right click on our breakpoints to disable them and let the program continue.

The program can now draw the window, we see it is flashing a lot of flags into the text box and the console output shows that we are continuously visting the exception handler. We also notice the debug message 

```
Debugged application message: 17-06-25 23:43:57
```

So time 0 was UTC timestamp...that's being hashed to produce this flag. The IP addresses were time servers (which we can confirm by googling the IP address).

Perhaps labytime.com wants one of these flags, but how do we get it fast enough?

Debugger hooks!

We can put a trace breakpoint on the TextOutA call, print the value of eax and the program will continue running.

There are many ways to approach the problem at this point, here is the one I used:

Noting that the length of the flag, and its address are constant, we enable the TextOutA breakpoint, but disable the Break (right-click the breakpoint and select edit)


![edit-breakpoint](/images/labyrenth2017/binary/2-edit-breakpoint.png)

```
from idaapi import *

class MyDbgHook(DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        RefreshDebuggerMemory()
        # 0xF6190 is what eax points to when this breakpoint is hit (during this run of the program)
        shiftyFlag = GetManyBytes(0xF6190, 45)
        print shiftyFlag
        return 0


debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
```

With the breakpoint set properly, press Shift+F2 or File -> Script Command

then paste this debugger hook into the script window and press run.

now, get labytime.com ready and be quick on the copy-paste from the console output (or add a little more python to submit the flag to the website for you):

```
Break point at 0x61c30 pid=3324
PAN{25d839aeef1576de3a8c40aea6da25123c3d5ae7}
```

![win](/images/labyrenth2017/binary/2-win.png)

Note that we could also retrieve the value of eax with [GetRegValue](https://www.hex-rays.com/products/ida/support/idadoc/169.shtml).

### References:


1. [fakenet](https://practicalmalwareanalysis.com/fakenet/)
2. [fakenet-ng](https://github.com/fireeye/flare-fakenet-ng)
3. [wireshark](https://www.wireshark.org/download.html)
4. [Adding vectored exception handlers](https://msdn.microsoft.com/en-us/library/windows/desktop/ms679274(v=vs.85).aspx)
5. [TextOutA](https://msdn.microsoft.com/en-us/library/windows/desktop/dd145133(v=vs.85).aspx)
6. [Privilege Level - CLI](https://en.wikipedia.org/wiki/Interrupt_flag#Privilege_level)
7. [Tilon: Son of Tilon](https://securityintelligence.com/tilon-son-of-silon/)
8. [Control Flow Obfuscations in Malware](https://repo.zenk-security.com/Reversing%20.%20cracking/Control%20Flow%20Obfuscations%20in%20Malwares.pdf)
9. [Anti-debugging tricks](https://deepflash.blogspot.ca/2013/12/anti-debugging-tricks-and-control-flow.html)
10. [IDA Python Stack Exchange](https://reverseengineering.stackexchange.com/questions/13383/how-ca
n-i-set-breakpoint-and-get-value-of-a-register-with-idapython)
11. [IDA Python - debughook.py](https://github.com/idapython/src/blob/master/examples/debughook.py)
12. [GetRegValue](https://www.hex-rays.com/products/ida/support/idadoc/169.shtml)

