# RflDllOb - Bambini
Reflective DLL Injection - M++

Reflective DLL and its very personal Injector. 
Please refer to [my blog](https://oldboy21.github.io/posts/2023/12/all-i-want-for-christmas-is-reflective-dll-injection/) about this development journey. 


# RflDllOb - Next Gen

Finally after months of research, the pumped-up version of RflDll-Ob is available. Couple of things to keep in mind: 
* It works only with the logic implemented in this [Injector](https://github.com/oldboy21/RflDllOb/tree/main/RflDllOb-NG/ReflectiveDLLInjector-NG).  
* Code is not perfect, might definitely contain some errors, if you want use it please review first. Do not do nasty stuff though, educational purposes only! 

This version is based on the following: 

* [YOLO: You Only Load Once](https://oldboy21.github.io/posts/2024/01/yolo-you-only-load-once/)
* [Reflective DLL Got Indirect Syscall skills](https://oldboy21.github.io/posts/2024/02/reflective-dll-got-indirect-syscall-skills/) 
* [SWAPPALA: Why Change When You Can Hide?](https://oldboy21.github.io/posts/2024/05/swappala-why-change-when-you-can-hide/) 
* [SLE(A)PING Issues: SWAPPALA and Reflective DLL Friends Forever](https://oldboy21.github.io/posts/2024/06/sleaping-issues-swappala-and-reflective-dll-friends-forever/) 
* [Timer Callbacks Spoofing to Improve your SLEAP and SWAPPALA Untold](https://oldboy21.github.io/posts/2024/09/timer-callbacks-spoofing-to-improve-your-sleap-and-swappala-untold/)

## Sit down, I will tell you a story

If you do not want to read my blogs and miss all the memes and the GIFs: 

This is about an R&D journey that started naturally, just as a pure passion of knowing something more about a topic. Some months ago I picked Reflective Loading as topic to dissect and learn more about. Why Reflective Loading? Well, old but gold. It is some years old but still very widely used among the good and (unfortunately) bad players in this cyber game. Although widely used, I felt like there were not many resources deeply explaining the idea around it, so couple of days before Christmas I wrote a “definitely too long” blog and I have published repository where I explain step by step the Reflective Loading process among the other challenges. Really fun and great feedback. Motivated by that feeling of sharing something nice with the community I have kept working on it, kinda wandering through spot ideas inspired by detections, other talks, open source community or just a beer with a colleague. Without knowing, I was sailing towards a nice R&D adventure. First challenge I have picked was hiding the ReflectiveLoader function. That is the position independent code (PIC) function that loads the DLL in memory, core of this whole concept. Sometimes its logic is detected, even just by static analysis so I decided to implement YOLO (You Only Load Once). The idea relies on the fact you need the Reflective Loader function only once, hence finding the function boundaries parsing PE headers, I was able to encrypt it before the injection, decrypt it in memory when i needed it and discard it once it came the moment of loading. Cool, in Italy we say “The more I eat the bigger my appetite gets,” so the next idea was to implement indirect syscalls for the whole loading process. I have picked the “what I thought to be the most reliable method” to enumerate SSN (FreshyCalls and Syswhysperer3) and dove completely into the challenge of enumerating syscall identifiers using PIC. Not as painful as fun, once I overcame the stack size challenges with some math, the Reflective Loader was loading the DLL bypassing user-land hooks with a mix of PIC C++ and Assembly. The final villain(s) were waiting at the end of the journey: in-memory scanners. Here is where my research intensified, inspired by Sektor7 course and Ekko sleep, I was dreaming of a Reflectively loaded DLL that would hide itself in memory by swapping with a legit DLL at the same address. But what were the challenges? A DLL loaded via LoadLibraryA has its handles (File/Section) closed by the end of the function, and mapping a DLL without using LoadLibraryA would require annoying PEB manipulation and lots of IOC. Furthermore, in-memory sleeping technique using Windows timers like Ekko, does not support Windows APIs that take more than 4 arguments (due to the fact a single thread is used and the ROP chain contexts point to the same stack). Scary times.

For what it concerned the missing Section handle, hardware breakpoint came to the rescue. By hooking and detour-ing the ZwClose function, I was able to keep a connection with the kernel object by forcing ZwClose to return before it reached the point where it would have closed the handle. By reversing the code of System Informer (former Process Hacker) I found a way to get my hands back to that handle too. Phew, the logic of swapping malicious and sacrificial DLL turned out to be possible and that was named SWAPPALA right away.

Honestly excited by the first achievement, I was moving forward to the next challenge of creating a sleep mask that would match the SWAPPALA logics: mapping a section to a specific address requires the usage of MapViewOfFileEx Win API that is not compatible with the actual implementation of Ekko sleep due to the amount of arguments required for its correct operation.

Before having my own successful implementation I had adapted Ekko sleep mask to my needs, coming up with EkkoQua which uses duplicated stack for two of the functions part of the sleeping ROP chain in order to handle Win32 APIs that takes more than 4 arguments (Little pills of Windows calling convention here). Despite limited success with EkkoQua, some tests made me realize that EkkoQua does not work in the context of processes with enabled security protections as stack cookie, control flow guard (despite whitelisting NtContinue as valid targets) etc. After realizing that NtContinue also ignores the debug registers (hence officially destroying another idea I had) I have decided to drop the goal of adapting existing sleep mask and come up with my own: SLE(A)PING.

SLEAPING makes use of timer thread workers in order to resume threads I had previously created in a suspended state and with a crafted context. This time the threads working during the “Sleep” time have their own stack so they do not step on each other, moreover as bonus point the ResumeThread function (as substitute for NtContinue) used by the timer thread does not need to be added as a valid target in the Control Flow Guard table, meaning one less IOC.

Last update (September 2024) also includes the logic for spoofing the callback address of the OS timers used to implement SLEAPING technique. This makes RflDllOb-NG more resilient against in-memory scanners by modifying the timer callback addresses at sleeping time. 

To conclude: SWAPPALA and SLEAPING are used to load the reflective DLL in a private mapping backed by physical memory and swap-it with a memory mapping backed by a legit DLL on disk, at its very own legit address. All of this orchestrated at sleeping time by worker threads created in a suspended state and resumed via OS timers.

## RflDllOb-NG VS In-memory Scanners

Results at the time of the commit, who knows how it is going to be (!?)

![HSB](https://raw.githubusercontent.com/oldboy21/RflDllOb/main/imgs/hsb.png?raw=true)

![Moneta](https://raw.githubusercontent.com/oldboy21/RflDllOb/main/imgs/moneta.png?raw=true)

![pesieve](https://raw.githubusercontent.com/oldboy21/RflDllOb/main/imgs/pesieve.png?raw=true)

## Little Demo

This demo helps to understand how the Reflective DLL Ob hides itself behind a legit dll at sleeping time. 

[![Reflective DLL Next Gen](https://raw.githubusercontent.com/oldboy21/RflDllOb/main/imgs/rfldllobng.png)](https://vimeo.com/955537475?share=copy)

Fun fact: at a certain point in the video, exactly when the Reflective DLL mapping pops up, the song "Suddenly I see" of KT Tunstall starts playing. Nothing of that was planned in advance. 