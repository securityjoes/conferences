# Watch Out! And just skip the packer Workshop

## Requirements
* Virtual machine: https://www.dropbox.com/s/hpsx2obufomsi9a/win10-x64-lab.zip?dl=0
* Malware samples: https://www.dropbox.com/s/942xrzvvpn6pch9/workshop_samples.zip?dl=0

## Definitions 
* Software packer: Tool used by software developers (malicious or not) to shield programs against reverse engineering.
* Shellcode: Small piece of code that is injected and executed directly into memory. It does not comply any of the standard executable formats, it is just code. To be executed, a shellcode requires another program acting as a loader. 
* Code substitution packer: A packer that replaces parts of the original executable mapped into memory by the OS loader.
* Code injection packer: A packer that allocates new memory sections in the same process or in additional process and writes shellcode or complete PE files that will be executed.
* Hybrid packer: A packer that implements both code substitution and injection in its logic.
* Code virtualization packer: A packer that contains a virtual machine and a copy of the program ported to a custom set of instructions (only known by the VM) that are interpreted in run-time.
* OEP: *Original Entry Point*. This is where the code execution starts in the unpacked PE.
* EIP: *Extended Instruction Pointer*. CPU registry which stores the address of the instruction to be executed.
* IAT: *Import Address Table*. PE structure that contains all the information required to correctly resolve the dependencies/libraries used by the software during its execution.
* Tail jump: Instruction in which the packer execution ends and the control flow is redirected to entry point of the unpacked sample.

## Hands-On
### Is it packed?

1. Signature-based detection:

    Depending on the packer you are facing, sometimes it is super easy to recognize it just by using static analysis tools such as [Detect It Easy](https://github.com/horsicq/DIE-engine/releases) and [PEiD](https://www.aldeid.com/wiki/PEiD). This kind of tools rely on a set of signatures known for several packers, so its performance its limited when you are dealing with a custom packer; however it is always good to try it.
    
    Below an example of this kind of detection for the UPX packer in the software Detect It Easy.
    
    ![image](https://user-images.githubusercontent.com/8562692/140227209-a93b7d07-afe6-45cf-b8d4-8229c013159c.png)


2. Strings, imports and exports analysis:

    One of the main goals of a packer is to hide the valuable code and data. This is clearly visible when you statically compare a packed and an unpacked version of a software (see below, strings of the packed sample in the left and strings of the unpacked sample in the right). The amount of interesting and valuable data that is available during the static analysis in a packed software is drastically reduced.
    
    ![image](https://user-images.githubusercontent.com/8562692/140229300-c5748c5c-2ca2-449b-825e-6d5c3710ac7b.png)

3. PE structure analysis:
    
    If you look at the sections of a PE file you will find two interesting values: *raw-size* and *virtual-size*. These values inform the OS the size of each section in disk and the required space in memoy to handle its corresponding data. 
    
    In an unpacked sample these values are comparable in magnitude, however if you are dealing with a packed sample; sometimes you could see a huge difference between those values, this is a great indicator that something is hidden. Below, the information of each PE section is provided for both the packed sample (left) and unpacked sample (right). 
    
    ![image](https://user-images.githubusercontent.com/8562692/140231353-3c6b4197-d1a2-4806-9fe7-f148ee096456.png)

4. Entropy analysis 
    
    Entropy in the context of information, can be defined as the average level of "uncertainty" in the outcome of a variable. In other words, the higher the entropy the more random a variable looks like. 
    
    This is important when you are dealing with packers, because they usually apply cryptographic algorithms to protect the data; increasing in this way the entropy of the final sample. Long story short, a sample with high entropy is more likely to have encrypted data or being packed. 
    
    See below an entropy comparison between a packed (left) and an unpacked sample (right).
    
    ![image](https://user-images.githubusercontent.com/8562692/140231605-67130b78-fdd7-4012-b0ab-5a8437dac2f5.png)

5. Dynamic results vs static characteristics:

    This validation is quite simple, just execute the sample in your VM and compare the behavior with the static characteristics of the sample (strings, imports, exports); if there's a mismatch between both analyses, it is clear that something is hiding the true nature of the sample.

### Code Substitution Packers 
*For this section of the workshop you you will use file "upx_REvil.exe".*

1. Finding the *Tail jump*

    Even though UPX is one of the easiest packers to understand and defeat, it is still being used by Threat Actors, specially as a second protection layer (yes, you can find samples protected with multiple layers of packing code). 
    
    UPX is a substitution packer, that means it replaces some of the contents of the original imaged loaded by the OS in memory, the diagram that explains this behaviour is displayed below.
    
    ![image](https://user-images.githubusercontent.com/8562692/172319593-4930f576-18b8-46ba-8bc9-85d82c5b5809.png)
    
    In this workshop, we are going to used UPX to learn one of the key concepts of unpacking; the famous *tail jump*. By definition, the *tail jump* is the instruction in which the packer execution ends and the control flow is redirected to the entry point of the unpacked sample. This jump can be implemented in several different ways, some of them are listed below:
    * `JMP OEP_ADDRESS`
    * `CALL OEP_ADDRESS`
    * `PUSH OEP_ADDRESS -> RET`

    This implementation may vary depending on the Threat Actors intensions and their skills to avoid security tools. However the main characteristic that help you recognize the *tail jump* of a packer is **"a redirection of the control flow to a section of code far from the current address"**.
    
    If you want to find the UPX *tail jump*, just start debugging an UPX-protected sample, go to the entry point of the packer and scroll down; you will see a JMP instruction right before a bunch of 0x0000 OPCODES. See the picture below.

![image](https://user-images.githubusercontent.com/8562692/140300397-5854440d-2311-42a8-9abf-7bd369d2a86b.png)

2. The importance of [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

    Based on its documentation, *VirtualProtect* is a Windows API that allows to "change the protection on a region of committed pages in the virtual address space of the calling process". This is quite important when dealing with packers because they constantly update the protections of all the different memory pages that are used in the unpacking logic in order to write and execute the original code.
    
    In the case of UPX, it uses this API a few lines of code before hitting the *tail jump*. You could think that this only happens in UPX, but it is actually very common, packers usually call *VirtualProtect* in the code that is close to its tail jump, so you need to keep alway an eye on this API. 

3. Finding the OEP

    Once you have found the *tail jump*, just step into it by hitting the F7 key, you will be redirected to the entry point of the unpacked sample, the OEP. 
    
    Below the OEP of the executable "packed_remcos.exe" is shown.

![image](https://user-images.githubusercontent.com/8562692/140296467-f52c33bc-e035-449a-98c6-f6e649d62b73.png)

4. Dumping unpacked PE

     Now that you are in the OEP, you just need to extract the contents of the original executable and save it to disk. This can be achieved using the plugin OllyDumpEx.
     
     To use it just go to Plugins > OllyDumpEx > Dump process; in the new window, click in "GET EIP as OEP",  which basically instructs the software to set the address of the current instruction as the entry point of the dumped executable, then click Dump and choose the path where you want to store the new executable.

![image](https://user-images.githubusercontent.com/8562692/140296704-79976741-317b-4a01-8e8a-d916d537de37.png)

5. Fixing IAT

    One of the main differences between an executable mapped into memory and its image on disk is the way imports are handled. In the case of a PE file on disk, it contains a structure called the IAT (Imports Address Table) that stores the information of all the required dlls for the software to work. This structure does not exist in memory, instead, it is replaced by the actual images of every dll listed in the original IAT.
    
    Now that we have dumped a PE from memory, we need to fix/rebuild its IAT otherwise it will not work. To do so, just go to Plugins > Scylla, and in the new window click on "IAT Autosearch", then click on "Get Imports", wait until all the dlls required by the unpacked sample are listed and finally click on "Fix Dump" and load the previously dumped PE. If done correctly, this process will generate a working copy of the unpacked sample that you can debug and analyze using any tool you want.

![image](https://user-images.githubusercontent.com/8562692/140296881-8fa1468e-955a-4f50-90d5-325c9fe5c7f6.png)

### Hybrid Packers (Injection - Substitution)
*Note: For this section of the workshop you will use file "custom_packer_REvil.exe".*

1. The importance of [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc), [LocalAlloc](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc) and [GlobalAlloc](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc)

    Any packer that uses injection MUST allocate additional memory sections in which the code will be written and executed. This task can be done using the Windows APIs *VirtualAlloc*, *LocalAlloc* and *GlobalAlloc*. You should keep track of these APIs when handling this kind of packers.
    
    For this workshop we are going to analyze a custom packer used by the REvil gang to protect their ransomware. This packer can be classified as a hybrid packer because during its execution it injects several pieces of shellcode to finally replace the complete memory image of the PE. A diagram that explains this kind of packer is shown below. 

![image](https://user-images.githubusercontent.com/8562692/172320227-0bb75da9-2ec3-4276-ba5d-5544668b50f0.png)
     
2. Finding first injected shellcode (LocalAlloc)

    Our first stop during the analysis of this sample is to extract the first injected shellcode. This shellcode injection can be splited into five different steps:
    
    1. Memory is allocated using *LocalAlloc*.
    2. An encrypted shellcode is copied to the new memory location.
    3. Memory protections are set to *PAGE_EXECUTE_READWRITE* to allow modification and execution of the code.
    4. Shellcode is decrypted.
    5. Shellcode is executed.

    Below the section of code used in steps 1 - 4 is shown; you can stop execution of the code in this part just setting a breakpoint in *LocallAlloc*. Step 5, can be easily found just returning from the current function and steping into the next call instruction.
    Remember that all the code that is going to be analyzed from this point on, only exists in memory, it was injected by the packer to make detection harder.

![image](https://user-images.githubusercontent.com/8562692/140274435-652cae1f-a34d-46b7-8f61-01fb774676d0.png)

3. Finding second injected shellcode (VirtualAlloc)

    There is another hidden shellcode in this packer that takes care of the payload decryption and the final code substitution. To capture the exact code that handles this operation you need to set a new breakpoint in *VirtualAlloc*. The injetion process of this new code can be summarized as follows:
    
    1. Memory is allocated using *VirtualAlloc*.
    2. Shellcode is decrypted in the new memory location.
    3. Shellcode is executed. 

    In the figure below, you can see the all three stages of this injection directly on the debugger.

![image](https://user-images.githubusercontent.com/8562692/140274983-5487bb9b-ba3b-42fd-aafb-826047d3b2ad.png)

4. Payload decryption (VirtualAlloc)

    The next step of this journey is to identify the exact piece of code that handles the payload decryption. This can be easily achieved just by setting a new breakpoint in *VirtualAlloc*. If you follow the code after the breakpoint is hit, you will see a piece of code that looks like the one below.
    
    For the sake of readability I highlighted (in red and green) the most important parts of the code. What you will see while debugging this section is basically a new PE file being copied to the new alocated memory space. You can dump directly this PE, however, just because we want to understand the whole flow, we are going to continue the execution of the packer.
    
![image](https://user-images.githubusercontent.com/8562692/140275736-e165e32e-8c7f-4e62-a0fc-d712fe7e00c4.png)

5. Code substitution (VirtualProtect)

    At this point, we know the payload is waiting in memory just to be copied to the final destination. So, the last missing piece of the analysis is to capture the section responsible of replacing the code. To do that we are going to set a new breackpoint in *VirtualProtect*; this is because memory protection MUST be changed if the packer wants to replace the code. 
    
    Once the breakpoint is hit, take a minute to see the arguments passed (see picture below), and you will see that it is trying to set *PAGE_EXECUTE_READWRITE* permissions in the address 0x400000 which is the exact same base address of the packed code!

![image](https://user-images.githubusercontent.com/8562692/140276292-8a1577ce-df14-4278-bf25-3322d3e51c89.png)

6. Finding the "Tail jump"

Finally if you want to find the tail jump, just scroll down a little bit. You will see it, it is not that difficult isn't it?

![image](https://user-images.githubusercontent.com/8562692/140276841-d722df0e-34bf-450f-8a49-64f02adfcdd0.png)

7. Finding the OEP

  Once you have found the *tail jump*, just step into it by hitting the F7 key, you will be redirected to the entry point of the unpacked sample, the OEP. If done correctly, you will see something like the image below.

![image](https://user-images.githubusercontent.com/8562692/140277622-893bde4c-0270-4c38-befd-67b29b4f6a1c.png)

8. Dump the unpacked PE and fix the IAT just as you did when unpacking UPX.
    
### Code Injection Packers (Proccess Injection)

Aside from the packers already explained, there is a special type that injects its malicious code into external processes to make its detection harder. The study of those packers out of the scope of this workshop by now. However, in case you are curious enought to study this topic by your own, I recommend you the following literature:

* https://attack.mitre.org/techniques/T1055/
* https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process

Remember that to make your life easier while analyzing this type of packers you should always identify the required Windows APIs and follow their usage during the execution of the sample. API calls such as [CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and [ResumeThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) are just the tip of the iceberg here. 

Study the interaction of each API with the OS for each type of injection is important if you want to master this.

### Happy Reversing!
