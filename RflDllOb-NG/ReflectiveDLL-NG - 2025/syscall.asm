; bello code for syscall 

.data
; i do not think data is needer here

.code 
ZwAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, dword ptr [rsp + 56]
	jmp qword ptr [rsp + 64]
ZwAllocateVirtualMemory ENDP

ZwProtectVirtualMemory PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 48]
	jmp qword ptr [rsp + 56]
ZwProtectVirtualMemory ENDP

ZwFlushInstructionCache PROC
	mov r10,rcx 
	mov rax, r9
	jmp qword ptr [rsp + 40]
ZwFlushInstructionCache ENDP

ZwCreateSection PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 64]
	jmp qword ptr [rsp + 72]
ZwCreateSection ENDP

ZwMapViewOfSection PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 88]
	jmp qword ptr [rsp + 96]
ZwMapViewOfSection ENDP

ZwUnmapViewOfSection PROC
	mov r10,rcx
	mov eax, r8d
	jmp r9
ZwUnmapViewOfSection ENDP

ZwQuerySystemInformation PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 40]
	jmp qword ptr [rsp + 48]
ZwQuerySystemInformation ENDP

ZwQueryObject PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 48]
	jmp qword ptr [rsp + 56]
ZwQueryObject ENDP

ZwQueryVirtualMemory PROC
	mov r10, rcx
	mov eax, dword ptr [rsp + 56]
	jmp qword ptr [rsp + 64]
ZwQueryVirtualMemory ENDP

ZwFreeVirtualMemory PROC
	mov r10,rcx
	mov eax, dword ptr [rsp + 40]
	jmp qword ptr [rsp + 48]
ZwFreeVirtualMemory ENDP

ZwSetContextThread PROC
	mov r10,rcx
	mov eax, r8d
	jmp r9
ZwSetContextThread ENDP

ZwGetContextThread PROC
	mov r10,rcx
	mov eax, r8d
	jmp r9
ZwGetContextThread ENDP

end