.686
.MODEL FLAT, C

.CODE
ASSUME FS:NOTHING

set_exception_handler PROC address:DWORD
	push ebx
	mov ebx, fs:[0]
	mov eax, [ebx]
	cmp eax, 0FFFFFFFFh
	je L2
L1:
	mov ebx, [ebx]
	mov eax, [ebx]
	cmp eax, 0FFFFFFFFh
	jne L1 
L2:
	push address
	pop [ebx + 4]
	mov fs:[0], ebx
	pop ebx
	ret
set_exception_handler ENDP

END
