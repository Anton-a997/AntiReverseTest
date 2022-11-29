.686
.MODEL FLAT, C

.CODE

f_rop PROC
	sub esp, 4
	mov edx, [esp + 8]
	mov eax, [esp + 4]
	mov [esp + 8], eax
	xor eax, eax
	xor ecx, ecx
L1:
	mov al, [edx + ecx]
	test eax, eax
	je L2
	mov [esp + ecx], al
	inc ecx
	jmp L1
L2:
	add esp, 4
	ret
f_rop ENDP

END
