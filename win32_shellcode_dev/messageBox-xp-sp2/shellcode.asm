;msgbox.asm

[BITS 32]
[SECTION .text]

global _start


_start:
	;eax holds return value
	;ebx will hold function addresses
	;ecx will hold string pointers
	;edx will hold NULL

	
	xor eax,eax
	xor ebx,ebx			;zero out the registers
	xor ecx,ecx
	xor edx,edx
	
	jmp short GetLibrary

LibraryReturn:
	pop ecx				;get the library string
	mov [ecx + 10], dl		;insert NULL
	mov ebx, 0x7c801d77		;LoadLibraryA(libraryname); for winxp2 =  0x7c801d77
	push ecx			;beginning of user32.dll
	call ebx			;eax will hold the module handle

	jmp short FunctionName

FunctionReturn:

	pop ecx				;get the address of the Function string
	xor edx,edx
	mov [ecx + 11],dl		;insert NULL
	push ecx
	push eax
	mov ebx,  0x7c80ac28		;GetProcAddress(hmodule,functionname); for winxp2 =  0x7c80ac28
	call ebx			;eax now holds the address of MessageBoxA
	
	jmp short Message

MessageReturn:
	pop ecx				;get the message string
	xor edx,edx			
	mov [ecx+3],dl			;insert the NULL

	xor edx,edx
	
	push edx			;MB_OK
	push ecx			;title
	push ecx			;message
	push edx			;NULL window handle
	
	call eax			;MessageBoxA(windowhandle,msg,title,type); Address

ender:
	xor edx,edx
	push eax			
	mov eax, 0x7c81caa2 		;exitprocess(exitcode); for winxp2 = 0x7c81caa2
	call eax			;exit cleanly so we don't crash the parent program
	

	;the N at the end of each string signifies the location of the NULL
	;character that needs to be inserted
	

GetLibrary:
	call LibraryReturn
	db 'user32.dllN'
FunctionName
	call FunctionReturn
	db 'MessageBoxAN'
Message
	call MessageReturn
	db 'HeyN'

