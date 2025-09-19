[bits 16]
; MOV segreg, reg
mov es, ax
mov ds, bx
mov ss, cx
mov cs, dx

; MOV reg, segreg
mov ax, es
mov bx, ds
mov cx, ss
mov dx, cs

; MOV segreg, mem
mov es, [bx]
mov ds, [si]

; MOV mem, segreg
mov [bx], es
mov [si], ds
