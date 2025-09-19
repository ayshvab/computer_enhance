[bits 16]
; MOV reg, mem
mov ax, [bx]
mov al, [si]
mov cx, [di]
mov dl, [bp]

; MOV reg, mem with displacement
mov ax, [bx+5]
mov al, [si-10]
mov bx, [1234h]
mov cl, [bp+di]
