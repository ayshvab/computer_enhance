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

; MOV accumulator to/from direct address
mov al, [0h]
mov al, [1234h]
mov ax, [5678h]
mov [1234h], al
mov [5678h], ax
