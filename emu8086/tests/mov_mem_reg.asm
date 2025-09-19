[bits 16]
; MOV mem, reg
mov [bx], ax
mov [si], al
mov [di], cx
mov [bp], dl

; MOV mem, reg with displacement
mov [bx+5], ax
mov [si-10], al
mov [1234h], bx
mov [bp+di], cl
