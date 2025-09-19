[bits 16]
; ADD mem, reg (16-bit)
add [bx], ax
add [si], cx
add [di], dx
add [bp], bx

; ADD mem, reg (8-bit)
add [bx], al
add [si], cl
add [di], dl
add [bp], bl

; ADD mem, reg with displacement
add [bx+5], ax
add [si-10], al
add [1234h], cx
add [bp+di], dl
