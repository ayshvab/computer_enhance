[bits 16]
; ADD with positive 8-bit immediate (sign extension to 16-bit)
; These should zero-extend the upper bits since MSB = 0

add ax, 0x01    ; 0x01 -> 0x0001
add bx, 0x7F    ; 0x7F -> 0x007F (max positive 8-bit)
add cx, 0x42    ; 0x42 -> 0x0042
add dx, 0x10    ; 0x10 -> 0x0010
add si, 0x0A    ; 0x0A -> 0x000A
add di, 0x50    ; 0x50 -> 0x0050

; Memory operations with positive sign extension
add [bx], byte 0x20    ; 8-bit to memory
add [si], word 0x30    ; 16-bit immediate (should use sign-extended form)
