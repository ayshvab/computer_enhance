[bits 16]
; ADD reg, mem (16-bit)
add ax, [bx]
add cx, [si]
add dx, [di]
add bx, [bp]

; ADD reg, mem (8-bit)
add al, [bx]
add cl, [si]
add dl, [di]
add bl, [bp]

; ADD reg, mem with displacement
add ax, [bx+5]
add al, [si-10]
add cx, [1234h]
add dl, [bp+di]
