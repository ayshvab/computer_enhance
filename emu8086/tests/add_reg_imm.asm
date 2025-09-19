[bits 16]
; ADD reg, imm (special encoding for AX/AL)
add ax, 1234h
add al, 42h

; ADD reg, imm (general encoding)
add bx, 5678h
add bl, 99h
add cx, 1
add dl, 255
add si, 32767
add ch, 128
