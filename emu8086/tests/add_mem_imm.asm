[bits 16]
; ADD mem, imm (16-bit)
add word [bx], 1234h
add word [si], 5678h
add word [di], 1
add word [bp], 32767

; ADD mem, imm (8-bit)
add byte [bx], 42h
add byte [si], 99h
add byte [di], 1
add byte [bp], 255

; ADD mem, imm with displacement
add word [bx+5], 9999h
add byte [si-10], 33h
add word [1234h], 0abcdh
add byte [bp+di], 128
