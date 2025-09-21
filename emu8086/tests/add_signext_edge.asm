[bits 16]

; Edge cases around sign bit boundary
add ax, 0x7F    ; 0x7F -> 0x007F (largest positive 8-bit)
add bx, 0x80    ; 0x80 -> 0xFF80 (smallest negative 8-bit as unsigned)

; Zero case
add si, 0       ; 0x00 -> 0x0000

; Boundary testing with different addressing modes
add [bp], word 0x7F    ; Positive boundary to memory
add [bp+2], word 0x80  ; Negative boundary to memory  
add [bx+si], byte 0xFF ; Maximum 8-bit value

; Mix of register sizes
add al, 0x7F    ; 8-bit register, no sign extension needed
add ah, 0x80    ; 8-bit register, no sign extension needed
