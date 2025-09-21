[bits 16]
; ADD with negative 8-bit immediate (sign extension to 16-bit)
; These should sign-extend with all 1's in upper bits since MSB = 1

add ax, -1      ; 0xFF -> 0xFFFF
add bx, -2      ; 0xFE -> 0xFFFE 
add cx, -128    ; 0x80 -> 0xFF80 (min negative 8-bit)
add dx, -10     ; 0xF6 -> 0xFFF6
add si, -50     ; 0xCE -> 0xFFCE
add di, -127    ; 0x81 -> 0xFF81

; Memory operations with negative sign extension
add [bx], byte -5      ; 0xFB -> 0xFFFFB for memory word operation
add [si], word -100    ; 0xFF9C should be sign-extended properly
