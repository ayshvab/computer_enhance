[bits 16]
; MOV mem, imm
mov word [bx], 1234h
mov byte [si], 42h
mov word [di], 0abcdh
mov byte [bp], 99

; MOV mem, imm with displacement
mov word [bx+5], 5678h
mov byte [si-10], 33h
mov word [1234h], 9999h
mov byte [bp+di], 0ffh
