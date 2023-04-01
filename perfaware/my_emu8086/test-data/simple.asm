bits 16

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Register_or_memory_to_or_from_register

; MOD = 11
mov al, cl
mov bh, al

; MOD = 00
mov [bx+si], cl
mov cl, [bx+si]
mov [bx], bx
mov [bx], bl

; DIRECT ADDRESS
mov [12], cl

; MOD == 01
mov [bx+si+45], cl
mov [bx+si-45], cx
mov cx, [bx+si+45]

; MOD == 10
mov [si-894], cx


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Immediate to register_or_memory
mov [bx+si], word 4096
mov [bx+si], word -1345

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Memory to accumulator / Accumulator to memory

mov [1234], ax
mov [1234], al
mov al, [1234]
