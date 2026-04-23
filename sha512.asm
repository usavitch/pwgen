; sha512.asm - программная реализация SHA-512
; Экспортирует функцию sha512_full

global sha512_full

section .rodata align=8
k_table:
    dq 0x428a2f98d728ae22
    dq 0x7137449123ef65cd
    dq 0xb5c0fbcfec4d3b2f
    dq 0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538
    dq 0x59f111f1b605d019
    dq 0x923f82a4af194f9b
    dq 0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242
    dq 0x12835b0145706fbe
    dq 0x243185be4ee4b28c
    dq 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f
    dq 0x80deb1fe3b1696b1
    dq 0x9bdc06a725c71235
    dq 0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2
    dq 0xefbe4786384f25e3
    dq 0x0fc19dc68b8cd5b5
    dq 0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275
    dq 0x4a7484aa6ea6e483
    dq 0x5cb0a9dcbd41fbd4
    dq 0x76f988da831153b5
    dq 0x983e5152ee66dfab
    dq 0xa831c66d2db43210
    dq 0xb00327c898fb213f
    dq 0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2
    dq 0xd5a79147930aa725
    dq 0x06ca6351e003826f
    dq 0x142929670a0e6e70
    dq 0x27b70a8546d22ffc
    dq 0x2e1b21385c26c926
    dq 0x4d2c6dfc5ac42aed
    dq 0x53380d139d95b3df
    dq 0x650a73548baf63de
    dq 0x766a0abb3c77b2a8
    dq 0x81c2c92e47edaee6
    dq 0x92722c851482353b
    dq 0xa2bfe8a14cf10364
    dq 0xa81a664bbc423001
    dq 0xc24b8b70d0f89791
    dq 0xc76c51a30654be30
    dq 0xd192e819d6ef5218
    dq 0xd69906245565a910
    dq 0xf40e35855771202a
    dq 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8
    dq 0x1e376c085141ab53
    dq 0x2748774cdf8eeb99
    dq 0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63
    dq 0x4ed8aa4ae3418acb
    dq 0x5b9cca4f7763e373
    dq 0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc
    dq 0x78a5636f43172f60
    dq 0x84c87814a1f0ab72
    dq 0x8cc702081a6439ec
    dq 0x90befffa23631e28
    dq 0xa4506cebde82bde9
    dq 0xbef9a3f7b2c67915
    dq 0xc67178f2e372532b
    dq 0xca273eceea26619c
    dq 0xd186b8c721c0c207
    dq 0xeada7dd6cde0eb1e
    dq 0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba
    dq 0x0a637dc5a2c898a6
    dq 0x113f9804bef90dae
    dq 0x1b710b35131c471b
    dq 0x28db77f523047d84
    dq 0x32caab7b40c72493
    dq 0x3c9ebe0a15c9bebc
    dq 0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6
    dq 0x597f299cfc657e2a
    dq 0x5fcb6fab3ad6faec
    dq 0x6c44198c4a475817

section .text
; void sha512_full(const void *data, size_t len, void *hash_out)
; rdi = data, rsi = len, rdx = hash_out

sha512_full:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 216
    mov rcx, rsp
    lea r8, [rcx+64]
    
    ; Загружаем константы через rax
    mov rax, 0x6a09e667f3bcc908
    mov qword [rcx+0*8], rax
    mov rax, 0xbb67ae8584caa73b
    mov qword [rcx+1*8], rax
    mov rax, 0x3c6ef372fe94f82b
    mov qword [rcx+2*8], rax
    mov rax, 0xa54ff53a5f1d36f1
    mov qword [rcx+3*8], rax
    mov rax, 0x510e527fade682d1
    mov qword [rcx+4*8], rax
    mov rax, 0x9b05688c2b3e6c1f
    mov qword [rcx+5*8], rax
    mov rax, 0x1f83d9abfb41bd6b
    mov qword [rcx+6*8], rax
    mov rax, 0x5be0cd19137e2179
    mov qword [rcx+7*8], rax
    
    mov r9, rcx
    mov rbx, rdx
    mov rdx, rsi
    mov rsi, rdi
.loop:
    cmp rdx, 128
    jb .final
    mov rdi, r8
    mov rcx, 16
    rep movsq
    mov rdi, r9
    call sha512_transform
    sub rdx, 128
    jmp .loop
.final:
    mov rdi, r8
    mov rcx, rdx
    shr rcx, 3
    rep movsq
    mov rcx, rdx
    and rcx, 7
    rep movsb
    mov byte [rdi], 0x80
    inc rdi
    lea rcx, [r8+112]
    sub rcx, rdi
    cmp rcx, 0
    jg .pad
    lea rcx, [r8+128]
    sub rcx, rdi
.pad:
    xor al, al
    rep stosb
    mov rax, rdx
    shl rax, 3
    mov [r8+112], rax
    xor rax, rax
    mov [r8+120], rax
    mov rdi, r9
    call sha512_transform
    mov rdi, rbx
    mov rsi, r9
    mov rcx, 8
    rep movsq
    add rsp, 216
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

sha512_transform:
    push rbp
    mov rbp, rsp
    sub rsp, 640
    lea r11, [rsp]
    mov rcx, 16
.copy:
    mov rax, [rdi+rcx*8-8]
    bswap rax
    mov [r11+rcx*8-8], rax
    loop .copy
    mov rcx, 16
.extend:
    mov rax, [r11+rcx*8-16]
    mov rdx, rax
    ror rax, 19
    ror rdx, 61
    xor rax, rdx
    shr rdx, 6
    xor rax, rdx
    add rax, [r11+rcx*8-56]
    add rax, [r11+rcx*8-128]
    mov [r11+rcx*8], rax
    inc rcx
    cmp rcx, 80
    jb .extend
    mov r8, [rdi+0*8]
    mov r9, [rdi+1*8]
    mov r10, [rdi+2*8]
    mov r12, [rdi+3*8]
    mov r13, [rdi+4*8]
    mov r14, [rdi+5*8]
    mov r15, [rdi+6*8]
    mov rbx, [rdi+7*8]
    xor rcx, rcx
.round:
    mov rdx, r13
    ror rdx, 14
    ror r13, 18
    xor rdx, r13
    ror r13, 41
    xor rdx, r13
    mov rax, r8
    and r13, r14
    and rax, r14
    xor rdx, r13
    xor rdx, rax
    lea rax, [k_table]
    add rdx, [rax+rcx*8]
    add rdx, [r11+rcx*8]
    mov rax, rbx
    ror rax, 28
    ror rbx, 34
    xor rax, rbx
    ror rbx, 39
    xor rax, rbx
    add rdx, rax
    mov rax, rbx
    and rbx, r15
    not rax
    and rax, r15
    xor rbx, rax
    add rdx, rbx
    mov rbx, r15
    mov r15, r14
    mov r14, r13
    mov r13, r12
    add r13, rdx
    mov r12, r10
    mov r10, r9
    mov r9, r8
    mov r8, rdx
    inc rcx
    cmp rcx, 80
    jb .round
    add [rdi+0*8], r8
    add [rdi+1*8], r9
    add [rdi+2*8], r10
    add [rdi+3*8], r12
    add [rdi+4*8], r13
    add [rdi+5*8], r14
    add [rdi+6*8], r15
    add [rdi+7*8], rbx
    leave
    ret
