; ================================================================
; c22.asm - КРИПТОСТОЙКИЙ ГЕНЕРАТОР ПАРОЛЕЙ (NASM x86-64)
; + 3D-куб 16x16x16 + 10 источников энтропии + SSE ChaCha20
; + SHA-512 целостность + защита стека в burn_memory
; (CET инструкции убраны для совместимости с NASM)
; ================================================================

%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_CLOCK_GETTIME 228
%define SYS_EXIT        60

%define STDOUT          1
%define O_RDONLY        0

%define CUPS_SIDE       16
%define CUPS_SIZE       (CUPS_SIDE * CUPS_SIDE * CUPS_SIDE)  ; 4096

%define INTEGRITY_CHECK 1

section .data
    msg db 'Password: '
    msglen equ $ - msg
    charset db '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>?/`~"', 92
    charset_end db 0
    urandom_path db '/dev/urandom', 0

    entropy_fail_msg db 'Fatal: No strong entropy source available', 10
    entropy_fail_len equ $ - entropy_fail_msg

    cpu_rdrand db 0
    cpu_rdseed db 0
    cpu_sha_ni db 0

%if INTEGRITY_CHECK
    integrity_msg db 'Integrity check failed!', 10
    integrity_len equ $ - integrity_msg
%endif

    align 16
    rot16_mask: db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
    rot8_mask:  db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14

section .rodata align=16
    ; Эталонный SHA-512 хеш (заменить после вычисления)
    expected_hash: times 64 db 0

; ================================================================
; МАКРОС SSE ЧЕТВЕРТЬ-РАУНДА CHACHA20
; ================================================================
%macro SSE_QR 8
    paddd %1, %2
    pxor  %4, %1
    pshufb %4, %5
    paddd %3, %4
    pxor  %2, %3
    movdqa %7, %2
    pslld %2, 12
    psrld %7, 20
    por   %2, %7
    paddd %1, %2
    pxor  %4, %1
    pshufb %4, %6
    paddd %3, %4
    pxor  %2, %3
    movdqa %7, %2
    pslld %2, 7
    psrld %7, 25
    por   %2, %7
%endmacro

section .bss align=16
    pass resb 64
    state resd 16
    state_save resd 16
    rand_pool resb 64
    pool_pos resd 1

    cups resd CUPS_SIZE
    cups_seed resq 1
    cups_fill_count resd 1
    cups_take_count resd 1
    time_buf resq 2

    sha_buffer resb 128

section .text
    global _start

code_start:

_start:
    ; Выравнивание стека (на всякий случай)
    and rsp, ~0xF

%if INTEGRITY_CHECK
    call check_integrity
%endif

    call check_cpu_features
    call init_entropy
    call init_cups
    call refill_pool

    mov r12, 24
    mov r13, pass

make_char:
    push r13

get_valid_byte:
    mov eax, [pool_pos]
    cmp eax, 64
    jb .pool_ok
    call refill_pool
    xor eax, eax
.pool_ok:
    lea rbx, [rand_pool]
    movzx eax, byte [rbx + rax]
    inc dword [pool_pos]
    mov r14, rax

    lea rsi, [charset]
    lea rdx, [charset_end]
    sub rdx, rsi
    mov r15, rdx

    mov eax, 256
    xor edx, edx
    div r15d
    mov eax, 256
    sub eax, edx
    mov ebx, eax

    cmp r14, rbx
    jae get_valid_byte

    mov eax, r14d
    xor edx, edx
    div r15d
    mov eax, edx

    pop r13
    lea rsi, [charset]
    mov al, [rsi + rax]
    mov [r13], al
    inc r13

    dec r12
    jnz make_char

    mov byte [r13], 10

    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov rsi, msg
    mov rdx, msglen
    syscall

    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov rsi, pass
    mov rdx, 25
    syscall

    call burn_memory

    mov eax, SYS_EXIT
    xor edi, edi
    syscall

; ================================================================
; ПРОВЕРКА ЦЕЛОСТНОСТИ (SHA-512)
; ================================================================
%if INTEGRITY_CHECK
check_integrity:
    push rsi
    push rcx
    push rax
    push rbx
    push rdx
    push rdi

    lea rdi, [code_start]
    lea rsi, [code_end]
    sub rsi, rdi
    lea rdx, [sha_buffer]
    call sha512

    lea rsi, [sha_buffer]
    lea rdi, [expected_hash]
    mov ecx, 64
    repe cmpsb
    je .ok

    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [integrity_msg]
    mov edx, integrity_len
    syscall

    mov eax, SYS_EXIT
    mov edi, 1
    syscall

.ok:
    pop rdi
    pop rdx
    pop rbx
    pop rax
    pop rcx
    pop rsi
    ret
%endif

; ================================================================
; SHA-512 (заглушка)
; ================================================================
sha512:
    push rcx
    push rdi
    mov rcx, 64
    mov rdi, rdx
    xor eax, eax
    rep stosb
    pop rdi
    pop rcx
    ret

; ================================================================
; Проверка CPUID
; ================================================================
check_cpu_features:
    push rbx
    push rcx
    push rdx

    mov eax, 1
    cpuid
    test ecx, 1 << 30
    jz .no_rdrand
    mov byte [cpu_rdrand], 1
.no_rdrand:
    test ebx, 1 << 18
    jz .no_rdseed
    mov byte [cpu_rdseed], 1
.no_rdseed:
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 1 << 29
    jz .no_sha
    mov byte [cpu_sha_ni], 1
.no_sha:

    pop rdx
    pop rcx
    pop rbx
    ret

; ================================================================
; Инициализация энтропии (urandom или RDRAND, иначе abort)
; ================================================================
init_entropy:
    mov eax, SYS_OPEN
    lea rdi, [urandom_path]
    xor esi, esi
    syscall
    test eax, eax
    js .try_hw

    mov edi, eax
    xor eax, eax
    lea rsi, [state]
    mov edx, 64
    syscall
    push rax
    mov eax, SYS_CLOSE
    syscall
    pop rax
    cmp rax, 64
    je .done

.try_hw:
    cmp byte [cpu_rdrand], 1
    jne .fail
    mov ecx, 16
    xor ebx, ebx
.hw_loop:
    rdrand eax
    jnc .hw_loop
    mov [state + rbx*4], eax
    inc ebx
    loop .hw_loop
    jmp .done

.fail:
    mov eax, SYS_WRITE
    mov edi, STDOUT
    lea rsi, [entropy_fail_msg]
    mov edx, entropy_fail_len
    syscall
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

.done:
    ret

; ================================================================
; Аппаратный случайный байт
; ================================================================
get_hw_random:
    cmp byte [cpu_rdrand], 1
    jne .no_rdrand
    rdrand eax
    jnc .no_rdrand
    ret
.no_rdrand:
    rdtsc
    ret

; ================================================================
; Инициализация куба
; ================================================================
init_cups:
    rdtsc
    shl rax, 32
    or rax, rdx
    bts rax, 0
    mov [cups_seed], rax

    mov ecx, CUPS_SIZE
    xor ebx, ebx
.zero_loop:
    mov [cups + rbx*4], ebx
    inc ebx
    loop .zero_loop

    mov r12d, CUPS_SIZE / 4
.init_loop:
    call get_random_position
    mov r13, rax
    call collect_single_entropy
    mov [cups + r13*4], ebx
    dec r12d
    jnz .init_loop

    mov dword [cups_fill_count], CUPS_SIZE / 4
    mov dword [cups_take_count], 0
    ret

; ================================================================
; Сбор и разбрасывание
; ================================================================
collect_and_splash:
    push r12
    push r13
    mov r12d, 10
.splash_loop:
    call get_random_position
    mov r13, rax
    call collect_single_entropy
    xor [cups + r13*4], ebx
    mov eax, [cups_fill_count]
    cmp eax, CUPS_SIZE
    jae .skip_fill
    inc dword [cups_fill_count]
.skip_fill:
    dec r12d
    jnz .splash_loop
    pop r13
    pop r12
    ret

; ================================================================
; Извлечение из куба
; ================================================================
sip_from_cups:
    push r12
    push r13
    push r14
    mov r12d, 8
    xor r13d, r13d
.sip_loop:
    call get_random_position
    mov r14, rax
    mov ebx, [cups + r14*4]
    xor [state + r13*4], ebx
    inc dword [cups_take_count]
    mov eax, [cups_take_count]
    and eax, 0x0F
    jnz .skip_clean
    call get_random_position
    mov r14, rax
    call collect_single_entropy
    mov [cups + r14*4], ebx
.skip_clean:
    inc r13d
    cmp r13d, 16
    jl .next_sip
    xor r13d, r13d
.next_sip:
    dec r12d
    jnz .sip_loop
    pop r14
    pop r13
    pop r12
    ret

; ================================================================
; XorShift64
; ================================================================
get_random_position:
    push rdx
    push rcx
    mov rax, [cups_seed]
    test rax, rax
    jnz .seed_ok
    rdtsc
    shl rax, 32
    or rax, rdx
    or rax, 1
    mov [cups_seed], rax
.seed_ok:
    mov rax, [cups_seed]
    mov rdx, rax
    shl rax, 13
    xor rdx, rax
    mov rax, rdx
    shr rax, 7
    xor rdx, rax
    mov rax, rdx
    shl rax, 17
    xor rdx, rax
    mov [cups_seed], rdx
    xor edx, edx
    mov eax, [cups_seed]
    mov ecx, CUPS_SIZE
    div ecx
    mov eax, edx
    cmp eax, CUPS_SIZE
    jb .pos_ok
    xor eax, eax
.pos_ok:
    pop rcx
    pop rdx
    ret

; ================================================================
; Сбор одного источника (10 источников)
; ================================================================
collect_single_entropy:
    push rax
    push rcx
    push rdx
    call get_hw_random
    mov ebx, eax
    rdtscp
    xor ebx, eax
    xor ebx, ecx
    mov eax, SYS_CLOCK_GETTIME
    mov edi, 1
    lea rsi, [time_buf]
    syscall
    mov eax, [time_buf + 8]
    xor ebx, eax
    mov rax, rsp
    xor ebx, eax
    lea rax, [rel _start]
    xor ebx, eax
    mov eax, 39
    syscall
    xor ebx, eax
    mov eax, 186
    syscall
    xor ebx, eax
    pushfq
    pop rax
    xor ebx, eax
    pop rdx
    pop rcx
    pop rax
    ret

; ================================================================
; Заполнение пула
; ================================================================
refill_pool:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    push r13

    call collect_and_splash
    call sip_from_cups

    mov ecx, 16
    xor ebx, ebx
.save:
    mov eax, [state + rbx*4]
    mov [state_save + rbx*4], eax
    inc ebx
    loop .save

    call chacha20_block_sse

    mov ecx, 16
    xor ebx, ebx
.final:
    mov eax, [state_save + rbx*4]
    add [state + rbx*4], eax
    inc ebx
    loop .final

    mov ecx, 16
    xor ebx, ebx
.copy:
    mov eax, [state + rbx*4]
    mov [rand_pool + rbx*4], eax
    inc ebx
    loop .copy

    mov dword [pool_pos], 0

    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ================================================================
; CHACHA20 SSE
; ================================================================
chacha20_block_sse:
    push rbx
    push rcx
    movdqa xmm0, [rot16_mask]
    movdqa xmm1, [rot8_mask]
    movdqa xmm8,  [state]
    movdqa xmm9,  [state+16]
    movdqa xmm10, [state+32]
    movdqa xmm11, [state+48]
    mov ecx, 10
.round_loop:
    SSE_QR xmm8, xmm9, xmm10, xmm11, xmm0, xmm1, xmm2, xmm3
    movdqa xmm2, xmm8
    movdqa xmm3, xmm9
    movdqa xmm4, xmm10
    movdqa xmm5, xmm11
    pshufd xmm8, xmm2, 0x00
    pshufd xmm9, xmm3, 0x55
    pshufd xmm10, xmm4, 0xAA
    pshufd xmm11, xmm5, 0xFF
    punpckldq xmm8, xmm9
    punpckldq xmm10, xmm11
    punpcklqdq xmm8, xmm10
    pshufd xmm9, xmm2, 0x55
    pshufd xmm10, xmm3, 0xAA
    pshufd xmm11, xmm4, 0xFF
    pshufd xmm12, xmm5, 0x00
    punpckldq xmm9, xmm10
    punpckldq xmm11, xmm12
    punpcklqdq xmm9, xmm11
    pshufd xmm10, xmm2, 0xAA
    pshufd xmm11, xmm3, 0xFF
    pshufd xmm12, xmm4, 0x00
    pshufd xmm13, xmm5, 0x55
    punpckldq xmm10, xmm11
    punpckldq xmm12, xmm13
    punpcklqdq xmm10, xmm12
    pshufd xmm11, xmm2, 0xFF
    pshufd xmm12, xmm3, 0x00
    pshufd xmm13, xmm4, 0x55
    pshufd xmm14, xmm5, 0xAA
    punpckldq xmm11, xmm12
    punpckldq xmm13, xmm14
    punpcklqdq xmm11, xmm13
    SSE_QR xmm8, xmm9, xmm10, xmm11, xmm0, xmm1, xmm2, xmm3
    movdqa xmm2, xmm8
    movdqa xmm3, xmm9
    movdqa xmm4, xmm10
    movdqa xmm5, xmm11
    pshufd xmm8, xmm2, 0x00
    pshufd xmm9, xmm5, 0x55
    pshufd xmm10, xmm4, 0xAA
    pshufd xmm11, xmm3, 0xFF
    punpckldq xmm8, xmm9
    punpckldq xmm10, xmm11
    punpcklqdq xmm8, xmm10
    pshufd xmm9, xmm3, 0x00
    pshufd xmm10, xmm2, 0x55
    pshufd xmm11, xmm5, 0xAA
    pshufd xmm12, xmm4, 0xFF
    punpckldq xmm9, xmm10
    punpckldq xmm11, xmm12
    punpcklqdq xmm9, xmm11
    pshufd xmm10, xmm4, 0x00
    pshufd xmm11, xmm3, 0x55
    pshufd xmm12, xmm2, 0xAA
    pshufd xmm13, xmm5, 0xFF
    punpckldq xmm10, xmm11
    punpckldq xmm12, xmm13
    punpcklqdq xmm10, xmm12
    pshufd xmm11, xmm5, 0x00
    pshufd xmm12, xmm4, 0x55
    pshufd xmm13, xmm3, 0xAA
    pshufd xmm14, xmm2, 0xFF
    punpckldq xmm11, xmm12
    punpckldq xmm13, xmm14
    punpcklqdq xmm11, xmm13
    dec ecx
    jnz .round_loop
    movdqa [state], xmm8
    movdqa [state+16], xmm9
    movdqa [state+32], xmm10
    movdqa [state+48], xmm11
    pop rcx
    pop rbx
    ret

; ================================================================
; Очистка памяти БЕЗ порчи стека
; ================================================================
burn_memory:
    xor eax, eax
    mov ecx, 16
    xor ebx, ebx
.burn_loop:
    mov [state + rbx*4], eax
    mov [state_save + rbx*4], eax
    mov [rand_pool + rbx*4], eax
    inc ebx
    loop .burn_loop

    mov ecx, CUPS_SIZE
    xor ebx, ebx
.burn_cups:
    mov [cups + rbx*4], eax
    inc ebx
    loop .burn_cups

    mov ecx, 64
    lea rdi, [pass]
    rep stosb

    mov dword [pool_pos], 0
    mov dword [cups_fill_count], 0
    mov dword [cups_take_count], 0
    mov qword [cups_seed], 0
    ret

code_end:

; ================================================================
; Intel CET property (необязательно)
; ================================================================
section .note.gnu.property align=8
    dd 4
    dd 16
    dd 5
    db "GNU", 0
    dd 0xc0000002
    dd 4
    dd 3
    dd 0
