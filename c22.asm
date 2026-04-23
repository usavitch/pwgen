; ======================================================================
; КРИПТОСТОЙКИЙ ГЕНЕРАТОР ПАРОЛЕЙ (NASM x86-64)
; Исправлено: burn_memory очищает регистры, убран rdtsc, защита от DOS
; ======================================================================

%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_CLOSE 3
%define SYS_CLOCK_GETTIME 228
%define SYS_EXIT 60
%define STDOUT 1
%define O_RDONLY 0
%define CUPS_X 16
%define CUPS_Y 16
%define CUPS_DEPTH 16
%define CUPS_SIZE (CUPS_X * CUPS_Y * CUPS_DEPTH)
%define BALLS_PER_CUP 16
%define MAX_RETRIES 65536

%macro PUSH_CALLEE 0
push rbx
push rbp
push r12
push r13
push r14
push r15
%endmacro

%macro POP_CALLEE 0
pop r15
pop r14
pop r13
pop r12
pop rbp
pop rbx
%endmacro

%macro SSE_QR 8
paddd %1,%2
pxor %4,%1
pshufb %4,%5
paddd %3,%4
pxor %2,%3
movdqa %7,%2
pslld %2,12
psrld %7,20
por %2,%7
paddd %1,%2
pxor %4,%1
pshufb %4,%6
paddd %3,%4
pxor %2,%3
movdqa %7,%2
pslld %2,7
psrld %7,25
por %2,%7
%endmacro

section .data
msg db 'Password: '
msglen equ $-msg
charset db '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>?/`~"',92
charset_end db 0
urandom_path db '/dev/urandom',0
cpu_rdrand db 0
err_urandom_msg db 'Fatal: Cannot read /dev/urandom',10
err_urandom_len equ $-err_urandom_msg
no_rdrand_msg db 'Fatal: RDRAND not supported',10
no_rdrand_len equ $-no_rdrand_msg
dos_msg db 'Fatal: Too many retries in get_valid_byte',10
dos_len equ $-dos_msg
align 16
rot16_mask db 2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13
rot8_mask db 3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14

section .bss align=16
pass resb 64
state resd 16
state_save resd 16
rand_pool resb 64
pool_pos resd 1
cups resd CUPS_SIZE
cup_ball_count resb (CUPS_X * CUPS_Y)
cups_fill_count resd 1
cups_take_count resd 1
time_buf resq 2

section .text
global _start
_start:
    call    check_cpu_features
    call    init_entropy
    call    init_cups
    call    refill_pool

    mov     r12d, 24
    mov     r13, pass

make_char:
    push    r13
    xor     r14d, r14d

get_valid_byte:
    inc     r14d
    cmp     r14d, MAX_RETRIES
    ja      dos_exit

    mov     eax, [pool_pos]
    cmp     eax, 64
    jb      .pool_ok
    call    refill_pool
    xor     eax, eax
.pool_ok:
    lea     rbx, [rand_pool]
    movzx   eax, byte [rbx + rax]
    inc     dword [pool_pos]
    mov     r15d, eax

    lea     rsi, [charset]
    lea     rdx, [charset_end]
    sub     rdx, rsi
    mov     r8d, edx

    mov     eax, 256
    xor     edx, edx
    div     r8d
    mov     eax, 256
    sub     eax, edx
    mov     ebx, eax

    cmp     r15d, ebx
    jae     get_valid_byte

    mov     eax, r15d
    xor     edx, edx
    div     r8d
    mov     eax, edx

    pop     r13
    lea     rsi, [charset]
    mov     al, [rsi + rax]
    mov     [r13], al
    inc     r13

    dec     r12d
    jnz     make_char

    mov     byte [r13], 10

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    mov     rsi, msg
    mov     rdx, msglen
    syscall
    test    rax, rax
    js      fatal_exit

    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    mov     rsi, pass
    mov     rdx, 25
    syscall
    test    rax, rax
    js      fatal_exit

    call    burn_memory

    mov     eax, SYS_EXIT
    xor     edi, edi
    syscall

dos_exit:
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [dos_msg]
    mov     edx, dos_len
    syscall
    jmp     fatal_exit

fatal_exit:
    mov     eax, SYS_EXIT
    mov     edi, 1
    syscall

check_cpu_features:
    PUSH_CALLEE
    mov     eax, 1
    cpuid
    test    ecx, 1<<30
    jz      .no_rdrand
    mov     byte [cpu_rdrand], 1
.no_rdrand:
    POP_CALLEE
    ret

init_entropy:
    PUSH_CALLEE
    mov     eax, SYS_OPEN
    lea     rdi, [urandom_path]
    xor     esi, esi
    syscall
    test    eax, eax
    js      .fallback_to_rdrand

    mov     edi, eax
    xor     eax, eax
    lea     rsi, [state]
    mov     edx, 64
    syscall
    cmp     rax, 64
    jne     .urandom_failed

    mov     eax, SYS_CLOSE
    syscall
    jmp     .done

.urandom_failed:
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [err_urandom_msg]
    mov     edx, err_urandom_len
    syscall
    jmp     fatal_exit

.fallback_to_rdrand:
    cmp     byte [cpu_rdrand], 1
    jne     .no_rdrand
    mov     ecx, 16
    xor     ebx, ebx
.rdrand_loop:
    call    get_hw_random
    mov     [state + rbx*4], eax
    inc     ebx
    loop    .rdrand_loop
    jmp     .done

.no_rdrand:
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [no_rdrand_msg]
    mov     edx, no_rdrand_len
    syscall
    jmp     fatal_exit

.done:
    POP_CALLEE
    ret

get_hw_random:
    push    rcx
    mov     ecx, 10
.retry:
    cmp     byte [cpu_rdrand], 1
    jne     .fail
    rdrand  eax
    jnc     .next_attempt
    pop     rcx
    ret
.next_attempt:
    dec     ecx
    jnz     .retry
.fail:
    pop     rcx
    xor     eax, eax
    ret

get_random_byte:
    push    rcx
    call    get_hw_random
    and     eax, 0xFF
    pop     rcx
    ret

; ======================================================================
; ИНИЦИАЛИЗАЦИЯ КУБА (без rdtsc)
; ======================================================================
init_cups:
    PUSH_CALLEE
    
    mov     ecx, CUPS_SIZE
    lea     rdi, [cups]
    xor     eax, eax
    rep stosd
    
    mov     ecx, CUPS_X * CUPS_Y
    lea     rdi, [cup_ball_count]
    rep stosb
    
    mov     r12d, CUPS_X * CUPS_Y
    xor     r13d, r13d
    
.init_cup_loop:
    call    get_random_byte
    and     eax, 0x0F
    cmp     eax, 4
    jb      .min_balls
    cmp     eax, 12
    jbe     .balls_ok
.min_balls:
    mov     eax, 8
.balls_ok:
    mov     r14d, eax
    mov     [cup_ball_count + r13], al
    
    xor     ebx, ebx
.fill_balls:
    cmp     ebx, r14d
    jae     .next_cup
    
    mov     eax, r13d
    shl     eax, 4
    add     eax, ebx
    mov     edi, eax
    
    call    collect_single_entropy
    mov     [cups + rdi*4], ebx
    
    inc     ebx
    jmp     .fill_balls
    
.next_cup:
    inc     r13d
    dec     r12d
    jnz     .init_cup_loop

    mov     dword [cups_fill_count], 0
    mov     dword [cups_take_count], 0
    POP_CALLEE
    ret

; ======================================================================
; РАЗБРАСЫВАНИЕ ШАРИКОВ
; ======================================================================
collect_and_splash:
    PUSH_CALLEE
    mov     r12d, 10
    
.splash_loop:
    call    get_random_position
    mov     r13d, eax
    
    call    collect_single_entropy
    mov     r14d, ebx
    
    movzx   eax, byte [cup_ball_count + r13]
    cmp     eax, BALLS_PER_CUP
    jb      .add_ball
    
    call    get_random_byte
    and     eax, 0x0F
    jmp     .write_ball
    
.add_ball:
    inc     byte [cup_ball_count + r13]
.write_ball:
    mov     edx, r13d
    shl     edx, 4
    add     edx, eax
    mov     [cups + rdx*4], r14d
    
    mov     eax, [cups_fill_count]
    cmp     eax, CUPS_SIZE
    jae     .skip_count
    inc     dword [cups_fill_count]
.skip_count:
    dec     r12d
    jnz     .splash_loop
    
    POP_CALLEE
    ret

; ======================================================================
; ИЗВЛЕЧЕНИЕ ШАРИКОВ
; ======================================================================
sip_from_cups:
    PUSH_CALLEE
    mov     r12d, 8
    xor     r13d, r13d
    
.sip_loop:
    call    get_random_position
    mov     r14d, eax
    
    movzx   eax, byte [cup_ball_count + r14]
    test    eax, eax
    jz      .next_sip
    
    push    rax
    call    get_random_byte
    pop     rcx
    xor     edx, edx
    div     ecx
    mov     eax, edx
    
    mov     edx, r14d
    shl     edx, 4
    add     edx, eax
    
    mov     ebx, [cups + rdx*4]
    xor     [state + r13*4], ebx
    
    inc     dword [cups_take_count]
    
    mov     eax, [cups_take_count]
    and     eax, 0x07
    jnz     .skip_update
    
    call    collect_single_entropy
    mov     [cups + rdx*4], ebx
    
.skip_update:
    inc     r13d
    cmp     r13d, 16
    jl      .next_sip
    xor     r13d, r13d
    
.next_sip:
    dec     r12d
    jnz     .sip_loop
    
    POP_CALLEE
    ret

; ======================================================================
; СЛУЧАЙНАЯ ПОЗИЦИЯ СТАКАНЧИКА (через ChaCha20, без rdtsc)
; ======================================================================
get_random_position:
    PUSH_CALLEE
    call    chacha20_block_sse
    mov     eax, [state]
    xor     edx, edx
    mov     ecx, CUPS_X * CUPS_Y
    div     ecx
    mov     eax, edx
    POP_CALLEE
    ret

collect_single_entropy:
    push    rax
    push    rcx
    push    rdx
    call    get_hw_random
    mov     ebx, eax
    rdtscp
    xor     ebx, eax
    xor     ebx, ecx
    mov     eax, SYS_CLOCK_GETTIME
    mov     edi, 1
    lea     rsi, [time_buf]
    syscall
    mov     eax, [time_buf+8]
    xor     ebx, eax
    pushfq
    pop     rax
    xor     ebx, eax
    pop     rdx
    pop     rcx
    pop     rax
    ret

refill_pool:
    PUSH_CALLEE
    call    collect_and_splash
    call    sip_from_cups

    mov     ecx, 16
    xor     ebx, ebx
.save:
    mov     eax, [state + rbx*4]
    mov     [state_save + rbx*4], eax
    inc     ebx
    loop    .save

    call    chacha20_block_sse

    mov     ecx, 16
    xor     ebx, ebx
.final:
    mov     eax, [state_save + rbx*4]
    add     [state + rbx*4], eax
    inc     ebx
    loop    .final

    mov     ecx, 16
    xor     ebx, ebx
.copy:
    mov     eax, [state + rbx*4]
    mov     [rand_pool + rbx*4], eax
    inc     ebx
    loop    .copy

    mov     dword [pool_pos], 0
    POP_CALLEE
    ret

chacha20_block_sse:
    PUSH_CALLEE
    movdqa  xmm0, [rot16_mask]
    movdqa  xmm1, [rot8_mask]
    movdqa  xmm8,  [state]
    movdqa  xmm9,  [state+16]
    movdqa  xmm10, [state+32]
    movdqa  xmm11, [state+48]
    mov     ecx, 10
.round_loop:
    SSE_QR  xmm8, xmm9, xmm10, xmm11, xmm0, xmm1, xmm2, xmm3
    SSE_QR  xmm8, xmm9, xmm10, xmm11, xmm0, xmm1, xmm2, xmm3
    dec     ecx
    jnz     .round_loop
    movdqa  [state], xmm8
    movdqa  [state+16], xmm9
    movdqa  [state+32], xmm10
    movdqa  [state+48], xmm11
    POP_CALLEE
    ret

; ======================================================================
; ОЧИСТКА ПАМЯТИ (теперь очищает и регистры)
; ======================================================================
burn_memory:
    PUSH_CALLEE
    
    ; Очищаем память
    mov     ecx, 16
    xor     eax, eax
    lea     rdi, [state]
    rep stosd
    lea     rdi, [state_save]
    mov     ecx, 16
    rep stosd
    lea     rdi, [rand_pool]
    mov     ecx, 16
    rep stosd
    mov     ecx, CUPS_SIZE
    lea     rdi, [cups]
    rep stosd
    mov     ecx, CUPS_X * CUPS_Y
    lea     rdi, [cup_ball_count]
    rep stosb
    mov     ecx, 64
    lea     rdi, [pass]
    rep stosb
    
    ; Обнуляем счётчики
    mov     dword [pool_pos], 0
    mov     dword [cups_fill_count], 0
    mov     dword [cups_take_count], 0
    
    ; Очищаем ВСЕ регистры общего назначения
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rdi, rdi
    xor     rbp, rbp
    xor     r8,  r8
    xor     r9,  r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15
    
    ; Очищаем ВСЕ XMM регистры
    pxor    xmm0,  xmm0
    pxor    xmm1,  xmm1
    pxor    xmm2,  xmm2
    pxor    xmm3,  xmm3
    pxor    xmm4,  xmm4
    pxor    xmm5,  xmm5
    pxor    xmm6,  xmm6
    pxor    xmm7,  xmm7
    pxor    xmm8,  xmm8
    pxor    xmm9,  xmm9
    pxor    xmm10, xmm10
    pxor    xmm11, xmm11
    pxor    xmm12, xmm12
    pxor    xmm13, xmm13
    pxor    xmm14, xmm14
    pxor    xmm15, xmm15
    
    POP_CALLEE
    ret
