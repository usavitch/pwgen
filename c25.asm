; ======================================================================
; c25.asm — КРИПТОСТОЙКИЙ ГЕНЕРАТОР ПАРОЛЕЙ С FIPS 140-2 POST
; NASM x86-64, SSE ChaCha20, 3D-куб 16x16x16, Quarter-Round + 3D-диффузия
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
pop rbx
%endmacro

; ======================================================================
; QUARTER-ROUND ДЛЯ КУБА
; ======================================================================
%macro CUP_QR 0
    mov     eax, [rdi]
    mov     ebx, [rdi + 16]
    mov     edx, [rdi + 32]
    mov     ecx, [rsi]
    add     eax, ebx
    xor     edx, eax
    rol     edx, 16
    add     ecx, edx
    xor     ebx, ecx
    rol     ebx, 12
    add     eax, ebx
    xor     edx, eax
    rol     edx, 8
    add     ecx, edx
    xor     ebx, ecx
    rol     ebx, 7
    mov     [rdi], eax
    mov     [rdi + 16], ebx
    mov     [rsi], ecx
    mov     [rdi + 32], edx
%endmacro

; ======================================================================
; 3D-ДИФФУЗИЯ МЕЖДУ СТАКАНЧИКАМИ
; ======================================================================
%macro INTER_CUP_DIFFUSION 0
    lea     r9d, [r8d + 16]
    cmp     r9d, CUPS_X * CUPS_Y
    jb      %%diffuse
    sub     r9d, CUPS_X * CUPS_Y
%%diffuse:
    mov     r10d, r9d
    shl     r10, 6
    lea     r10, [cups + r10]
    xor     [r10], eax
    xor     [r10 + 16], ebx
    xor     [r10 + 32], edx
    xor     [r10 + 48], ecx
%endmacro

; ======================================================================
; SSE QUARTER-ROUND ДЛЯ CHACHA20
; ======================================================================
%macro SSE_QR 8
    paddd   %1, %2
    pxor    %4, %1
    pshufb  %4, %5
    paddd   %3, %4
    pxor    %2, %3
    movdqa  %7, %2
    pslld   %2, 12
    psrld   %7, 20
    por     %2, %7
    paddd   %1, %2
    pxor    %4, %1
    pshufb  %4, %6
    paddd   %3, %4
    pxor    %2, %3
    movdqa  %7, %2
    pslld   %2, 7
    psrld   %7, 25
    por     %2, %7
%endmacro

; ======================================================================
; ДАННЫЕ
; ======================================================================
section .data
msg db 'Password: '
msglen equ $-msg
charset db '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>?/`~"',92
charset_end db 0
urandom_path db '/dev/urandom',0
cpu_rdrand db 0
cpu_rdseed db 0
err_urandom_msg db 'Fatal: Cannot read /dev/urandom',10
err_urandom_len equ $-err_urandom_msg
no_rdrand_msg db 'Fatal: RDRAND not supported',10
no_rdrand_len equ $-no_rdrand_msg
dos_msg db 'Fatal: Too many retries',10
dos_len equ $-dos_msg
read_err_msg db 'Fatal: Short read',10
read_err_len equ $-read_err_msg

; FIPS 140-2 сообщения
fips_start_msg db 'FIPS 140-2 POST: Running self-tests...',10
fips_start_len equ $-fips_start_msg
fips_ok_msg db 'FIPS 140-2 POST: ALL TESTS PASSED',10
fips_ok_len equ $-fips_ok_msg
fips_fail_crngt db 'FIPS 140-2 POST: Continuous RNG Test FAILED!',10
fips_fail_crngt_len equ $-fips_fail_crngt
fips_fail_mono db 'FIPS 140-2 POST: Monobit Test FAILED!',10
fips_fail_mono_len equ $-fips_fail_mono

align 16
rot16_mask db 2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13
rot8_mask db 3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14

; ======================================================================
; НЕИНИЦИАЛИЗИРОВАННЫЕ ДАННЫЕ
; ======================================================================
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
temp_ball resd 1
fips_prev resd 16

; ======================================================================
; КОД
; ======================================================================
section .text
global _start

_start:
    and     rsp, ~0xF
    
    ; ==================================================================
    ; ИНИЦИАЛИЗАЦИЯ
    ; ==================================================================
    call    check_cpu_features
    call    init_entropy
    call    init_cups
    call    refill_pool
    
    ; ==================================================================
    ; FIPS 140-2 POWER-ON SELF-TEST
    ; ==================================================================
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [fips_start_msg]
    mov     edx, fips_start_len
    syscall
    
    call    fips_self_test
    
    ; ==================================================================
    ; ГЕНЕРАЦИЯ ПАРОЛЯ
    ; ==================================================================
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
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    mov     rsi, pass
    mov     rdx, 25
    syscall
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

read_error_exit:
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [read_err_msg]
    mov     edx, read_err_len
    syscall
    jmp     fatal_exit

fatal_exit:
    mov     eax, SYS_EXIT
    mov     edi, 1
    syscall

; ======================================================================
; FIPS 140-2 САМОТЕСТИРОВАНИЕ
; ======================================================================
fips_self_test:
    PUSH_CALLEE
    
    ; Тест 1: Continuous RNG Test
    call    fips_crngt
    test    eax, eax
    jz      .t1_ok
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [fips_fail_crngt]
    mov     edx, fips_fail_crngt_len
    syscall
    jmp     fatal_exit
.t1_ok:
    
    ; Тест 2: Monobit Test
    call    fips_monobit
    test    eax, eax
    jz      .t2_ok
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [fips_fail_mono]
    mov     edx, fips_fail_mono_len
    syscall
    jmp     fatal_exit
.t2_ok:
    
    mov     eax, SYS_WRITE
    mov     edi, STDOUT
    lea     rsi, [fips_ok_msg]
    mov     edx, fips_ok_len
    syscall
    
    POP_CALLEE
    ret

; ----------------------------------------------------------------------
; ТЕСТ 1: Continuous Random Number Generator Test
; ----------------------------------------------------------------------
fips_crngt:
    PUSH_CALLEE
    
    call    refill_pool
    mov     ecx, 16
    lea     rsi, [rand_pool]
    lea     rdi, [fips_prev]
    rep movsd
    
    call    refill_pool
    mov     ecx, 16
    lea     rsi, [rand_pool]
    lea     rdi, [fips_prev]
    repe cmpsd
    je      .crngt_fail
    
    xor     eax, eax
    jmp     .crngt_done
.crngt_fail:
    mov     eax, 1
.crngt_done:
    POP_CALLEE
    ret

; ----------------------------------------------------------------------
; ТЕСТ 2: Monobit Test (20000 бит, границы 9725-10275)
; ----------------------------------------------------------------------
fips_monobit:
    PUSH_CALLEE
    
    mov     r12d, 2500
    xor     r13d, r13d
    
.mono_loop:
    mov     eax, [pool_pos]
    cmp     eax, 64
    jb      .mono_ok
    push    r12
    push    r13
    call    refill_pool
    pop     r13
    pop     r12
    xor     eax, eax
.mono_ok:
    lea     rbx, [rand_pool]
    movzx   eax, byte [rbx + rax]
    inc     dword [pool_pos]
    
    mov     ecx, 8
    mov     edx, eax
.count_bits:
    test    dl, 1
    jz      .bit_zero
    inc     r13d
.bit_zero:
    shr     dl, 1
    loop    .count_bits
    
    dec     r12d
    jnz     .mono_loop
    
    cmp     r13d, 9725
    jb      .mono_fail
    cmp     r13d, 10275
    ja      .mono_fail
    
    xor     eax, eax
    jmp     .mono_done
.mono_fail:
    mov     eax, 1
.mono_done:
    POP_CALLEE
    ret

; ======================================================================
; ПРОВЕРКА CPUID
; ======================================================================
check_cpu_features:
    push    rbx
    push    rcx
    push    rdx
    mov     eax, 1
    cpuid
    test    ecx, 1<<30
    jz      .no_rdrand
    mov     byte [cpu_rdrand], 1
.no_rdrand:
    test    ebx, 1<<18
    jz      .no_rdseed
    mov     byte [cpu_rdseed], 1
.no_rdseed:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; ======================================================================
; ИНИЦИАЛИЗАЦИЯ ЭНТРОПИИ
; ======================================================================
init_entropy:
    PUSH_CALLEE
    mov     eax, SYS_OPEN
    lea     rdi, [urandom_path]
    xor     esi, esi
    syscall
    test    eax, eax
    js      .fallback_to_rdrand
    mov     r12d, eax
    lea     r13, [state]
    mov     r14d, 64
.read_loop:
    mov     eax, SYS_READ
    mov     edi, r12d
    mov     rsi, r13
    mov     edx, r14d
    syscall
    test    rax, rax
    jz      .urandom_failed
    js      .check_eintr
    sub     r14d, eax
    add     r13, rax
    cmp     r14d, 0
    jne     .read_loop
    jmp     .close_and_done
.check_eintr:
    cmp     eax, -4
    je      .read_loop
    jmp     .urandom_failed
.close_and_done:
    mov     eax, SYS_CLOSE
    mov     edi, r12d
    syscall
    jmp     .done
.urandom_failed:
    mov     eax, SYS_CLOSE
    mov     edi, r12d
    syscall
    cmp     byte [cpu_rdrand], 1
    jne     .fatal_no_entropy
    mov     ecx, 16
    xor     ebx, ebx
.rdrand_loop:
    call    get_hw_random
    mov     [state + rbx*4], eax
    inc     ebx
    loop    .rdrand_loop
    jmp     .done
.fatal_no_entropy:
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
.fb_rdrand_loop:
    call    get_hw_random
    mov     [state + rbx*4], eax
    inc     ebx
    loop    .fb_rdrand_loop
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

; ======================================================================
; АППАРАТНЫЙ СЛУЧАЙНЫЙ БАЙТ
; ======================================================================
get_hw_random:
    push    rcx
    mov     ecx, 10
.retry:
    cmp     byte [cpu_rdrand], 1
    jne     .try_rdseed
    rdrand  eax
    jnc     .next_attempt
    pop     rcx
    ret
.try_rdseed:
    cmp     byte [cpu_rdseed], 1
    jne     .fail
    rdseed  eax
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

; ======================================================================
; СЛУЧАЙНЫЙ БАЙТ
; ======================================================================
get_random_byte:
    push    rcx
    call    get_hw_random
    and     eax, 0xFF
    pop     rcx
    ret

; ======================================================================
; ИНИЦИАЛИЗАЦИЯ КУБА
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
    mov     eax, r13d
    shl     rax, 6
    lea     rdi, [cups + rax]
    mov     r8d, r13d
    xor     r15d, r15d
.fill_balls:
    cmp     r15d, r14d
    jae     .next_cup
    push    rdi
    push    r8
    call    collect_single_entropy
    pop     r8
    pop     rdi
    mov     [temp_ball], ebx
    lea     rsi, [temp_ball]
    CUP_QR
    mov     ebx, [temp_ball]
    mov     [rdi + r15*4], ebx
    inc     r15d
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
    mov     r8d, r13d
    mov     eax, r13d
    shl     rax, 6
    lea     rdi, [cups + rax]
    push    rdi
    push    r8
    call    collect_single_entropy
    pop     r8
    pop     rdi
    mov     [temp_ball], ebx
    movzx   eax, byte [cup_ball_count + r13]
    cmp     eax, BALLS_PER_CUP
    jb      .add_ball
    push    rdi
    push    r8
    call    get_random_byte
    pop     r8
    pop     rdi
    and     eax, 0x0F
    jmp     .write_ball
.add_ball:
    inc     byte [cup_ball_count + r13]
.write_ball:
    mov     r9d, eax
    lea     rsi, [temp_ball]
    CUP_QR
    push    rdi
    push    rax
    push    rbx
    push    rcx
    push    rdx
    INTER_CUP_DIFFUSION
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    pop     rdi
    mov     ebx, [temp_ball]
    mov     [rdi + r9*4], ebx
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
    mov     r8d, r14d
    movzx   eax, byte [cup_ball_count + r14]
    test    eax, eax
    jz      .next_sip
    push    rax
    push    r8
    call    get_random_byte
    pop     r8
    pop     rcx
    xor     edx, edx
    div     ecx
    mov     r15d, eax
    mov     eax, r14d
    shl     rax, 6
    lea     rdi, [cups + rax]
    mov     ebx, [rdi + r15*4]
    mov     [temp_ball], ebx
    lea     rsi, [temp_ball]
    CUP_QR
    push    rdi
    push    rax
    push    rbx
    push    rcx
    push    rdx
    INTER_CUP_DIFFUSION
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    pop     rdi
    mov     ebx, [temp_ball]
    xor     [state + r13*4], ebx
    inc     dword [cups_take_count]
    mov     eax, [cups_take_count]
    and     eax, 0x07
    jnz     .skip_update
    push    rdi
    push    r8
    call    collect_single_entropy
    pop     r8
    pop     rdi
    mov     [temp_ball], ebx
    lea     rsi, [temp_ball]
    CUP_QR
    push    rdi
    push    rax
    push    rbx
    push    rcx
    push    rdx
    INTER_CUP_DIFFUSION
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax
    pop     rdi
    mov     ebx, [temp_ball]
    mov     [rdi + r15*4], ebx
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
; СЛУЧАЙНАЯ ПОЗИЦИЯ
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

; ======================================================================
; СБОР ОДНОГО ИСТОЧНИКА ЭНТРОПИИ
; ======================================================================
collect_single_entropy:
    push    rax
    push    rcx
    push    rdx
    call    get_hw_random
    mov     ebx, eax
    lfence
    rdtsc
    lfence
    xor     ebx, eax
    xor     ebx, edx
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

; ======================================================================
; ЗАПОЛНЕНИЕ ПУЛА
; ======================================================================
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

; ======================================================================
; SSE CHACHA20 BLOCK
; ======================================================================
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
; ОЧИСТКА ПАМЯТИ
; ======================================================================
burn_memory:
    PUSH_CALLEE
    lea     rdi, [state]
    mov     ecx, 48
    mov     eax, 0xDEADBEEF
    rep stosd
    lea     rdi, [state]
    mov     ecx, 48
    mov     eax, 0xAAAAAAAA
    rep stosd
    lea     rdi, [cups]
    mov     ecx, CUPS_SIZE
    mov     eax, 0x12345678
    rep stosd
    lea     rdi, [cups]
    mov     ecx, CUPS_SIZE
    xor     eax, eax
    rep stosd
    lea     rdi, [cup_ball_count]
    mov     ecx, CUPS_X * CUPS_Y
    rep stosb
    lea     rdi, [pass]
    mov     ecx, 64
    rep stosb
    mov     dword [pool_pos], 0
    mov     dword [cups_fill_count], 0
    mov     dword [cups_take_count], 0
    mov     dword [temp_ball], 0
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
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rdi, rdi
    xor     r8,  r8
    xor     r9,  r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15
    POP_CALLEE
    ret
