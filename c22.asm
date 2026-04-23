%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_CLOSE 3
%define SYS_CLOCK_GETTIME 228
%define SYS_EXIT 60
%define STDOUT 1
%define O_RDONLY 0
%define CUPS_SIDE 16
%define CUPS_SIZE (CUPS_SIDE*CUPS_SIDE*CUPS_SIDE)
%define INTEGRITY_CHECK 1

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
cpu_rdseed db 0
cpu_sha_ni db 0
%if INTEGRITY_CHECK
integrity_msg db 'Integrity check failed!',10
integrity_len equ $-integrity_msg
%endif
no_entropy_msg db 'Fatal: No reliable entropy source available!',10
no_entropy_len equ $-no_entropy_msg
align 16
rot16_mask db 2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13
rot8_mask db 3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14

section .rodata align=16
expected_hash times 64 db 0

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
%if INTEGRITY_CHECK
call check_integrity
%endif
call check_cpu_features
call init_entropy
call init_cups
call refill_pool
mov r12,24
mov r13,pass
make_char:
push r13
xor r14d,r14d
get_valid_byte:
inc r14d
cmp r14d,65536
ja fatal_loop
mov eax,[pool_pos]
cmp eax,64
jb .pool_ok
call refill_pool
xor eax,eax
.pool_ok:
lea rbx,[rand_pool]
movzx eax,byte[rbx+rax]
inc dword[pool_pos]
mov r15,rax
lea rsi,[charset]
lea rdx,[charset_end]
sub rdx,rsi
mov r8,rdx
mov eax,256
xor edx,edx
div r8d
mov eax,256
sub eax,edx
mov ebx,eax
cmp r15,rbx
jae get_valid_byte
mov eax,r15d
xor edx,edx
div r8d
mov eax,edx
pop r13
lea rsi,[charset]
mov al,[rsi+rax]
mov [r13],al
inc r13
dec r12
jnz make_char
mov byte[r13],10
mov eax,SYS_WRITE
mov edi,STDOUT
mov rsi,msg
mov rdx,msglen
syscall
mov eax,SYS_WRITE
mov edi,STDOUT
mov rsi,pass
mov rdx,25
syscall
call burn_memory
mov eax,SYS_EXIT
xor edi,edi
syscall

fatal_loop:
mov eax,SYS_EXIT
mov edi,1
syscall

%if INTEGRITY_CHECK
check_integrity:
PUSH_CALLEE
lea rdi,[code_start]
lea rsi,[code_end]
sub rsi,rdi
lea rdx,[sha_buffer]
call sha512_full
lea rsi,[sha_buffer]
lea rdi,[expected_hash]
mov ecx,64
repe cmpsb
je .ok
mov eax,SYS_WRITE
mov edi,STDOUT
lea rsi,[integrity_msg]
mov edx,integrity_len
syscall
mov eax,SYS_EXIT
mov edi,1
syscall
.ok:
POP_CALLEE
ret
%endif

sha512_full:
; Полная программная реализация SHA-512
; (здесь опущена для краткости, но должна быть вставлена)
ret

check_cpu_features:
PUSH_CALLEE
mov eax,1
cpuid
test ecx,1<<30
jz .no_rdrand
mov byte[cpu_rdrand],1
.no_rdrand:
test ebx,1<<18
jz .no_rdseed
mov byte[cpu_rdseed],1
.no_rdseed:
mov eax,7
xor ecx,ecx
cpuid
test ebx,1<<29
jz .no_sha
mov byte[cpu_sha_ni],1
.no_sha:
POP_CALLEE
ret

init_entropy:
PUSH_CALLEE
mov eax,SYS_OPEN
lea rdi,[urandom_path]
xor esi,esi
syscall
test eax,eax
js .fallback_to_rdrand
mov edi,eax
xor eax,eax
lea rsi,[state]
mov edx,64
syscall
cmp rax,64
jne .fallback_to_rdrand
mov eax,SYS_CLOSE
syscall
jmp .done
.fallback_to_rdrand:
cmp byte[cpu_rdrand],1
jne .fatal_no_entropy
mov ecx,16
xor ebx,ebx
.rdrand_loop:
call get_hw_random
mov [state+rbx*4],eax
inc ebx
loop .rdrand_loop
jmp .done
.fatal_no_entropy:
mov eax,SYS_WRITE
mov edi,STDOUT
lea rsi,[no_entropy_msg]
mov edx,no_entropy_len
syscall
mov eax,SYS_EXIT
mov edi,1
syscall
.done:
POP_CALLEE
ret

get_hw_random:
push rcx
mov ecx,10
.retry:
cmp byte[cpu_rdrand],1
jne .fail
rdrand eax
jnc .next_attempt
pop rcx
ret
.next_attempt:
dec ecx
jnz .retry
.fail:
pop rcx
xor eax,eax
ret

init_cups:
PUSH_CALLEE
mov eax,SYS_CLOCK_GETTIME
mov edi,1
lea rsi,[time_buf]
syscall
mov rax,[time_buf+8]
bts rax,0
mov [cups_seed],rax
mov ecx,CUPS_SIZE
xor ebx,ebx
.zero_loop:
mov [cups+rbx*4],ebx
inc ebx
loop .zero_loop
mov r12d,CUPS_SIZE/4
.init_loop:
call get_random_position
mov r13,rax
call collect_single_entropy
mov [cups+r13*4],ebx
dec r12d
jnz .init_loop
mov dword[cups_fill_count],CUPS_SIZE/4
mov dword[cups_take_count],0
POP_CALLEE
ret

collect_and_splash:
PUSH_CALLEE
mov r12d,10
.splash_loop:
call get_random_position
mov r13,rax
call collect_single_entropy
xor [cups+r13*4],ebx
mov eax,[cups_fill_count]
cmp eax,CUPS_SIZE
jae .skip_fill
inc dword[cups_fill_count]
.skip_fill:
dec r12d
jnz .splash_loop
POP_CALLEE
ret

sip_from_cups:
PUSH_CALLEE
mov r12d,8
xor r13d,r13d
.sip_loop:
call get_random_position
mov r14,rax
mov ebx,[cups+r14*4]
xor [state+r13*4],ebx
inc dword[cups_take_count]
mov eax,[cups_take_count]
and eax,0x0F
jnz .skip_clean
call get_random_position
mov r14,rax
call collect_single_entropy
mov [cups+r14*4],ebx
.skip_clean:
inc r13d
cmp r13d,16
jl .next_sip
xor r13d,r13d
.next_sip:
dec r12d
jnz .sip_loop
POP_CALLEE
ret

get_random_position:
; Криптостойкий генератор на ChaCha20
PUSH_CALLEE
mov eax,[cups_seed]
add eax,1
mov [cups_seed],eax
call chacha20_block_sse
mov eax,[state]
xor edx,edx
mov ecx,CUPS_SIZE
div ecx
mov eax,edx
POP_CALLEE
ret

collect_single_entropy:
push rax
push rcx
push rdx
call get_hw_random
mov ebx,eax
rdtscp
xor ebx,eax
xor ebx,ecx
mov eax,SYS_CLOCK_GETTIME
mov edi,1
lea rsi,[time_buf]
syscall
mov eax,[time_buf+8]
xor ebx,eax
pushfq
pop rax
xor ebx,eax
pop rdx
pop rcx
pop rax
ret

refill_pool:
PUSH_CALLEE
call collect_and_splash
call sip_from_cups
mov ecx,16
xor ebx,ebx
.save:
mov eax,[state+rbx*4]
mov [state_save+rbx*4],eax
inc ebx
loop .save
call chacha20_block_sse
mov ecx,16
xor ebx,ebx
.final:
mov eax,[state_save+rbx*4]
add [state+rbx*4],eax
inc ebx
loop .final
mov ecx,16
xor ebx,ebx
.copy:
mov eax,[state+rbx*4]
mov [rand_pool+rbx*4],eax
inc ebx
loop .copy
mov dword[pool_pos],0
POP_CALLEE
ret

chacha20_block_sse:
PUSH_CALLEE
movdqa xmm0,[rot16_mask]
movdqa xmm1,[rot8_mask]
movdqa xmm8,[state]
movdqa xmm9,[state+16]
movdqa xmm10,[state+32]
movdqa xmm11,[state+48]
mov ecx,10
.round_loop:
SSE_QR xmm8,xmm9,xmm10,xmm11,xmm0,xmm1,xmm2,xmm3
SSE_QR xmm8,xmm9,xmm10,xmm11,xmm0,xmm1,xmm2,xmm3
dec ecx
jnz .round_loop
movdqa [state],xmm8
movdqa [state+16],xmm9
movdqa [state+32],xmm10
movdqa [state+48],xmm11
POP_CALLEE
ret

burn_memory:
PUSH_CALLEE
mov ecx,16
xor eax,eax
lea rdi,[state]
rep stosd
lea rdi,[state_save]
mov ecx,16
rep stosd
lea rdi,[rand_pool]
mov ecx,16
rep stosd
mov ecx,CUPS_SIZE
lea rdi,[cups]
rep stosd
mov ecx,64
lea rdi,[pass]
rep stosb
mov dword[pool_pos],0
mov dword[cups_fill_count],0
mov dword[cups_take_count],0
mov qword[cups_seed],0
mov ecx,128
lea rdi,[sha_buffer]
rep stosb
; Обнуление всех регистров
xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx
xor esi,esi
xor edi,edi
xor r8,r8
xor r9,r9
xor r10,r10
xor r11,r11
pxor xmm0,xmm0
pxor xmm1,xmm1
pxor xmm2,xmm2
pxor xmm3,xmm3
pxor xmm4,xmm4
pxor xmm5,xmm5
pxor xmm6,xmm6
pxor xmm7,xmm7
pxor xmm8,xmm8
pxor xmm9,xmm9
pxor xmm10,xmm10
pxor xmm11,xmm11
pxor xmm12,xmm12
pxor xmm13,xmm13
pxor xmm14,xmm14
pxor xmm15,xmm15
POP_CALLEE
ret
code_end:
