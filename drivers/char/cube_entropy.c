/*
 *  * cube_entropy.c - 3D Cube Entropy Pool (без констант)
 *   * Адаптировано из NASM-кода c22.asm alpha-0.1
 *    * Идея: полный отказ от криптографических констант,
 *     * вся энтропия собирается аппаратно.
 *      */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/prandom.h>
#include <asm/processor.h>
#include "cube_entropy.h"

/* SSE-маски для pshufb (таблицы перестановок для циклических сдвигов) */
static const u8 rot16_mask[16] __aligned(16) = {
    2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
};
static const u8 rot8_mask[16] __aligned(16) = {
    3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
};

/*
 *  * Аппаратный случайный байт (RDRAND с fallback на RDTSC)
 *   * Это ядерный аналог твоей get_hw_random
 *    */
static inline u32 get_hw_random(void)
{
    unsigned int eax, edx;
    unsigned long long tsc;

    /* Пытаемся RDRAND */
    if (__builtin_cpu_supports("rdrand")) {
        for (int i = 0; i < 10; i++) {
            if (__builtin_ia32_rdrand32_step(&eax))
                return eax;
        }
    }

    /* Fallback на RDTSC */
    tsc = rdtsc();
    eax = (u32)(tsc & 0xFFFFFFFF);
    edx = (u32)(tsc >> 32);
    return eax ^ edx;
}

/*
 *  * Сбор одного источника энтропии (аналог collect_single_entropy)
 *   * Микширование RDRAND + RDTSC + EFLAGS
 *    */
static u32 collect_single_entropy(void)
{
    u32 result = get_hw_random();
    unsigned long long tsc = rdtsc();
    unsigned long flags;

    /* Микшируем RDTSC */
    result ^= (u32)(tsc & 0xFFFFFFFF);
    result ^= (u32)(tsc >> 32);

    /* Микшируем EFLAGS */
    asm volatile("pushfq\n\tpopq %0" : "=r"(flags));
    result ^= (u32)(flags & 0xFFFFFFFF);

    return result;
}

/*
 *  * SSE ChaCha20 Block (AT&T синтаксис)
 *   * Это прямой перевод твоего макроса SSE_QR и chacha20_block_sse
 *    */
static void chacha20_block_sse(u32 state[16])
{
    asm volatile(
        /* Загружаем маски */
        "movdqa (%0), %%xmm0\n\t"      /* rot16_mask */
        "movdqa (%1), %%xmm1\n\t"      /* rot8_mask */

        /* Загружаем состояние */
        "movdqa (%2), %%xmm8\n\t"
        "movdqa 16(%2), %%xmm9\n\t"
        "movdqa 32(%2), %%xmm10\n\t"
        "movdqa 48(%2), %%xmm11\n\t"

        "movl $10, %%ecx\n\t"          /* 10 раундов */

    ".Lround_loop:\n\t"

        /* SSE_QR макрос вручную */
        "paddd %%xmm9, %%xmm8\n\t"
        "pxor %%xmm8, %%xmm11\n\t"
        "pshufb %%xmm0, %%xmm11\n\t"
        "paddd %%xmm11, %%xmm10\n\t"
        "pxor %%xmm10, %%xmm9\n\t"
        "movdqa %%xmm9, %%xmm2\n\t"
        "pslld $12, %%xmm9\n\t"
        "psrld $20, %%xmm2\n\t"
        "por %%xmm2, %%xmm9\n\t"
        "paddd %%xmm9, %%xmm8\n\t"
        "pxor %%xmm8, %%xmm11\n\t"
        "pshufb %%xmm1, %%xmm11\n\t"
        "paddd %%xmm11, %%xmm10\n\t"
        "pxor %%xmm10, %%xmm9\n\t"
        "movdqa %%xmm9, %%xmm2\n\t"
        "pslld $7, %%xmm9\n\t"
        "psrld $25, %%xmm2\n\t"
        "por %%xmm2, %%xmm9\n\t"

        /* Второй диагональный раунд */
        "paddd %%xmm9, %%xmm8\n\t"
        "pxor %%xmm8, %%xmm11\n\t"
        "pshufb %%xmm0, %%xmm11\n\t"
        "paddd %%xmm11, %%xmm10\n\t"
        "pxor %%xmm10, %%xmm9\n\t"
        "movdqa %%xmm9, %%xmm2\n\t"
        "pslld $12, %%xmm9\n\t"
        "psrld $20, %%xmm2\n\t"
        "por %%xmm2, %%xmm9\n\t"
        "paddd %%xmm9, %%xmm8\n\t"
        "pxor %%xmm8, %%xmm11\n\t"
        "pshufb %%xmm1, %%xmm11\n\t"
        "paddd %%xmm11, %%xmm10\n\t"
        "pxor %%xmm10, %%xmm9\n\t"
        "movdqa %%xmm9, %%xmm2\n\t"
        "pslld $7, %%xmm9\n\t"
        "psrld $25, %%xmm2\n\t"
        "por %%xmm2, %%xmm9\n\t"

        "decl %%ecx\n\t"
        "jnz .Lround_loop\n\t"

        /* Сохраняем результат */
        "movdqa %%xmm8, (%2)\n\t"
        "movdqa %%xmm9, 16(%2)\n\t"
        "movdqa %%xmm10, 32(%2)\n\t"
        "movdqa %%xmm11, 48(%2)\n\t"
        :
        : "r"(rot16_mask), "r"(rot8_mask), "r"(state)
        : "memory", "cc",
          "xmm0", "xmm1", "xmm2", "xmm8", "xmm9",
          "xmm10", "xmm11", "ecx"
    );
}

/*
 *  * Получение случайной позиции в кубе (аналог get_random_position)
 *   */
static u32 get_random_position(void)
{
    return prandom_u32() % CUPS_SURFACE;
}

/*
 *  * Разбрасывание шариков (аналог collect_and_splash)
 *   */
static void collect_and_splash(struct cube_state *cs)
{
    for (int i = 0; i < 10; i++) {
        u32 pos = get_random_position();
        u32 ball = collect_single_entropy();

        /* Получаем текущий счётчик шариков в стаканчике */
        u8 count = cs->cup_ball_count[pos];

        if (count < BALLS_PER_CUP) {
            /* Добавляем шарик */
            cs->cups[pos * BALLS_PER_CUP + count] = ball;
            cs->cup_ball_count[pos]++;
        } else {
            /* Перезаписываем случайный шарик */
            u8 idx = get_hw_random() % BALLS_PER_CUP;
            cs->cups[pos * BALLS_PER_CUP + idx] = ball;
        }

        if (cs->cups_fill_count < CUPS_SIZE)
            cs->cups_fill_count++;
    }
}

/*
 *  * Извлечение шариков (аналог sip_from_cups)
 *   */
static void sip_from_cups(struct cube_state *cs)
{
    u32 state_idx = 0;

    for (int i = 0; i < 8; i++) {
        u32 pos = get_random_position();
        u8 count = cs->cup_ball_count[pos];

        if (count == 0)
            continue;

        /* Выбираем случайный шарик */
        u8 ball_idx = get_hw_random() % count;
        u32 ball = cs->cups[pos * BALLS_PER_CUP + ball_idx];

        /* XOR-им в состояние */
        cs->state[state_idx] ^= ball;

        cs->cups_take_count++;

        /* Периодическое обновление шарика */
        if ((cs->cups_take_count & 0x07) == 0) {
            u32 new_ball = collect_single_entropy();
            cs->cups[pos * BALLS_PER_CUP + ball_idx] = new_ball;
        }

        state_idx = (state_idx + 1) % 16;
    }
}

/*
 *  * Инициализация куба (аналог init_cups)
 *   */
void cube_entropy_init(struct cube_state *cs)
{
    unsigned long flags;

    spin_lock_init(&cs->lock);
    spin_lock_irqsave(&cs->lock, flags);

    /* Обнуляем куб */
    memset(cs->cups, 0, sizeof(cs->cups));
    memset(cs->cup_ball_count, 0, sizeof(cs->cup_ball_count));
    memset(cs->state, 0, sizeof(cs->state));

    /* Заполняем начальной энтропией */
    for (u32 i = 0; i < CUPS_SURFACE; i++) {
        u8 balls = get_hw_random() % 13;  /* 0-12 */
        if (balls < 4)
            balls = 8;
        cs->cup_ball_count[i] = balls;

        for (u32 j = 0; j < balls; j++) {
            u32 entropy = collect_single_entropy();
            cs->cups[i * BALLS_PER_CUP + j] = entropy;
        }
    }

    cs->cups_fill_count = CUPS_SURFACE;
    cs->cups_take_count = 0;
    cs->pool_pos = 64;

    spin_unlock_irqrestore(&cs->lock, flags);
}

/*
 *  * Заполнение выходного пула (аналог refill_pool)
 *   */
static void refill_pool(struct cube_state *cs)
{
    unsigned long flags;

    spin_lock_irqsave(&cs->lock, flags);

    /* Собираем и разбрасываем энтропию */
    collect_and_splash(cs);

    /* Извлекаем энтропию из куба в состояние */
    sip_from_cups(cs);

    /* Сохраняем копию состояния */
    memcpy(cs->state_save, cs->state, sizeof(cs->state));

    /* ChaCha20 раунды */
    chacha20_block_sse(cs->state);

    /* Финальное сложение */
    for (int i = 0; i < 16; i++)
        cs->state[i] += cs->state_save[i];

    /* Копируем результат в выходной буфер */
    memcpy(cs->rand_pool, cs->state, 64);
    cs->pool_pos = 0;

    spin_unlock_irqrestore(&cs->lock, flags);
}

/*
 *  * НОВАЯ функция смешивания — замена _mix_pool_bytes()
 *   * Принимает энтропию и "разбрасывает" её по кубу
 *    */
void cube_mix_bytes(struct cube_state *cs, const void *in, int nbytes)
{
    const u32 *words = in;
    int nwords = nbytes / 4;

    spin_lock(&cs->lock);

    for (int i = 0; i < nwords; i++) {
        u32 pos = get_random_position();
        u8 count = cs->cup_ball_count[pos];

        if (count < BALLS_PER_CUP) {
            cs->cups[pos * BALLS_PER_CUP + count] = words[i];
            cs->cup_ball_count[pos]++;
        } else {
            u8 idx = get_hw_random() % BALLS_PER_CUP;
            cs->cups[pos * BALLS_PER_CUP + idx] = words[i];
        }
    }

    if (cs->cups_fill_count < CUPS_SIZE)
        cs->cups_fill_count += nwords;

    spin_unlock(&cs->lock);
}

/*
 *  * Извлечение случайных байт из куба
 *   */
void cube_extract_bytes(struct cube_state *cs, void *out, int nbytes)
{
    u8 *buf = out;
    int remaining = nbytes;

    spin_lock(&cs->lock);

    while (remaining > 0) {
        /* Если пул опустел — перезаполняем */
        if (cs->pool_pos >= 64)
            refill_pool(cs);

        int chunk = min(remaining, 64 - (int)cs->pool_pos);
        memcpy(buf, cs->rand_pool + cs->pool_pos, chunk);
        cs->pool_pos += chunk;
        buf += chunk;
        remaining -= chunk;
    }

    spin_unlock(&cs->lock);
}
