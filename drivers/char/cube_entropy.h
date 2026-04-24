#ifndef _CUBE_ENTROPY_H
#define _CUBE_ENTROPY_H

#include <linux/types.h>
#include <linux/spinlock.h>

#define CUPS_X 16
#define CUPS_Y 16
#define CUPS_DEPTH 16
#define CUPS_SIZE (CUPS_X * CUPS_Y * CUPS_DEPTH)
#define BALLS_PER_CUP 16
#define CUPS_SURFACE (CUPS_X * CUPS_Y)

// alpha 0.1

struct cube_state {
    u32 cups[CUPS_SIZE];                    /* 3D-куб стаканчиков */
    u8 cup_ball_count[CUPS_SURFACE];        /* счётчик шариков */
    u32 state[16];                          /* ChaCha20 state */
    u32 state_save[16];                     /* сохранённое состояние */
    u8 rand_pool[64];                       /* выходной буфер */
    u32 pool_pos;                           /* позиция в буфере */
    u32 cups_fill_count;
    u32 cups_take_count;
    spinlock_t lock;                        /* потокобезопасность */
};

/* API функции */
void cube_entropy_init(struct cube_state *cs);
void cube_mix_bytes(struct cube_state *cs, const void *in, int nbytes);
void cube_extract_bytes(struct cube_state *cs, void *out, int nbytes);

#endif /* _CUBE_ENTROPY_H */
