#include "hash.h"
#include "tables.h"
#include <hash.c>

#define COLWORDS     (STATEWORDS/8)
#define BYTESLICE(i) (((i)&7)*STATECOLS+(i)/8)

#if CRYPTO_BYTES<=32
static const u32 columnconstant[2] = { 0x30201000, 0x70605040 };
static const u8 shiftvalues[2][8] = { {0, 1, 2, 3, 4, 5, 6, 7}, {1, 3, 5, 7, 0, 2, 4, 6} };
#else
static const u32 columnconstant[4] = { 0x30201000, 0x70605040, 0xb0a09080, 0xf0e0d0c0 };
static const u8 shiftvalues[2][8] = { {0, 1, 2, 3, 4, 5, 6, 11}, {1, 3, 5, 11, 0, 2, 4, 6} };
#endif




__ kernel void permutation(u32 *buffer, u8 *cond)
{
  __attribute__ ((aligned (8))) u32 tmp[8];
  u32 constant;
  int tx = get_local_id(0);
  int ty = get_local_id(1);
  int i, j;
  for(constant=0; constant<(0x01010101*ROUNDS); constant+=0x01010101)
  {
    if (cond[0]==0)
    {
      while(ty<COLWORDS)
        buffer[ty] ^= columnconstant[ty]^constant;
    }
    else
    {
      while(tx<STATEWORDS)
        buffer[i] = ~buffer[i];
      while(ty<COLWORDS)
        buffer[STATEWORDS-COLWORDS+j] ^= columnconstant[j]^constant;
    }
    if (tx<8)
    {
      while(ty<COLWORDS)
        tmp[ty] = buffer[tx*COLWORDS+ty];
      while(ty<STATECOLS)
        ((u8*)buffer)[tx*STATECOLS+ty] = S[((u8*)tmp)[(ty+shiftvalues[cond][tx])>>(STATECOLS-1)]];
    }

    while(ty<COLWORDS)
      mixbytes((u32(*)[COLWORDS])buffer, tmp, ty);
  }
}