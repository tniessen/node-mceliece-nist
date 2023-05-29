#ifndef crypto_uint16_h
#define crypto_uint16_h

#include <inttypes.h>
typedef uint16_t crypto_uint16;

typedef int16_t crypto_uint16_signed;

static crypto_uint16_signed crypto_uint16_signed_negative_mask(crypto_uint16_signed crypto_uint16_signed_x)
{
  return crypto_uint16_signed_x >> 15;
}

static crypto_uint16 crypto_uint16_nonzero_mask(crypto_uint16 crypto_uint16_x)
{
  return crypto_uint16_signed_negative_mask(crypto_uint16_x) | crypto_uint16_signed_negative_mask(-crypto_uint16_x);
}

static crypto_uint16 crypto_uint16_zero_mask(crypto_uint16 crypto_uint16_x)
{
  return ~crypto_uint16_nonzero_mask(crypto_uint16_x);
}

static crypto_uint16 crypto_uint16_unequal_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_x ^ crypto_uint16_y;
  return crypto_uint16_nonzero_mask(crypto_uint16_xy);
}

static crypto_uint16 crypto_uint16_equal_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  return ~crypto_uint16_unequal_mask(crypto_uint16_x,crypto_uint16_y);
}

static crypto_uint16 crypto_uint16_smaller_mask(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_x ^ crypto_uint16_y;
  crypto_uint16 crypto_uint16_z = crypto_uint16_x - crypto_uint16_y;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_x ^ (((crypto_uint16) 1) << 15));
  return crypto_uint16_signed_negative_mask(crypto_uint16_z);
}

static crypto_uint16 crypto_uint16_min(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << 15));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  return crypto_uint16_x ^ crypto_uint16_z;
}

static crypto_uint16 crypto_uint16_max(crypto_uint16 crypto_uint16_x,crypto_uint16 crypto_uint16_y)
{
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << 15));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  return crypto_uint16_y ^ crypto_uint16_z;
}

static void crypto_uint16_minmax(crypto_uint16 *crypto_uint16_a,crypto_uint16 *crypto_uint16_b)
{
  crypto_uint16 crypto_uint16_x = *crypto_uint16_a;
  crypto_uint16 crypto_uint16_y = *crypto_uint16_b;
  crypto_uint16 crypto_uint16_xy = crypto_uint16_y ^ crypto_uint16_x;
  crypto_uint16 crypto_uint16_z = crypto_uint16_y - crypto_uint16_x;
  crypto_uint16_z ^= crypto_uint16_xy & (crypto_uint16_z ^ crypto_uint16_y ^ (((crypto_uint16) 1) << 15));
  crypto_uint16_z = crypto_uint16_signed_negative_mask(crypto_uint16_z);
  crypto_uint16_z &= crypto_uint16_xy;
  *crypto_uint16_a = crypto_uint16_x ^ crypto_uint16_z;
  *crypto_uint16_b = crypto_uint16_y ^ crypto_uint16_z;
}

#endif
