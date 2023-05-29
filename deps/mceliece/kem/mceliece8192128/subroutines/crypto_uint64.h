#ifndef crypto_uint64_h
#define crypto_uint64_h

#include <inttypes.h>
typedef uint64_t crypto_uint64;

typedef int64_t crypto_uint64_signed;

static crypto_uint64_signed crypto_uint64_signed_negative_mask(crypto_uint64_signed crypto_uint64_signed_x)
{
  return crypto_uint64_signed_x >> 63;
}

static crypto_uint64 crypto_uint64_nonzero_mask(crypto_uint64 crypto_uint64_x)
{
  return crypto_uint64_signed_negative_mask(crypto_uint64_x) | crypto_uint64_signed_negative_mask(-crypto_uint64_x);
}

static crypto_uint64 crypto_uint64_zero_mask(crypto_uint64 crypto_uint64_x)
{
  return ~crypto_uint64_nonzero_mask(crypto_uint64_x);
}

static crypto_uint64 crypto_uint64_unequal_mask(crypto_uint64 crypto_uint64_x,crypto_uint64 crypto_uint64_y)
{
  crypto_uint64 crypto_uint64_xy = crypto_uint64_x ^ crypto_uint64_y;
  return crypto_uint64_nonzero_mask(crypto_uint64_xy);
}

static crypto_uint64 crypto_uint64_equal_mask(crypto_uint64 crypto_uint64_x,crypto_uint64 crypto_uint64_y)
{
  return ~crypto_uint64_unequal_mask(crypto_uint64_x,crypto_uint64_y);
}

static crypto_uint64 crypto_uint64_smaller_mask(crypto_uint64 crypto_uint64_x,crypto_uint64 crypto_uint64_y)
{
  crypto_uint64 crypto_uint64_xy = crypto_uint64_x ^ crypto_uint64_y;
  crypto_uint64 crypto_uint64_z = crypto_uint64_x - crypto_uint64_y;
  crypto_uint64_z ^= crypto_uint64_xy & (crypto_uint64_z ^ crypto_uint64_x ^ (((crypto_uint64) 1) << 63));
  return crypto_uint64_signed_negative_mask(crypto_uint64_z);
}

static crypto_uint64 crypto_uint64_min(crypto_uint64 crypto_uint64_x,crypto_uint64 crypto_uint64_y)
{
  crypto_uint64 crypto_uint64_xy = crypto_uint64_y ^ crypto_uint64_x;
  crypto_uint64 crypto_uint64_z = crypto_uint64_y - crypto_uint64_x;
  crypto_uint64_z ^= crypto_uint64_xy & (crypto_uint64_z ^ crypto_uint64_y ^ (((crypto_uint64) 1) << 63));
  crypto_uint64_z = crypto_uint64_signed_negative_mask(crypto_uint64_z);
  crypto_uint64_z &= crypto_uint64_xy;
  return crypto_uint64_x ^ crypto_uint64_z;
}

static crypto_uint64 crypto_uint64_max(crypto_uint64 crypto_uint64_x,crypto_uint64 crypto_uint64_y)
{
  crypto_uint64 crypto_uint64_xy = crypto_uint64_y ^ crypto_uint64_x;
  crypto_uint64 crypto_uint64_z = crypto_uint64_y - crypto_uint64_x;
  crypto_uint64_z ^= crypto_uint64_xy & (crypto_uint64_z ^ crypto_uint64_y ^ (((crypto_uint64) 1) << 63));
  crypto_uint64_z = crypto_uint64_signed_negative_mask(crypto_uint64_z);
  crypto_uint64_z &= crypto_uint64_xy;
  return crypto_uint64_y ^ crypto_uint64_z;
}

static void crypto_uint64_minmax(crypto_uint64 *crypto_uint64_a,crypto_uint64 *crypto_uint64_b)
{
  crypto_uint64 crypto_uint64_x = *crypto_uint64_a;
  crypto_uint64 crypto_uint64_y = *crypto_uint64_b;
  crypto_uint64 crypto_uint64_xy = crypto_uint64_y ^ crypto_uint64_x;
  crypto_uint64 crypto_uint64_z = crypto_uint64_y - crypto_uint64_x;
  crypto_uint64_z ^= crypto_uint64_xy & (crypto_uint64_z ^ crypto_uint64_y ^ (((crypto_uint64) 1) << 63));
  crypto_uint64_z = crypto_uint64_signed_negative_mask(crypto_uint64_z);
  crypto_uint64_z &= crypto_uint64_xy;
  *crypto_uint64_a = crypto_uint64_x ^ crypto_uint64_z;
  *crypto_uint64_b = crypto_uint64_y ^ crypto_uint64_z;
}

#endif
