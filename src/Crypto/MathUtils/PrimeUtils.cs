using System.Numerics;
using System.Security.Cryptography;

namespace MathUtils;

/// <summary>
/// Utility methods for working with primes.
/// </summary>
public static class PrimeUtils {

  /// <summary>
  /// Get a random prime number.
  /// </summary>
  /// <param name="bits">Number of bits in the prime number.</param>
  /// <returns>Prime number on the given number of bits.</returns>
  public static BigInteger GetRandomPrime(int bits) {
    if (bits <= 2) {
      throw new ArgumentOutOfRangeException(nameof(bits), "Too Few Bits");
    }
    while (true) {
      BigInteger val = GenerateRandBigInt(BigInteger.Pow(2, bits));
      val |= 1;
      IsProbablePrime(val);
      if (IsProbablePrime(val)) {
        return val;
      }
    }
  }

  /// <summary>
  /// Tests whether a number is probably prime using the Miller-Rabin primality test.
  /// </summary>
  /// <param name="n">The number to test (must be greater than 1).</param>
  /// <param name="rounds">
  /// The number of witness rounds. Higher values reduce the probability of a false
  /// positive. 40 rounds gives a false positive probability of at most 2^(-80).
  /// </param>
  /// <returns>
  /// False if n is definitely composite; true if n is probably prime.
  /// </returns>

  public static BigInteger GenerateRandBigInt(BigInteger max) {
    byte[] random = new byte[max.GetByteCount(isUnsigned: true)];
    RandomNumberGenerator.Fill(random);
    BigInteger rand = new BigInteger(random, isUnsigned: true, isBigEndian: false);
    while(rand > max-1) {
      rand >>= 1;
    }
    rand |= 1;
    return rand;
  }
  public static bool IsProbablePrime(BigInteger n, int rounds = 40) {
    // int bits = n.GetBitLength(isUnsigned: true);
    // Console.WriteLine(bits);
    if (n == 2) {
      return true;
    }
    if (n % 2 == 0 || n < 2) {
      return false;
    }
    BigInteger s = 1;
    BigInteger d = (n -1) /2;
    while (d % 2 == 0) {
      s+=1;
      d/=2;
    }

    for (int k = 0; k < rounds; k+=1) {
      BigInteger a = GenerateRandBigInt(n-2);
      bool ProbablyPrime = false;
      //Console.WriteLine(a);


      BigInteger x = BigIntegerExtensions.ModExp(a, d, n);
      // BigInteger x = BigInteger.ModPow(a, d, n);
      if (x == 1 || x == (n - 1)) {
        ProbablyPrime = true;
      }
      for (int i = 1; i < s; i+=1) {
        x = BigIntegerExtensions.ModExp(x, 2, n);
        if (x == n - 1) {
          ProbablyPrime = true;
        }
      }
      if (!ProbablyPrime) {
        return false;
      }
    }
    return true;
  }

}
