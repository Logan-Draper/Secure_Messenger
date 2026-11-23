using System.Numerics;

namespace MathUtils;

public static class BigIntegerExtensions {

  /// <summary>
  /// Computes the Greatest Common Divisor of a and b, along with the 
  /// Bézout coefficients u and v such that: (a * u) + (b * v) = gcd(a, b).
  /// </summary>
  /// <param name="a">First integer.</param>
  /// <param name="b">Second integer.</param>
  /// <returns>A tuple (gcd, x, y), where gcd is the GCD of a and b,
  /// and x, y are the Bézout coefficients.</returns>
  /// <remarks>
  /// Your implementation will need to handle the case that gcd(a, 0) = gcd(0, a) = a.
  /// </remarks>
  public static (BigInteger gcd, BigInteger u, BigInteger v) ExtendedEuclidean(BigInteger a, BigInteger b) {
    BigInteger u, v, gcd;
    BigInteger r = a;
    if (b != 0) {
      r = a % b;
    }

    if (r == 0) {
      return (b, 0, 1);
    }
    (gcd, u, v) = ExtendedEuclidean(b, r);
    //d = av + b(u - qv)
    BigInteger q = 0;
    if (b != 0) {
      q = a / b;
    }
    return (gcd, v, u - q*v);
  }

  extension(BigInteger a) {

    /// <summary>
    /// Calculates this (mod n).
    /// </summary>
    /// <param name="n">The modulus n.</param>
    /// <returns>this (mod n)/returns>
    public BigInteger Mod(BigInteger n) {
      if (n < 2) throw new ArgumentOutOfRangeException(nameof(n), "Modulus must be greater than 1.");

      var result = a % n;
      if (result < 0) return result + n;
      return result;
    }

    /// <summary>
    /// Calculates this + b (mod n).
    /// </summary>
    /// <param name="b">The number to add.</param>
    /// <param name="n">The modulus n.</param>
    /// <returns>this + b (mod n)/returns>
    public BigInteger ModAdd(BigInteger b, BigInteger n) {
      return Mod(Mod(a, n) + Mod(b, n), n);
    }

    /// <summary>
    /// Calculates this - b (mod n).
    /// </summary>
    /// <param name="b">The number to subtract.</param>
    /// <param name="n">The modulus n.</param>
    /// <returns>this - b (mod n)/returns>
    public BigInteger ModSubstract(BigInteger b, BigInteger n) {
      return Mod(Mod(a, n) + Mod(-b, n), n);
    }

    /// <summary>
    /// Calculates this * b (mod n).
    /// </summary>
    /// <param name="b">The number to multiply.</param>
    /// <param name="n">The modulus n.</param>
    /// <returns>this * b (mod n)/returns>
    public BigInteger ModMultiply(BigInteger b, BigInteger n) {
      return Mod(Mod(a, n) * Mod(b, n), n);
    }

    /// <summary>
    /// Calculates this^-1 (mod n).
    /// </summary>
    /// <param name="n">The modulus n.</param>
    /// <returns>this^-1 (mod n)/returns>
    /// <remarks>
    /// You must implement this using <see cref="ExtendedEuclidean"/>.
    /// </remarks>
    public BigInteger ModInverse(BigInteger n) {
      //d = au + bv
      //let modulus n = v
      //d = this(u)+bn
      // a^-1 is congruent to u
      //extended euclidian returns d, u, v
      if (a == 0) {
        throw new ArgumentOutOfRangeException(nameof(n), "The element 0 has no modular inverse.");
      }
      BigInteger u, gcd;
      (gcd, u, _) = ExtendedEuclidean(a, n);
      if (gcd != 1) {
        throw new ArgumentException(nameof(gcd), "The elements are not coprime: d != 1");
      }
      if (u < 0) {
        return n + u;
      }
      return u;
    }

    /// <summary>
    /// Calculates this / b (mod n).
    /// </summary>
    /// <param name="b">The number to divide by.</param>
    /// <param name="n">The modulus n.</param>
    /// <returns>this / b (mod n)/returns>
    public BigInteger ModDivide(BigInteger b, BigInteger n) {
      if (b == 0) {
        throw new ArgumentOutOfRangeException(nameof(b), "Divisor must not be 0");
      }
      if (a < 0) a += n;
      if (b < 0) b += n;
      return Mod(a * ModInverse(b, n), n);
    }

    /// <summary>
    /// Computes this^e (mod n).
    /// </summary>
    /// <param name="e">The exponent (must be non-negative).</param>
    /// <param name="n">The modulus (must be positive).</param>
    /// <returns>The result of b^e (mod n).</returns>
    /// <remarks>
    /// You must implement this function efficiently.
    /// At most, you may use <see cref="ModMultiply" /> Ceiling(log2(base)) + #bits_set(exponent)) times.
    /// You are only allowed a single <see cref="BigInteger"/> for local variables.
    /// </remarks>
    public BigInteger ModExp(BigInteger e, BigInteger n) {
      if (e == 0) {
        return 1;
      }
      if (e == -1) {
        return ModInverse(a, n);
      }
      BigInteger power = 1;
      int i;
      BigInteger[] powersOfA = new BigInteger[(int)BigInteger.Log(e, 2) + 1];
      powersOfA[0] = a;
      for (i = 1; i < (BigInteger)BigInteger.Log(e, 2) + 1; i+=1) {
        powersOfA[i] = powersOfA[i-1] * powersOfA[i -1] % n;
      }
      for (i = 0; i < (BigInteger)BigInteger.Log(e, 2) + 1; i+=1) {
        if (((e >> i) & 1) == 1) {
          power = power * powersOfA[i] % n;
        }
      }
      return power;
    }

  }
}
