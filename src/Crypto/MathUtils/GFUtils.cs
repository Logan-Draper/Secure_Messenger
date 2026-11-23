namespace MathUtils;

/// <summary>
/// Base class for implementing an Echo client.
/// </summary>
public static class GFUtils {

  /// <summary>
  /// The irreducible polynial for GF(2^8) used in AES (x^8 + x^4 + x^3 + x + 1).
  /// </summary>
  private const byte AESIrreduciblePolynomial = 0x1b;

  /// <summary>
  /// Calculates x * a(x) (mod p(x)) in GF(2^8).
  /// </summary>
  /// <param name="a">a(x).</param>
  /// <param name="p">p(x).</param>
  /// <returns>x * a(x) (mod p(x)) in GF(2^8).</returns>
  public static byte XTimes(byte a, byte p = AESIrreduciblePolynomial) {
    //if high order bit of 'a' is 0, then left shift and return a
    if ((a & (1 << 7)) == 0) {
      a <<= 1;
      return a;
    }
    else {
      a<<=1;
      return (byte)(a ^ p);
    }
  }

  /// <summary>
  /// Calculates a(x) * b(x) mod (mod p(x)) in GF(2^8).
  /// </summary>
  /// <param name="a">a(x)</param>
  /// <param name="b">b(x)</param>
  /// <returns>a(x) * b(x) mod (mod p(x)) in GF(2^8).</returns>
  /// <remarks>
  /// You must implement this function efficiently.
  /// At most, you may call <see cref="XTimes" /> at most seven times.
  /// You must calculate values as you go, not create a collection that stores values.
  /// </remarks>
  public static byte GFMultiply(byte a, byte b, byte p = AESIrreduciblePolynomial) {
    byte[] values = new byte[8];
    values[0] = b;
    for (int i = 1; i < 8; i+=1) {
      values[i] = XTimes(values[i-1], p);
    } 

    byte product = 0x00;
    for (int i = 0; i < 8; i+=1) {
      if ((a & (1 << i)) != 0) {
        product = (byte)(product ^ values[i]);
      }
    }
    return product;
  }

}
