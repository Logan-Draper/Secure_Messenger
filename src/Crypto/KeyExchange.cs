using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

using ECCurve = MathUtils.ECCurve;
using ECPoint = MathUtils.ECPoint;
using Parameters = AsymmetricCryptography.ECParameters.Parameters;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of unauthenticated Diffie-Hellman.
/// </summary>
public class DiffieHellman {

  #region Record types

  /// <summary>
  /// Diffie-Hellman group parameters.
  /// </summary>
  /// <param name="Modulus">The modulus for group operations.</param>
  /// <param name="Generator">The generator for group operations.</param>
  /// <param name="Order">The order of the generator <c>g</c>.</param>
  public record struct Parameters(BigInteger Modulus, BigInteger Generator, BigInteger Order);

  #endregion

  #region Configuration

  /// <summary>The smallest modulus bit length this implementation will generate.</summary>
  public const int MinimumBitLength = 32;
  private readonly BigInteger _p; //modulus
  private readonly BigInteger _q; // order of g
  private readonly BigInteger _g; //generator
  private readonly BigInteger _privateValue; //private value

  #endregion

  #region Key retrieval

  /// <summary>Returns the parameters held by this instance.</summary>
  public Parameters GetParameters() =>
  new Parameters(_p, _g, _q);

  /// <summary>Returns the public key held by this instance.</summary>
  public BigInteger GetPublicValue() =>
  //g^a mod p
  //g^b mod p
  BigIntegerExtensions.ModExp(_g, _privateValue, _p);


  #endregion

  #region Constructors

  /// <summary>
  /// Create an Diffie-Hellman instance. Generates parameters and key pair.
  /// </summary>
  /// <param name="bitLength">Modulus size in bits.</param>
  /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
  /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
  public DiffieHellman(int bitLength) {

    (_p, _q) = AsymmetricUtils.GetRandomSafePrime(bitLength);
    while (true) {
      _g = AsymmetricUtils.GetRandom(1, _p);
      if (_g != 1 && BigIntegerExtensions.ModExp(_g, _q, _p) == 1) {
        break;
      }
    }
    _privateValue = AsymmetricUtils.GetRandom(1, _q-1);
    if (_p <= 1) {
      throw new ArgumentException();
    }
    if (bitLength < MinimumBitLength) {
      throw new ArgumentOutOfRangeException(nameof(bitLength), "bitLength is less than MinimumBitLength");
    }

    if (bitLength %2 == 1) {
      throw new ArgumentException( "bitLength must be even",nameof(bitLength));
    }


  }

  /// <summary>
  /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
  /// </summary>
  /// <param name="parameters">Parameters to use when generating the key pair.</param>
  public DiffieHellman(Parameters parameters) {
    _p = parameters.Modulus;
    _g = parameters.Generator;
    _q = parameters.Order;
    int bitLength = (int)_p.GetBitLength();

    if (BigIntegerExtensions.ModExp(_g, _q, _p) != 1) {
      throw new ArgumentException("Not in group");
    }
    _privateValue = AsymmetricUtils.GetRandom(1, _q-1);

    if (_p <= 1) {
      throw new ArgumentException("Modulus is too small");
    }
    if (_g <= 1 || _g > _p-1) {
      throw new ArgumentException("Generator is not in range");

    }
    if (bitLength < MinimumBitLength) {
      throw new ArgumentOutOfRangeException(nameof(bitLength), "bitLength is less than MinimumBitLength");
    }

    if (bitLength %2 == 1) {
      throw new ArgumentException( "bitLength must be even",nameof(bitLength));
    }


  }

  #endregion

  #region Operations

  /// <summary>
  /// Combines a received public value with the local private key to calculate a shared value.
  /// </summary>
  /// <param name="receivedPublicValue">The peer's public value.</param>
  /// <returns>The calculated shared value.</returns>
  /// <exception cref="ArgumentOutOfRangeException">
  /// <paramref name="receivedPublicValue"/> is not within the group.</exception>
  public BigInteger ComputeSharedValue(BigInteger receivedPublicValue) {
    if (receivedPublicValue <= 1 || receivedPublicValue >= _p) {
      throw new ArgumentOutOfRangeException();
    }
    if (BigIntegerExtensions.ModExp(receivedPublicValue, _q, _p) != 1) {
      throw new ArgumentOutOfRangeException("Received public value is not within the group.", nameof(receivedPublicValue));
    }
    if (receivedPublicValue < 1 || receivedPublicValue >= _p) {
      throw new ArgumentOutOfRangeException("Received public value is not within the group.", nameof(receivedPublicValue));
    }

    return BigIntegerExtensions.ModExp(receivedPublicValue, _privateValue, _p);
  }

  /// <summary>
  /// Combines a received public value with the local private key to derive a shared key using HKDF w/ SHA-512.
  /// </summary>
  /// <param name="receivedPublicValue">The peer's public value.</param>
  /// <param name="byteCount">The desired number of bytes in the shared key.</param>
  /// <returns>A shared key derived from calculating shared value.</returns>
  /// <exception cref="ArgumentOutOfRangeException">
  /// <paramref name="receivedPublicValue"/> is not within the group or byteCount is not positive.</exception>
  /// <remarks>
  /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
  /// as the hash algorithm.
  /// </remarks>
  public byte[] ComputeSharedKey(BigInteger receivedPublicValue, int byteCount) {
    if (byteCount < 1) {
      throw new ArgumentOutOfRangeException("Byte count too small");
    }
    if (receivedPublicValue <= 1 || receivedPublicValue >= _p) {
      throw new ArgumentOutOfRangeException("Public value out of range");
    }
    if (BigIntegerExtensions.ModExp(receivedPublicValue, _q, _p) != 1) {
      throw new ArgumentOutOfRangeException("Received public value is not within the group.", nameof(receivedPublicValue));
    }
    if (receivedPublicValue < 1 || receivedPublicValue >= _p) {
      throw new ArgumentOutOfRangeException("Received public value is not within the group.", nameof(receivedPublicValue));
    }
    BigInteger sharedValue = BigIntegerExtensions.ModExp(receivedPublicValue, _privateValue, _p);
    int modulusByteCount = (int)(_p.GetBitLength() + 7) / 8;
    return HKDF.DeriveKey(HashAlgorithmName.SHA512, AsymmetricUtils.ToByteArray(sharedValue, modulusByteCount), byteCount);


  }

  #endregion

}

/// <summary>
/// Implementation of unauthenticated Elliptic Curve Diffie-Hellman key agreement over a
/// prime-order subgroup of the multiplicative group of integers modulo a safe prime.
/// </summary>
public class ECDiffieHellman {

  #region Members

  /// <summary>The curve parameters.</summary>
  private readonly Parameters parameters;

  /// <summary>The public key.</summary>
  private readonly ECPoint publicKey;

  /// <summary>The private key.</summary>
  private readonly BigInteger privateKey;



  #endregion

  #region Key retrieval

  /// <summary>Returns the parameters held by this instance.</summary>
  public Parameters GetParameters() =>
  parameters;
  /// <summary>Returns the public key held by this instance.</summary>
  public ECPoint GetPublicValue() =>
  privateKey*parameters.Generator;

  #endregion

  #region Constructors

  /// <summary>
  /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
  /// </summary>
  /// <param name="parameters">Parameters to use when generating the key pair.</param>
  public ECDiffieHellman(Parameters parameters) {
    this.parameters = parameters;
    if (parameters.Generator == ECPoint.PointAtInfinity) {
      throw new ArgumentException("Generator is at infinity");
    }
    if (parameters.Curve.P.GetBitLength() < 5) { //5 is the smallest value that satisfies y^2 = x^3 + ax + b  (y = 2 and x = 3)
      throw new ArgumentException("Field Length is too small");
    }
    privateKey = AsymmetricUtils.GetRandom(1, parameters.Order - 1);

  }

  #endregion

  #region Operations

  /// <summary>
  /// Combines a received public point with the local private key to calculate a shared point.
  /// </summary>
  /// <param name="receivedPublicPoint">The peer's public point.</param>
  /// <returns>The calculated shared point.</returns>
  /// <exception cref="ArgumentOutOfRangeException">
  /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
  public ECPoint ComputeSharedPoint(ECPoint receivedPublicPoint) {
    BigInteger x = receivedPublicPoint.X;
    BigInteger y = receivedPublicPoint.Y;
    if (receivedPublicPoint == ECPoint.PointAtInfinity) {
      throw new ArgumentOutOfRangeException(nameof(receivedPublicPoint), "Point is at infinity.");
    }
    if (!parameters.Curve.AreCoordinatesOnCurve(x, y)) {
      throw new ArgumentOutOfRangeException("Points are not on curve");
    }
    if (parameters.Order * receivedPublicPoint != ECPoint.PointAtInfinity) {
      throw new ArgumentOutOfRangeException(nameof(receivedPublicPoint), "Point has the wrong order.");
    }
    return privateKey*receivedPublicPoint;
  }

  /// <summary>
  /// Combines a received public point with the local private key to derive a shared key using HKDF w/ SHA-512.
  /// </summary>
  /// <param name="receivedPublicPoint">The peer's public point.</param>
  /// <param name="byteCount">The desired number of bytes in the shared key.</param>
  /// <returns>The calculated shared value.</returns>
  /// <exception cref="ArgumentOutOfRangeException">
  /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
  /// <remarks>
  /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
  /// as the hash algorithm.
  /// </remarks>
  public byte[] ComputeSharedKey(ECPoint receivedPublicPoint, int byteCount) {
    if (byteCount < 1) {
      throw new ArgumentOutOfRangeException(nameof(byteCount), "byteCount must be positive.");
    }
    ECPoint sharedPoint = ComputeSharedPoint(receivedPublicPoint);
    int modulusByteCount = (int)(parameters.Curve.P.GetBitLength() + 7) / 8;
    return HKDF.DeriveKey(HashAlgorithmName.SHA512, AsymmetricUtils.ToByteArray(sharedPoint.X, modulusByteCount), byteCount);
  }

  #endregion
}
