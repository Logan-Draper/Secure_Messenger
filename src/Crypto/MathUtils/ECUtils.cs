using System.Drawing;
using System.Numerics;

namespace MathUtils;

/// <summary>
/// Represents an elliptic curve over a finite field.
/// </summary>
public readonly record struct ECCurve {

    #region Members

    /// <summary>Linear coefficient <c>A</c> of the curve equation.</summary>
    public BigInteger A { get; }

    /// <summary>Constant coefficient <c>B</c> of the curve equation.</summary>
    public BigInteger B { get; }

    /// <summary>Prime modulus of the curve.</summary>
    public BigInteger P { get; }

    #endregion

    #region Constructor

    /// <summary>
    /// Initializes a new instance of the <see cref="ECCurve"/> struct with the specified coefficients and prime modulus.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <exception cref="ArgumentException">Thrown when the given parameters do not produce a non-singular elliptic curve.</exception>
    public ECCurve(BigInteger a, BigInteger b, BigInteger p) {
      if (-16*(4*BigInteger.Pow(a, 3) + 27*b*b) == 0) {
        throw new ArgumentException("discriminant must be non-zero");
      }
      A = a;
      B = b;
      P = p;
    }

    #endregion

    #region Operation

    /// <summary>
    /// Deconstructs the elliptic curve into its constituent components.
    /// </summary>
    /// <param name="a">Outputs the linear coefficient <c>A</c>.</param>
    /// <param name="b">Outputs the constant coefficient <c>B</c>.</param>
    /// <param name="p">Outputs the prime modulus <c>P</c>.</param>
    /// <remarks>
    /// Your implementation needs to make sure the point is on the curve.
    /// </remarks>
    public void Deconstruct(out BigInteger a, out BigInteger b, out BigInteger p) {
      a = A;
      b = B;
      p = P;
    }

    /// <summary>
    /// Determines whether the specified coefficients and prime modulus form a valid (non-singular) elliptic curve.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <returns><see langword="true"/> if the discriminant is non-zero modulo <c>P</c>.</returns>
    public static bool IsValidCurve(BigInteger a, BigInteger b, BigInteger p) {
      if (-16*(4*BigInteger.Pow(a, 3) + 27*b*b) != 0) {
        return true;
      }
      return false;
    }

    /// <summary>
    /// Constructs a point on the curve y² ≡ x³ + Ax + B (mod P).
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>ECPoint for the given x and y.</returns>
    public ECPoint GetPoint(BigInteger x, BigInteger y) {
      x = BigIntegerExtensions.Mod(x, P);
      if (x < 0) {
        x+=P;
      }
      y = BigIntegerExtensions.Mod(y, P);
      if (y < 0) {
        y+=P;
      }
      if (!AreCoordinatesOnCurve(x, y)) {
        throw new ArgumentException("Invalid coordinates");
      }

      return new ECPoint(this, x, y);
    }

    /// <summary>
    /// Checks if the given coordinates are on the curve.
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>True if the coordinates are on the curve, false otherwise.</returns>
    public bool AreCoordinatesOnCurve(BigInteger x, BigInteger y) {

      x = BigIntegerExtensions.Mod(x, P);
      if (x < 0) {
        x+=P;
      }
      y = BigIntegerExtensions.Mod(y, P);
      if (y < 0) {
        y+=P;
      }
      BigInteger YSquared= BigIntegerExtensions.ModExp(y, 2, P);
      BigInteger RightSideEQ = BigIntegerExtensions.Mod(BigIntegerExtensions.ModExp(x, 3, P) + BigIntegerExtensions.Mod(A*x, P) + B, P);
      return YSquared == RightSideEQ;

    }

    #endregion
}

/// <summary>
/// Represents a point on an elliptic curve, or the identity element (point at infinity).
/// </summary>
public readonly record struct ECPoint {

  #region Members

  /// <summary>Gets the elliptic curve to which this point belongs.</summary>
  private ECCurve E { get; }

  /// <summary>Gets the x-coordinate of the point.</summary>
  public BigInteger X { get; }

  /// <summary>Gets the y-coordinate of the point.</summary>
  public BigInteger Y { get; }

  #endregion

  #region Point at infinity

  /// <summary>Gets the identity element (point at infinity) for elliptic curve arithmetic.</summary>
  public static ECPoint PointAtInfinity { get; } = default;

  #endregion

  #region Constructor

  /// <summary>
  /// Constructs a finite point on the given curve.
  /// </summary>
  /// <param name="e">Curve the point belongs to.</param>
  /// <param name="x">X coordinate of the point (must be non-negative).</param>
  /// <param name="y">Y coordinate of the point (must be non-negative).</param>
  internal ECPoint(ECCurve e, BigInteger x, BigInteger y) {
    E=e;
    X=x;
    Y=y;
  }

  #endregion

  #region Operation

  /// <summary>
  /// Deconstructs the point into its associated curve and coordinates.
  /// </summary>
  /// <param name="e">Outputs the curve.</param>
  /// <param name="x">Outputs the x-coordinate.</param>
  /// <param name="y">Outputs the y-coordinate.</param>
  public void Deconstruct(out ECCurve e, out BigInteger x, out BigInteger y) {
    e = E;
    x = X;
    y = Y;
  }

  #endregion

  #region Operator overloads

  /// <summary>
  /// Negates the specified point, producing its additive inverse on the curve.
  /// </summary>
  /// <param name="value">The point to negate.</param>
  /// <returns>The negated point.</returns>
  public static ECPoint operator -(ECPoint value) {
    BigInteger negativey = value.E.P - value.Y;
    return new ECPoint(value.E, value.X, negativey);
  }

  /// <summary>
  /// Adds two points on an elliptic curve.
  /// </summary>
  /// <param name="lhs">The first point.</param>
  /// <param name="rhs">The second point.</param>
  /// <returns>The resulting point of the addition.</returns>
  /// <exception cref="ArgumentException">Thrown when attempting to add points from different elliptic curves.</exception>
  public static ECPoint operator +(ECPoint lhs, ECPoint rhs) {
    BigInteger Delta;
    BigInteger rx;
    BigInteger ry;      
    if (lhs == PointAtInfinity) return rhs;
    if (rhs == PointAtInfinity) return lhs;
    if (lhs.E != rhs.E) throw new ArgumentException("Points are not on the same curve");
    if(lhs.X == rhs.X && BigIntegerExtensions.Mod(lhs.Y + rhs.Y, lhs.E.P) == 0) {
      return PointAtInfinity;
    }

    if (lhs.X == rhs.X && lhs.Y == rhs.Y) {
      Delta = BigIntegerExtensions.ModDivide(3*lhs.X*lhs.X + lhs.E.A, 2*lhs.Y, lhs.E.P);
    }
    else {
      Delta = BigIntegerExtensions.ModDivide(rhs.Y - lhs.Y,rhs.X - lhs.X, lhs.E.P);
      // Delta = BigIntegerExtensions.Mod((rhs.Y - lhs.Y)/(rhs.X - lhs.X), lhs.E.P);
    }
    rx = BigIntegerExtensions.Mod(Delta*Delta - lhs.X - rhs.X, lhs.E.P);
    ry = BigIntegerExtensions.Mod(Delta*(lhs.X - rx) - lhs.Y, lhs.E.P);
    return new ECPoint(lhs.E, rx, ry);
  }

  /// <summary>
  /// Multiplies an elliptic curve point by a scalar using double-and-add scalar multiplication.
  /// </summary>
  /// <param name="k">The scalar multiplier.</param>
  /// <param name="point">The point to multiply.</param>
  /// <returns>The point <c>k * point</c>.</returns>
  /// <remarks>
  /// You must implement this function efficiently.
  /// At most, you may use <see cref="operator +" /> Ceiling(log2(base)) + #bits_set(k)) times.
  /// You are only allowed a single <see cref="ECPoint"/>  for local variables.
  /// </remarks>
  public static ECPoint operator *(BigInteger k, ECPoint point) {
    if (k == 0) return PointAtInfinity; 
    if (k == -1) {
      return new ECPoint(point.E, point.X, point.E.P-point.Y);
    }
    ECPoint multiplier = PointAtInfinity;
    int i;
    ECPoint[] multipliersOfA = new ECPoint[(int)BigInteger.Log(k,2) + 1];
    multipliersOfA[0] = point;
    for (i = 1; i < (BigInteger)BigInteger.Log(k,2) + 1; i+=1) {
      multipliersOfA[i] = multipliersOfA[i - 1] + multipliersOfA[i -1];
    }
    for (i = 0; i < (BigInteger)BigInteger.Log(k,2) + 1; i+=1) {
      if (((k >> i) & 1) ==1) {
        multiplier = multiplier + multipliersOfA[i];
      }
    }
    return multiplier;
  }

  #endregion
}
