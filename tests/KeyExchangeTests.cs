using System;
using System.Linq;
using System.Numerics;
using AsymmetricCryptography;
using MathUtils;
using Xunit;

using DhParameters = AsymmetricCryptography.DiffieHellman.Parameters;
using EcParameters = AsymmetricCryptography.ECParameters.Parameters;
using ECCurve = MathUtils.ECCurve;
using ECPoint = MathUtils.ECPoint;

namespace SimpleMessenger.Tests;

public class KeyExchangeTests
{
    /// <summary>
    /// Smallest legal modulus size. Keeps safe-prime generation fast enough for a unit test
    /// while still exercising every code path.
    /// </summary>
    private const int TestBitLength = DiffieHellman.MinimumBitLength;

    /// <summary>Creates two parties that share a single set of group parameters.</summary>
    private static (DiffieHellman Alice, DiffieHellman Bob) CreatePair(int bitLength = TestBitLength)
    {
        var alice = new DiffieHellman(bitLength);
        var bob = new DiffieHellman(alice.GetParameters());
        return (alice, bob);
    }

    #region Key agreement

    [Fact]
    public void BothParties_DeriveSameSharedSecret()
    {
        var (alice, bob) = CreatePair();

        BigInteger aliceSecret = alice.ComputeSharedValue(bob.GetPublicValue());
        BigInteger bobSecret = bob.ComputeSharedValue(alice.GetPublicValue());

        Assert.Equal(aliceSecret, bobSecret);
        Assert.True(aliceSecret > 1, "Shared value collapsed to the identity element.");
    }

    [Fact]
    public void BothParties_DeriveSameSharedKey()
    {
        var (alice, bob) = CreatePair();

        byte[] aliceKey = alice.ComputeSharedKey(bob.GetPublicValue(), 32);
        byte[] bobKey = bob.ComputeSharedKey(alice.GetPublicValue(), 32);

        Assert.Equal(32, aliceKey.Length);
        Assert.Equal(aliceKey, bobKey);
    }

    [Fact]
    public void ComputeSharedValue_IsDeterministic()
    {
        var (alice, bob) = CreatePair();
        BigInteger bobPublic = bob.GetPublicValue();

        Assert.Equal(alice.ComputeSharedValue(bobPublic), alice.ComputeSharedValue(bobPublic));
    }

    [Fact]
    public void ComputeSharedValue_IsInTheGroup()
    {
        var (alice, bob) = CreatePair();
        DhParameters p = alice.GetParameters();

        BigInteger shared = alice.ComputeSharedValue(bob.GetPublicValue());

        Assert.InRange(shared, 1, p.Modulus - 1);
        Assert.Equal(BigInteger.One, BigIntegerExtensions.ModExp(shared, p.Order, p.Modulus));
    }

    [Fact]
    public void SharedValue_DiffersForDifferentPeers()
    {
        var alice = new DiffieHellman(TestBitLength);
        DhParameters parameters = alice.GetParameters();
        var bob = new DiffieHellman(parameters);
        var mallory = new DiffieHellman(parameters);

        // Guard against the (astronomically unlikely) case of two parties drawing the same private value.
        Assert.NotEqual(bob.GetPublicValue(), mallory.GetPublicValue());

        Assert.NotEqual(
            alice.ComputeSharedValue(bob.GetPublicValue()),
                        alice.ComputeSharedValue(mallory.GetPublicValue()));
    }

    #endregion

    #region Key generation

    [Fact]
    public void GenerateKeyPair_ProducesDifferentKeysEachTime()
    {
        const int iterations = 25;

        var alice = new DiffieHellman(TestBitLength);
        DhParameters parameters = alice.GetParameters();

        var publicValues = new System.Collections.Generic.HashSet<BigInteger>();

        for (int i = 0; i < iterations; i++)
        {
            BigInteger publicValue = new DiffieHellman(parameters).GetPublicValue();
            Assert.True(publicValues.Add(publicValue),
                        "Two instances produced the same public value, so the private value is not random.");
        }
    }

    [Fact]
    public void GetPublicValue_IsStableAcrossCalls()
    {
        var alice = new DiffieHellman(TestBitLength);

        Assert.Equal(alice.GetPublicValue(), alice.GetPublicValue());
    }

    [Fact]
    public void GetPublicValue_IsInTheGroup()
    {
        var alice = new DiffieHellman(TestBitLength);
        DhParameters p = alice.GetParameters();

        BigInteger publicValue = alice.GetPublicValue();

        Assert.InRange(publicValue, 2, p.Modulus - 1);
        Assert.Equal(BigInteger.One, BigIntegerExtensions.ModExp(publicValue, p.Order, p.Modulus));
    }

    [Fact]
    public void GeneratedParameters_AreWellFormed()
    {
        var alice = new DiffieHellman(TestBitLength);
        DhParameters p = alice.GetParameters();

        Assert.True(p.Modulus > 1, "Modulus must exceed 1.");
        Assert.True(p.Order > 1, "Order must exceed 1.");
        Assert.InRange(p.Generator, 2, p.Modulus - 1);

        // The order of g must divide the order of the full multiplicative group.
        Assert.Equal(BigInteger.Zero, (p.Modulus - 1) % p.Order);

        // g must actually generate the claimed subgroup.
        Assert.Equal(BigInteger.One, BigIntegerExtensions.ModExp(p.Generator, p.Order, p.Modulus));
    }

    [Fact]
    public void Constructor_WithSharedParameters_ReusesThemExactly()
    {
        var alice = new DiffieHellman(TestBitLength);
        var bob = new DiffieHellman(alice.GetParameters());

        Assert.Equal(alice.GetParameters(), bob.GetParameters());
    }

    #endregion

    #region Parameter validation

    [Theory]
    [InlineData(2)]
    [InlineData(16)]
    [InlineData(DiffieHellman.MinimumBitLength - 2)]
    public void Constructor_WithBitLengthBelowMinimum_Throws(int bitLength)
    {
        Assert.ThrowsAny<ArgumentException>(() => new DiffieHellman(bitLength));
    }

    [Fact]
    public void Constructor_WithOddBitLength_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() => new DiffieHellman(TestBitLength + 1));
    }

    [Fact]
    public void Constructor_WithGeneratorOutsideGroup_Throws()
    {
        DhParameters valid = new DiffieHellman(TestBitLength).GetParameters();

        // p - 1 has order 2, not q, so it is not a member of the prime-order subgroup.
        var bad = new DhParameters(valid.Modulus, valid.Modulus - 1, valid.Order);

        Assert.Throws<ArgumentException>(() => new DiffieHellman(bad));
    }

    [Fact]
    public void Constructor_WithGeneratorOfOne_Throws()
    {
        DhParameters valid = new DiffieHellman(TestBitLength).GetParameters();

        // 1^q == 1 passes the subgroup check, but 1 generates nothing.
        var bad = new DhParameters(valid.Modulus, BigInteger.One, valid.Order);

        Assert.Throws<ArgumentException>(() => new DiffieHellman(bad));
    }

    #endregion

    #region Public value validation

    [Fact]
    public void ComputeSharedValue_WithValueOfZeroOrOne_Throws()
    {
        var alice = new DiffieHellman(TestBitLength);

        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedValue(BigInteger.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedValue(BigInteger.One));
    }

    [Fact]
    public void ComputeSharedValue_WithValueAtOrAboveModulus_Throws()
    {
        var alice = new DiffieHellman(TestBitLength);
        BigInteger p = alice.GetParameters().Modulus;

        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedValue(p));
        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedValue(p + 1));
    }

    [Fact]
    public void ComputeSharedValue_WithInRangeNonMember_Throws()
    {
        var alice = new DiffieHellman(TestBitLength);
        BigInteger p = alice.GetParameters().Modulus;

        // p - 1 is in range but sits in the order-2 subgroup, so it must be rejected.
        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedValue(p - 1));
    }

    [Fact]
    public void ComputeSharedKey_RejectsTheSameValuesAsComputeSharedValue()
    {
        var alice = new DiffieHellman(TestBitLength);
        BigInteger p = alice.GetParameters().Modulus;

        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedKey(BigInteger.One, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedKey(p, 32));
        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedKey(p - 1, 32));
    }

    #endregion

    #region Key derivation

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(100)]
    public void ComputeSharedKey_ReturnsRequestedLength(int byteCount)
    {
        var (alice, bob) = CreatePair();

        byte[] key = alice.ComputeSharedKey(bob.GetPublicValue(), byteCount);

        Assert.Equal(byteCount, key.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void ComputeSharedKey_WithNonPositiveByteCount_Throws(int byteCount)
    {
        var (alice, bob) = CreatePair();
        BigInteger bobPublic = bob.GetPublicValue();

        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedKey(bobPublic, byteCount));
    }

    [Fact]
    public void ComputeSharedKey_IsDeterministic()
    {
        var (alice, bob) = CreatePair();
        BigInteger bobPublic = bob.GetPublicValue();

        Assert.Equal(
            alice.ComputeSharedKey(bobPublic, 32),
                     alice.ComputeSharedKey(bobPublic, 32));
    }

    [Fact]
    public void ComputeSharedKey_ShorterOutputIsAPrefixOfLongerOutput()
    {
        // HKDF-Expand is a prefix function when salt and info are unchanged; this pins the
        // derivation to HKDF rather than some ad-hoc truncation or re-hash.
        var (alice, bob) = CreatePair();
        BigInteger bobPublic = bob.GetPublicValue();

        byte[] shortKey = alice.ComputeSharedKey(bobPublic, 32);
        byte[] longKey = alice.ComputeSharedKey(bobPublic, 96);

        Assert.Equal(shortKey, longKey.Take(32).ToArray());
    }

    [Fact]
    public void ComputeSharedKey_IsNotAllZeros()
    {
        var (alice, bob) = CreatePair();

        byte[] key = alice.ComputeSharedKey(bob.GetPublicValue(), 32);

        Assert.Contains(key, b => b != 0);
    }

    [Fact]
    public void ComputeSharedKey_DiffersForDifferentPeers()
    {
        var alice = new DiffieHellman(TestBitLength);
        DhParameters parameters = alice.GetParameters();
        var bob = new DiffieHellman(parameters);
        var mallory = new DiffieHellman(parameters);

        Assert.NotEqual(bob.GetPublicValue(), mallory.GetPublicValue());

        Assert.NotEqual(
            alice.ComputeSharedKey(bob.GetPublicValue(), 32),
                        alice.ComputeSharedKey(mallory.GetPublicValue(), 32));
    }

    [Fact]
    public void ComputeSharedKey_IsIndependentOfInstanceOrdering()
    {
        // Full round trip at a realistic size: both sides must agree on a 64-byte key.
        var (alice, bob) = CreatePair();

        Assert.Equal(
            alice.ComputeSharedKey(bob.GetPublicValue(), 64),
                     bob.ComputeSharedKey(alice.GetPublicValue(), 64));
    }

    #endregion
}

/// <summary>
/// Tests for <see cref="ECDiffieHellman"/> over the NIST prime curves.
/// </summary>
public class ECKeyExchangeTests
{
    /// <summary>Default curve for tests that do not care which curve they run on.</summary>
    private static EcParameters P256 => ECParameters.NISTP256;

    /// <summary>All three curves, for tests that must cover field-size handling.</summary>
    public static TheoryData<string> AllCurves => new() { "P256", "P384", "P521" };

    private static EcParameters CurveByName(string name) => name switch
    {
        "P256" => ECParameters.NISTP256,
        "P384" => ECParameters.NISTP384,
        "P521" => ECParameters.NISTP521,
        _ => throw new ArgumentOutOfRangeException(nameof(name))
    };

    /// <summary>Creates two parties on the same curve.</summary>
    private static (ECDiffieHellman Alice, ECDiffieHellman Bob) CreatePair(EcParameters? parameters = null)
    {
        EcParameters p = parameters ?? P256;
        return (new ECDiffieHellman(p), new ECDiffieHellman(p));
    }

    #region Key agreement

    [Theory]
    [MemberData(nameof(AllCurves))]
    public void BothParties_DeriveSameSharedPoint(string curveName)
    {
        var (alice, bob) = CreatePair(CurveByName(curveName));

        ECPoint aliceShared = alice.ComputeSharedPoint(bob.GetPublicValue());
        ECPoint bobShared = bob.ComputeSharedPoint(alice.GetPublicValue());

        Assert.Equal(aliceShared, bobShared);
        Assert.NotEqual(ECPoint.PointAtInfinity, aliceShared);
    }

    [Theory]
    [MemberData(nameof(AllCurves))]
    public void BothParties_DeriveSameSharedKey(string curveName)
    {
        // P-521 is the interesting case: a 66-byte coordinate whose top byte holds one
        // significant bit. If ToByteArray pads or truncates to a word boundary, this fails.
        var (alice, bob) = CreatePair(CurveByName(curveName));

        byte[] aliceKey = alice.ComputeSharedKey(bob.GetPublicValue(), 32);
        byte[] bobKey = bob.ComputeSharedKey(alice.GetPublicValue(), 32);

        Assert.Equal(32, aliceKey.Length);
        Assert.Equal(aliceKey, bobKey);
    }

    [Fact]
    public void SharedPoint_IsOnTheCurve()
    {
        var (alice, bob) = CreatePair();

        ECPoint shared = alice.ComputeSharedPoint(bob.GetPublicValue());

        Assert.True(P256.Curve.AreCoordinatesOnCurve(shared.X, shared.Y),
                    "Shared point is not on the curve.");
    }

    [Fact]
    public void SharedPoint_HasTheOrderOfTheGroup()
    {
        var (alice, bob) = CreatePair();

        ECPoint shared = alice.ComputeSharedPoint(bob.GetPublicValue());

        Assert.Equal(ECPoint.PointAtInfinity, P256.Order * shared);
    }

    [Fact]
    public void ComputeSharedPoint_IsDeterministic()
    {
        var (alice, bob) = CreatePair();
        ECPoint bobPublic = bob.GetPublicValue();

        Assert.Equal(alice.ComputeSharedPoint(bobPublic), alice.ComputeSharedPoint(bobPublic));
    }

    [Fact]
    public void SharedPoint_DiffersForDifferentPeers()
    {
        var alice = new ECDiffieHellman(P256);
        var bob = new ECDiffieHellman(P256);
        var mallory = new ECDiffieHellman(P256);

        Assert.NotEqual(bob.GetPublicValue(), mallory.GetPublicValue());

        Assert.NotEqual(
            alice.ComputeSharedPoint(bob.GetPublicValue()),
                        alice.ComputeSharedPoint(mallory.GetPublicValue()));
    }

    #endregion

    #region Key generation

    [Fact]
    public void GenerateKeyPair_ProducesDifferentKeysEachTime()
    {
        const int iterations = 25;

        var publicKeys = new System.Collections.Generic.HashSet<ECPoint>();

        for (int i = 0; i < iterations; i++)
        {
            ECPoint publicKey = new ECDiffieHellman(P256).GetPublicValue();
            Assert.True(publicKeys.Add(publicKey),
                        "Two instances produced the same public point, so the private key is not random.");
        }
    }

    [Fact]
    public void GetPublicValue_IsStableAcrossCalls()
    {
        var alice = new ECDiffieHellman(P256);

        Assert.Equal(alice.GetPublicValue(), alice.GetPublicValue());
    }

    [Theory]
    [MemberData(nameof(AllCurves))]
    public void GetPublicValue_IsAValidGroupElement(string curveName)
    {
        EcParameters p = CurveByName(curveName);
        ECPoint publicKey = new ECDiffieHellman(p).GetPublicValue();

        Assert.NotEqual(ECPoint.PointAtInfinity, publicKey);
        Assert.True(p.Curve.AreCoordinatesOnCurve(publicKey.X, publicKey.Y),
                    "Public point is not on the curve.");
        Assert.Equal(ECPoint.PointAtInfinity, p.Order * publicKey);
    }

    [Fact]
    public void GetParameters_ReturnsTheSuppliedParameters()
    {
        var alice = new ECDiffieHellman(P256);

        Assert.Equal(P256, alice.GetParameters());
    }

    [Theory]
    [MemberData(nameof(AllCurves))]
    public void NamedCurveGenerator_HasTheDocumentedOrder(string curveName)
    {
        // Guards the hex constants in ECParameters: a mistyped nibble in G or the order
        // would almost certainly break n * G == O.
        EcParameters p = CurveByName(curveName);

        Assert.True(p.Curve.AreCoordinatesOnCurve(p.Generator.X, p.Generator.Y),
                    "Generator is not on the curve.");
        Assert.Equal(ECPoint.PointAtInfinity, p.Order * p.Generator);
    }

    [Theory]
    [MemberData(nameof(AllCurves))]
    public void NamedCurveConstants_ParseAsPositiveValues(string curveName)
    {
        // NumberStyles.HexNumber parses two's complement, and every p, a, and order here
        // begins with 0xF. The "00" prefix in ECParameters.Parse is what keeps them positive.
        EcParameters p = CurveByName(curveName);

        Assert.True(p.Curve.P > 0, "Field prime parsed as negative.");
        Assert.True(p.Order > 0, "Group order parsed as negative.");
        Assert.True(p.Generator.X > 0 && p.Generator.Y > 0, "Generator coordinates parsed as negative.");
    }

    [Fact]
    public void NISTP521_HasA521BitField()
    {
        // 521 bits -> 66 bytes, not 64. Pinned because ComputeSharedKey derives its
        // coordinate buffer size from this value.
        Assert.Equal(521, ECParameters.NISTP521.Curve.P.GetBitLength());
        Assert.Equal(66, (int)(ECParameters.NISTP521.Curve.P.GetBitLength() + 7) / 8);
    }

    #endregion

    #region Parameter validation

    [Fact]
    public void Constructor_WithGeneratorAtInfinity_Throws()
    {
        var bad = new EcParameters(P256.Curve, ECPoint.PointAtInfinity, P256.Order);

        Assert.Throws<ArgumentException>(() => new ECDiffieHellman(bad));
    }

    #endregion

    #region Public point validation

    [Fact]
    public void ComputeSharedPoint_WithPointAtInfinity_Throws()
    {
        var alice = new ECDiffieHellman(P256);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => alice.ComputeSharedPoint(ECPoint.PointAtInfinity));
    }

    [Fact]
    public void ComputeSharedKey_WithPointAtInfinity_Throws()
    {
        var alice = new ECDiffieHellman(P256);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => alice.ComputeSharedKey(ECPoint.PointAtInfinity, 32));
    }

    [Fact]
    public void ComputeSharedPoint_WithPointFromAnotherCurve_Throws()
    {
        // An invalid-curve attack in miniature: a well-formed P-384 point is not a valid
        // P-256 input and must be rejected rather than multiplied.
        var alice = new ECDiffieHellman(ECParameters.NISTP256);
        ECPoint foreignPoint = new ECDiffieHellman(ECParameters.NISTP384).GetPublicValue();

        Assert.ThrowsAny<ArgumentException>(() => alice.ComputeSharedPoint(foreignPoint));
    }

    [Fact]
    public void ComputeSharedPoint_WithOffCurvePoint_Throws()
    {
        var alice = new ECDiffieHellman(P256);
        ECPoint valid = new ECDiffieHellman(P256).GetPublicValue();

        // Flipping one coordinate takes the point off the curve. Whichever layer catches it --
        // GetPoint on construction, or AreCoordinatesOnCurve inside ComputeSharedPoint -- the
        // caller must see an argument exception rather than a derived key.
        BigInteger offCurveY = (valid.Y + 1) % P256.Curve.P;
        Assert.False(P256.Curve.AreCoordinatesOnCurve(valid.X, offCurveY),
                     "Test setup failed: the perturbed coordinates are still on the curve.");

        Assert.ThrowsAny<ArgumentException>(() =>
        alice.ComputeSharedPoint(P256.Curve.GetPoint(valid.X, offCurveY)));
    }

    #endregion

    #region Key derivation

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(100)]
    public void ComputeSharedKey_ReturnsRequestedLength(int byteCount)
    {
        var (alice, bob) = CreatePair();

        byte[] key = alice.ComputeSharedKey(bob.GetPublicValue(), byteCount);

        Assert.Equal(byteCount, key.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void ComputeSharedKey_WithNonPositiveByteCount_Throws(int byteCount)
    {
        var (alice, bob) = CreatePair();
        ECPoint bobPublic = bob.GetPublicValue();

        Assert.Throws<ArgumentOutOfRangeException>(() => alice.ComputeSharedKey(bobPublic, byteCount));
    }

    [Fact]
    public void ComputeSharedKey_ValidatesByteCountBeforeThePoint()
    {
        // byteCount is checked first, so an invalid point plus an invalid count must still
        // surface the count failure -- and must never reach the scalar multiplication.
        var alice = new ECDiffieHellman(P256);

        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => alice.ComputeSharedKey(ECPoint.PointAtInfinity, 0));

        Assert.Equal("byteCount", ex.ParamName);
    }

    [Fact]
    public void ComputeSharedKey_IsDeterministic()
    {
        var (alice, bob) = CreatePair();
        ECPoint bobPublic = bob.GetPublicValue();

        Assert.Equal(
            alice.ComputeSharedKey(bobPublic, 32),
                     alice.ComputeSharedKey(bobPublic, 32));
    }

    [Fact]
    public void ComputeSharedKey_ShorterOutputIsAPrefixOfLongerOutput()
    {
        var (alice, bob) = CreatePair();
        ECPoint bobPublic = bob.GetPublicValue();

        byte[] shortKey = alice.ComputeSharedKey(bobPublic, 32);
        byte[] longKey = alice.ComputeSharedKey(bobPublic, 96);

        Assert.Equal(shortKey, longKey.Take(32).ToArray());
    }

    [Fact]
    public void ComputeSharedKey_IsNotAllZeros()
    {
        var (alice, bob) = CreatePair();

        byte[] key = alice.ComputeSharedKey(bob.GetPublicValue(), 32);

        Assert.Contains(key, b => b != 0);
    }

    [Fact]
    public void ComputeSharedKey_DiffersForDifferentPeers()
    {
        var alice = new ECDiffieHellman(P256);
        var bob = new ECDiffieHellman(P256);
        var mallory = new ECDiffieHellman(P256);

        Assert.NotEqual(bob.GetPublicValue(), mallory.GetPublicValue());

        Assert.NotEqual(
            alice.ComputeSharedKey(bob.GetPublicValue(), 32),
                        alice.ComputeSharedKey(mallory.GetPublicValue(), 32));
    }

    [Fact]
    public void ComputeSharedKey_DiffersAcrossCurvesForTheSameParties()
    {
        // The derivation feeds only the shared x-coordinate into HKDF, so independent runs
        // on different curves must not collide.
        byte[] p256Key;
        byte[] p384Key;

        {
            var (alice, bob) = CreatePair(ECParameters.NISTP256);
            p256Key = alice.ComputeSharedKey(bob.GetPublicValue(), 32);
        }
        {
            var (alice, bob) = CreatePair(ECParameters.NISTP384);
            p384Key = alice.ComputeSharedKey(bob.GetPublicValue(), 32);
        }

        Assert.NotEqual(p256Key, p384Key);
    }

    #endregion
}
