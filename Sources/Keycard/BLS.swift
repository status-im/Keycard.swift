import BigInt
import CryptoSwift
import Foundation

public struct BLS {
  public static func hash(_ msg: [UInt8]) -> [UInt8] {
    let u = BLS.hashToField(msg, 2);
    let q0 = BLS.isogenyMapG2(BLS.mapToCurveSimpleSWU9mod16(Fp2(u[0][0], u[0][1])))
    let q1 = BLS.isogenyMapG2(BLS.mapToCurveSimpleSWU9mod16(Fp2(u[1][0], u[1][1])))
    let r = q0.add(q1).clearCofactor()
    return r.serialize(compressed: false)
  }

  public static func compress(_ g2: [UInt8]) -> [UInt8] {
    return PointG2(g2).serialize(compressed: true)
  }

  static let DST: [UInt8] = [
    0x42,  0x4C,  0x53,  0x5F,  0x53,  0x49,  0x47,  0x5F,
    0x42,  0x4C,  0x53,  0x31,  0x32,  0x33,  0x38,  0x31,
    0x47,  0x32,  0x5F,  0x58,  0x4D,  0x44,  0x3A,  0x53,
    0x48,  0x41,  0x2D,  0x32,  0x35,  0x36,  0x5F,  0x53,
    0x53,  0x57,  0x55,  0x5F,  0x52,  0x4F,  0x5F,  0x4E,
    0x55,  0x4C,  0x5F,  0x2B,
  ]

  static let L = 64
  static let M = 2
  static let SHA256_DIGEST_SIZE = 32

  static let P_MINUS_9_DIV_16 = (Fp.P.power(2) - 9) / 16

  static let rv1 = Fp("6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
  static let ev1 = Fp("699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90")
  static let ev2 = Fp("8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5")
  static let ev3 = Fp("ab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17")
  static let ev4 = Fp("aa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1")

  static let FP2_ROOTS_OF_UNITY = [
    Fp2.ONE,
    Fp2(BLS.rv1, BLS.rv1.neg()),
    Fp2(Fp.ZERO, Fp.ONE),
    Fp2(BLS.rv1, BLS.rv1)
  ]

  static let FP2_ETAs = [
    Fp2(BLS.ev1, BLS.ev2),
    Fp2(BLS.ev2.neg(), BLS.ev1),
    Fp2(BLS.ev3, BLS.ev4),
    Fp2(BLS.ev4.neg(), BLS.ev3)
  ]

  static let xnum = [
    Fp2(Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"),
        Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6")),
    Fp2(Fp.ZERO,
        Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a")),
    Fp2(Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e"),
        Fp("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d")),
    Fp2(Fp("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1"),
        Fp.ZERO),    
  ]

  static let xden = [
    Fp2(Fp.ZERO,
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63")),
    Fp2(Fp(0xc),
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f")),
    Fp2.ONE,
    Fp2.ZERO,    
  ]

  static let ynum = [
    Fp2(Fp("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"),
        Fp("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706")),
    Fp2(Fp.ZERO,
        Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be")),
    Fp2(Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c"),
        Fp("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f")),
    Fp2(Fp("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10"),
        Fp.ZERO),    
  ]

  static let yden = [
    Fp2(Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"),
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb")),
    Fp2(Fp.ZERO,
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3")),
    Fp2(Fp(0x12),
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99")),
    Fp2(Fp.ONE, Fp.ZERO),    
  ]

  static let ISOGENY_COEFFICIENTS = [xnum, xden, ynum, yden];    

  static func strxor(_ b0: [UInt8], _ b1: [UInt8], _ b1off: Int) -> [UInt8] {
    var xored: [UInt8] = [UInt8](repeating: 0, count: b0.count)
    for i in 0..<xored.count {
      xored[i] = (b0[i] ^ b1[i + b1off])
    }

    return xored
  }

  static func expandMessage(_ msg: [UInt8], _ DST: [UInt8], _ len: Int) -> [UInt8] {
    let ell: Int = (len + (BLS.SHA256_DIGEST_SIZE - 1)) / BLS.SHA256_DIGEST_SIZE
    var md = SHA2(variant: .sha256)
    _ = try! md.update(withBytes: [UInt8](repeating: 0, count: BLS.SHA256_DIGEST_SIZE*2), isLast: false)
    _ = try! md.update(withBytes: msg, isLast: false)
    _ = try! md.update(withBytes: [UInt8((len >> 8) & 0xff), UInt8(len & 0xff), UInt8(0)], isLast: false)
    let b0 = try! md.update(withBytes: DST, isLast: true)
    var b: [UInt8] = []

    for i in 0..<ell {
      md = SHA2(variant: .sha256)
      
      if (i == 0) {
        _ = try! md.update(withBytes: b0, isLast: false);
      } else {
        _ = try! md.update(withBytes: strxor(b0, b, ((i - 1) * SHA256_DIGEST_SIZE)), isLast: false)
      }

      _ = try! md.update(withBytes:[UInt8(i + 1)], isLast: false);
      b += try! md.update(withBytes: DST, isLast: true);
    }

    return Array(b[0..<len])
  }

  static func hashToField(_ msg: [UInt8], _ count: Int) -> [[Fp]] {
    let uniformBytes = BLS.expandMessage(msg, BLS.DST, count * BLS.M * BLS.L)
    var u: [[Fp]] = Array(repeating: Array(repeating: Fp(0), count: M), count: count)
    for i in 0..<count {
      for j in 0..<BLS.M {
        let off = (BLS.L * (j + (i * BLS.M)));
        u[i][j] = Fp(Data(uniformBytes[off..<(off + BLS.L)]))
      }
    }

    return u
  }

  static func isogenyMapG2(_ point: PointG2) -> PointG2 {
    let zPowers = [point.z, point.z.square(), point.z.pow(3)]
    var mapped = [Fp2.ZERO, Fp2.ZERO, Fp2.ZERO, Fp2.ZERO]

    for i in 0..<BLS.ISOGENY_COEFFICIENTS.count {
      let kI = BLS.ISOGENY_COEFFICIENTS[i];
      mapped[i] = kI[3];
      let arr = [kI[2], kI[1], kI[0]];
      
      for j in 0..<arr.count {
        let kIJ = arr[j];
        mapped[i] = mapped[i].mul(point.x).add(zPowers[j].mul(kIJ));
      }
    }

    mapped[2] = mapped[2].mul(point.y)
    mapped[3] = mapped[3].mul(point.z)
  
    let z2 = mapped[1].mul(mapped[3]);
    let x2 = mapped[0].mul(mapped[3]);
    let y2 = mapped[1].mul(mapped[2]);

    return PointG2(x2, y2, z2)
  }  

  static func sqrtDivFp2(_ u: Fp2, _ v: Fp2) -> (Bool, Fp2) {
    let v7 = v.pow(7)
    let uv7 = u.mul(v7)
    let uv15 = uv7.mul(v7.mul(v))
    let gamma = uv15.pow(BLS.P_MINUS_9_DIV_16).mul(uv7)

    for fp2root in BLS.FP2_ROOTS_OF_UNITY {
      let candidate = fp2root.mul(gamma)
      if (candidate.square().mul(v).sub(u).isZero()) {
        return (true, candidate)
      }
    }

    return (false, gamma);
  }  

  static func mapToCurveSimpleSWU9mod16(_ t: Fp2) -> PointG2 {
    let iso3a = Fp2(Fp(0), Fp(240))
    let iso3b = Fp2(Fp(1012), Fp(1012))
    let iso3z = Fp2(Fp(-2), Fp(-1))
    let t2 = t.square()
    let iso3zt2 = iso3z.mul(t2)
    let ztzt = iso3zt2.add(iso3zt2.square())
    var denominator = iso3a.mul(ztzt).neg()
    var numerator = iso3b.mul(ztzt.add(Fp2.ONE))

    if (denominator.isZero()) {
      denominator = iso3z.mul(iso3a);
    }

    let v = denominator.pow(3)
    var u = numerator.pow(3)
      .add(iso3a.mul(numerator).mul(denominator.square()))
      .add(iso3b.mul(v))
    
    let (sqrtSuccess, sqrtValue) = sqrtDivFp2(u, v);

    var y: Fp2? = nil

    if (!sqrtSuccess) {
      u = iso3zt2.pow(3).mul(u)
      let sqrtCandidateX1 = sqrtValue.mul(t.pow(3))

      for fp2eta in BLS.FP2_ETAs {
        let etaSqrtCanditate = fp2eta.mul(sqrtCandidateX1)
        if (etaSqrtCanditate.square().mul(v).sub(u).isZero()) {
          y = etaSqrtCanditate
          numerator = numerator.mul(iso3zt2)
          break;
        }
      }
    } else {
      y = sqrtValue
    }

    if var y1 = y {
      if (t.sgn0() != y1.sgn0()) {
        y1 = y1.neg()
      }

      y1 = y1.mul(denominator)
      return PointG2(numerator, y1, denominator)
    } else {
      return PointG2.ZERO
    }
  }

  struct Fp: Equatable {
      static let P = BigInt("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", radix: 16)!

      static let ZERO = Fp(0)
      static let ONE = Fp(1)
      static let SIZE = 48

      let i: BigInt

      init(_ data: Data) {
        self.init(BigInt(sign: .plus, magnitude: BigUInt(data)))
      }

      init(_ i: BigInt) {
        self.i = i.modulus(Fp.P)
      }

      init(_ s: String) {
        self.init(BigInt(s, radix: 16)!)
      } 

      func mul(_ b: Fp) -> Fp {
        return Fp(self.i * b.i)
      }

      func add(_ b: Fp) -> Fp {
        return Fp(self.i + b.i)
      } 

      func sub(_ b: Fp) -> Fp {
        return Fp(self.i - b.i)
      }

      func neg() -> Fp {
        return Fp(-self.i)
      } 

      func square() -> Fp {
        return Fp(self.i.power(2))
      }

      func inv() -> Fp {
        return Fp(self.i.inverse(Fp.P)!)
      }

      func isZero() -> Bool {
        return self.i == 0
      }

      func serialize() -> Data {
        let encoded = self.i.magnitude.serialize()
        var data = Data(count:Fp.SIZE - encoded.count)
        data.append(encoded)
        return data
      }

      static func ==(_ a: Fp, _ b: Fp) -> Bool {
        return a.i == b.i
      }              

  }

  struct Fp2: Equatable {
    static let FROBENIUS_COEFFICIENTS = [
      Fp.ONE, 
      Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa")]

    static let ZERO = Fp2(Fp.ZERO, Fp.ZERO)
    static let ONE = Fp2(Fp.ONE, Fp.ZERO)

    static let SIZE = Fp.SIZE * 2

    let re: Fp
    let im: Fp

    init(_ re: Fp, _ im: Fp) {
      self.re = re
      self.im = im
    }

    init(_ buf: [UInt8]) {
      self.init(Fp(Data(buf[..<Fp.SIZE])), Fp(Data(buf[Fp.SIZE...])))
    }

    func sgn0() -> UInt {
      let sgn = ((self.re.i & 1) == 1) || (self.re.isZero() && ((self.im.i & 1) == 1))
      return sgn ? 1 : 0
    }

    func square() -> Fp2 {
      let a = self.re.add(self.im)
      let b = self.re.sub(self.im)
      let c = self.re.add(self.re)
      return Fp2(a.mul(b), c.mul(self.im))   
    }

    func pow(_ n: BigInt) -> Fp2 {
      if (n == 0) { 
        return Fp2.ONE
      }

      if (n == 1) {
        return self
      } 

      var n1 = n
      var p = Fp2.ONE
      var d = self

      while(n1 != 0) {
        if ((n1 & 1) == 1) {
          p = p.mul(d)
        }

        d = d.square()
        n1 >>= 1
      }

      return p
    }

    func isZero() -> Bool {
      return self.re.isZero() && self.im.isZero()
    }

    func mul(_ b: Fp2) -> Fp2 {
      let t1 = self.re.mul(b.re)
      let t2 = self.im.mul(b.im)
      return Fp2(t1.sub(t2), self.re.add(self.im).mul(b.re.add(b.im)).sub(t1.add(t2)))
    }

    func mul(_ b: Fp) -> Fp2 {
      return Fp2(self.re.mul(b), self.im.mul(b))
    } 

    func mul(_ b: BigInt) -> Fp2 {
      return self.mul(Fp(b))
    }

    func add(_ b: Fp2) -> Fp2 {
      return Fp2(self.re.add(b.re), self.im.add(b.im))
    }

    func sub(_ b: Fp2) -> Fp2 {
      return Fp2(self.re.sub(b.re), self.im.sub(b.im))
    }

    func neg() -> Fp2 {
      return Fp2(self.re.neg(), self.im.neg())
    }  

    func inv() -> Fp2 {
      let factor = self.re.square().add(self.im.square()).inv()
      return Fp2(factor.mul(self.re), factor.mul(self.im.neg()))
    } 

    func mulByNonresidue() -> Fp2 {
      return Fp2(self.re.sub(self.im), self.re.add(self.im))
    }

    func frobeniusMap(_ power: Int) -> Fp2 {
      return Fp2(self.re, self.im.mul(Fp2.FROBENIUS_COEFFICIENTS[power % 2]))
    }  

    func serialize() -> Data {
      var data = self.im.serialize()
      data.append(self.re.serialize())
      return data
    }

    static func ==(_ a: Fp2, _ b: Fp2) -> Bool {
      return (a.re == b.re) && (a.im == b.im)
    }
  }

  struct Fp6 {
    static let FROBENIUS_COEFFICIENTS_1 = [
      Fp2.ONE,
      Fp2(
        Fp.ZERO,
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
      ),
      Fp2(
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      Fp2(Fp.ZERO, Fp.ONE),
      Fp2(
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      Fp2(
        Fp.ZERO,
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe")
      ),
    ]

    static let FROBENIUS_COEFFICIENTS_2 = [
      Fp2.ONE,
      Fp2(
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"),
        Fp.ZERO
      ),
      Fp2(
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      Fp2(
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"),
        Fp.ZERO
      ),
      Fp2(
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      Fp2(
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff"),
        Fp.ZERO
      ),
    ]

    static let ZERO = Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO)
    static let ONE = Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO)

    let c0: Fp2
    let c1: Fp2
    let c2: Fp2

    init(_ c0: Fp2, _ c1: Fp2, _ c2: Fp2) {
      self.c0 = c0
      self.c1 = c1
      self.c2 = c2
    }

    func add(_ b: Fp6) -> Fp6 {
      return Fp6(self.c0.add(b.c0), self.c1.add(b.c1), self.c2.add(b.c2))
    }

    func sub(_ b: Fp6) -> Fp6 {
      return Fp6(self.c0.sub(b.c0), self.c1.sub(b.c1), self.c2.sub(b.c2))
    }
  
    func mul(_ b: Fp6) -> Fp6 {
      let t0 = self.c0.mul(b.c0)
      let t1 = self.c1.mul(b.c1)
      let t2 = self.c2.mul(b.c2)
      
      return Fp6(
        t0.add(self.c1.add(self.c2).mul(b.c1.add(b.c2)).sub(t1.add(t2)).mulByNonresidue()),
        c0.add(c1).mul(b.c0.add(b.c1)).sub(t0.add(t1)).add(t2.mulByNonresidue()),
        t1.add(c0.add(c2).mul(b.c0.add(b.c2)).sub(t0.add(t2)))
      );
    }

    func mulByNonresidue() -> Fp6 {
      return Fp6(self.c2.mulByNonresidue(), self.c0, self.c1)
    } 
    
    func mulByFp2(_ b: Fp2) -> Fp6 {
      return Fp6(self.c0.mul(b), self.c1.mul(b), self.c2.mul(b))
    }
  
    func square() -> Fp6 {
      let t0 = self.c0.square()
      let t1 = self.c0.mul(self.c1).mul(2)
      let t3 = self.c1.mul(self.c2).mul(2)
      let t4 = self.c2.square()

      return Fp6(
        t3.mulByNonresidue().add(t0),
        t4.mulByNonresidue().add(t1),
        t1.add(self.c0.sub(self.c1).add(self.c2).square()).add(t3).sub(t0).sub(t4)
      );
    }

    func neg() -> Fp6 {
      return Fp6(self.c0.neg(), self.c1.neg(), self.c2.neg())
    }  
  
    func inv() -> Fp6 {
      let t0 = self.c0.square().sub(self.c2.mul(self.c1).mulByNonresidue())
      let t1 = self.c2.square().mulByNonresidue().sub(self.c0.mul(self.c1))
      let t2 = self.c1.square().sub(self.c0.mul(self.c2))
      let t4 = self.c2.mul(t1).add(self.c1.mul(t2)).mulByNonresidue().add(self.c0.mul(t0)).inv()
      return Fp6(t4.mul(t0), t4.mul(t1), t4.mul(t2))
    }

    func frobeniusMap(_ power: Int) -> Fp6 {
      return Fp6(
        self.c0.frobeniusMap(power),
        self.c1.frobeniusMap(power).mul(Fp6.FROBENIUS_COEFFICIENTS_1[power % 6]),
        self.c2.frobeniusMap(power).mul(Fp6.FROBENIUS_COEFFICIENTS_2[power % 6])
      )
    }  
  }

  struct Fp12 {
    static let FROBENIUS_COEFFICIENTS = [
      Fp2.ONE,
      Fp2(
        Fp("1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8"),
        Fp("00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3")
      ),
      Fp2(
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff"),
        Fp.ZERO
      ),
      Fp2(
        Fp("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2"),
        Fp("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
      ),
      Fp2(
        Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      Fp2(
        Fp("144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995"),
        Fp("05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116")
      ),
      Fp2(
        Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"),
        Fp.ZERO
      ),
      Fp2(
        Fp("00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3"),
        Fp("1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8")
      ),
      Fp2(
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      Fp2(
        Fp("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09"),
        Fp("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2")
      ),
      Fp2(
        Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"),
        Fp.ZERO
      ),
      Fp2(
        Fp("05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116"),
        Fp("144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995")
      ),
    ]

    static let ZERO = Fp12(Fp6.ZERO, Fp6.ZERO)
    static let ONE = Fp12(Fp6.ONE, Fp6.ZERO)

    let c0: Fp6
    let c1: Fp6

    init(_ c0: Fp6, _ c1: Fp6) {
      self.c0 = c0
      self.c1 = c1
    }

    func add(_ b: Fp12) -> Fp12 {
      return Fp12(self.c0.add(b.c0), self.c1.add(b.c1))
    }

    func sub(_ b: Fp12) -> Fp12 {
      return Fp12(self.c0.sub(b.c0), self.c1.sub(b.c1))
    }
  
    func mul(_ b: Fp12) -> Fp12 {
      let t1 = self.c0.mul(b.c0)
      let t2 = self.c1.mul(b.c1)

      return Fp12(
        t1.add(t2.mulByNonresidue()),
        self.c0.add(self.c1).mul(b.c0.add(b.c1)).sub(t1.add(t2))
      )
    }
  
    func mulByFp2(_ b: Fp2) -> Fp12 {
      return Fp12(self.c0.mulByFp2(b), self.c1.mulByFp2(b))
    }
  
    func square() -> Fp12 {
      let ab = self.c0.mul(self.c1);

      return Fp12(
        self.c1.mulByNonresidue().add(self.c0).mul(self.c0.add(self.c1)).sub(ab).sub(ab.mulByNonresidue()),
        ab.add(ab)
      )
    }
  
    func inv() -> Fp12 {
      let t = self.c0.square().sub(self.c1.square().mulByNonresidue()).inv()
      return Fp12(self.c0.mul(t), self.c1.mul(t).neg())
    }
  
    func frobeniusMap(_ power: Int) -> Fp12 {
      let r0 = self.c0.frobeniusMap(power);
      let r1 = self.c1.frobeniusMap(power);
      let coeff = Fp12.FROBENIUS_COEFFICIENTS[power % 12];
      return Fp12(
        r0,
        Fp6(r1.c0.mul(coeff), r1.c1.mul(coeff), r1.c2.mul(coeff))
      )
    }
  }

  struct PointG2: Equatable {
    static let UT_ROOT = Fp6(Fp2.ZERO, Fp2.ONE, Fp2.ZERO)
    static let WSQ = Fp12(UT_ROOT, Fp6.ZERO)
    static let WCU = Fp12(Fp6.ZERO, UT_ROOT)
    static let WSQ_INV = WSQ.inv()
    static let WCU_INV = WCU.inv()
    static let PSI2_C1 = Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
    static let CURVE_X = BigInt("d201000000010000", radix: 16)!


    static let ZERO = PointG2(Fp2.ONE, Fp2.ONE, Fp2.ZERO)

    let x: Fp2
    let y: Fp2
    let z: Fp2

    init(_ x: Fp2, _ y: Fp2, _ z: Fp2) {
      self.x = x
      self.y = y
      self.z = z
    }

    init(_ buf: [UInt8]) {
      self.x = Fp2(Array(buf[..<Fp2.SIZE]))
      self.y = Fp2(Array(buf[Fp2.SIZE...]))
      self.z = Fp2.ONE
    }

    func add(_ b: PointG2) -> PointG2 {
      if (self.isZero()) {
        return b
      } else if (b.isZero()) {
        return self
      }

      let x1 = self.x
      let y1 = self.y
      let z1 = self.z
      let x2 = b.x
      let y2 = b.y
      let z2 = b.z
      let u1 = y2.mul(z1)
      let u2 = y1.mul(z2)
      let v1 = x2.mul(z1)
      let v2 = x1.mul(z2)

      if ((v1 == v2) && (u1 == u2)) {
        if (u1 == u2) {
          return self.doubleP()
        } else {
          return PointG2.ZERO
        }
      }

      let u = u1.sub(u2)
      let v = v1.sub(v2)
      let vv = v.square()
      let vvv = vv.mul(v)
      let v2vv = v2.mul(vv)
      let w = z1.mul(z2)
      let a = u.square().mul(w).sub(vvv).sub(v2vv.add(v2vv))
      let x3 = v.mul(a)
      let y3 = u.mul(v2vv.sub(a)).sub(vvv.mul(u2))
      let z3 = vvv.mul(w)
      return PointG2(x3, y3, z3)
    }

    func doubleP() -> PointG2 {
      let w = self.x.square().mul(3)
      let s = self.y.mul(self.z)
      let ss = s.square()
      let sss = ss.mul(s)
      let b = self.x.mul(self.y).mul(s)
      let h = w.square().sub(b.mul(8))
      let x3 = h.mul(s).mul(2)
      let y3 = w.mul(b.mul(4).sub(h)).sub(
        self.y.square().mul(8).mul(ss)
      )
      let z3 = sss.mul(8)
      return PointG2(x3, y3, z3)
    }

    func isZero() -> Bool {
      return self.z.isZero()
    }

    func clearCofactor() -> PointG2 {
      let t1 = self.mulCurveX()
      var t2 = self.psi()
      var t3 = self.doubleP()
      t3 = t3.psi2()
      t3 = t3.sub(t2)
      t2 = t1.add(t2)
      t2 = t2.mulCurveX()
      t3 = t3.add(t2)
      t3 = t3.sub(t1)
      return t3.sub(self)
    }

    func sub(_ p: PointG2) -> PointG2 {
      return self.add(p.neg())
    }

    func neg() -> PointG2 {
      return PointG2(self.x, self.y.neg(), self.z)
    }

    func psi2() -> PointG2 {
      let p = toAffine();
      return PointG2(p.x.mul(PointG2.PSI2_C1), p.y.neg(), p.z)
    }

    func psi() -> PointG2 {
      let p = toAffine()
      let x2 = PointG2.WSQ_INV.mulByFp2(p.x).frobeniusMap(1).mul(PointG2.WSQ).c0.c0
      let y2 = PointG2.WCU_INV.mulByFp2(p.y).frobeniusMap(1).mul(PointG2.WCU).c0.c0
      return PointG2(x2, y2, p.z)
    }

    func mulCurveX() -> PointG2 {
      return self.mulUnsafe(PointG2.CURVE_X).neg()
    }

    func mulUnsafe(_ n: BigInt) -> PointG2 {
      var n1 = n
      var point = PointG2.ZERO
      var d = self

      while (n1 != 0) {
        if ((n1 & 1) == 1) {
          point = point.add(d)
        }

        d = d.doubleP()
        n1 >>= 1
      }

      return point
    }

    func toAffine() -> PointG2 {
      let invZ = self.z.inv()
      return PointG2(self.x.mul(invZ), self.y.mul(invZ), Fp2.ONE)
    }

    func serialize(compressed: Bool) -> [UInt8] {
      let p = self.toAffine()
      var result = p.x.serialize()

      if (compressed) {
        result[0] |= 0x80;
        let tmp = (p.y.im.isZero() ? p.y.re.i : p.y.im.i) << 1;
        if (tmp > Fp.P) {
          result[0] |= 0x20;
        }
      } else {
        result.append(p.y.serialize());
      }

      return Array(result);
    }

    static func ==(_ a: PointG2, _ b: PointG2) -> Bool {
      return (a.x == b.x) && (a.y == b.y) && (a.z == b.z)
    }
  }    
}
