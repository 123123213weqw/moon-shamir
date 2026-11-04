///|
/// CRC-32 (the reflected 0xEDB88320 form) over the secret bytes, carried
/// in every share. This is an integrity label for catching a mistyped,
/// truncated or foreign share during combine - explicitly not a MAC, and
/// the sharing secrecy itself rests only on the information-theoretic
/// argument, never on this checksum.
fn crc32(bytes : Array[Int32]) -> UInt32 {
  let mut crc = 0xFFFFFFFFU
  for byte in bytes {
    crc = crc ^ byte.reinterpret_as_uint()
    for _ in 0..<8 {
      if (crc & 1U) == 1U {
        crc = (crc >> 1) ^ 0xEDB88320U
      } else {
        crc = crc >> 1
      }
    }
  }
  crc ^ 0xFFFFFFFFU
}

///|
/// The integrity label as 8 lowercase hex digits, the share's wire form.
fn digest_hex(digest : UInt32) -> String {
  to_hex([
    ((digest >> 24) & 0xFFU).reinterpret_as_int(),
    ((digest >> 16) & 0xFFU).reinterpret_as_int(),
    ((digest >> 8) & 0xFFU).reinterpret_as_int(),
    (digest & 0xFFU).reinterpret_as_int(),
  ])
}

///|
fn digest_of_bytes(bytes : Array[Int32]) -> UInt32 {
  (bytes[0].reinterpret_as_uint() << 24) |
  (bytes[1].reinterpret_as_uint() << 16) |
  (bytes[2].reinterpret_as_uint() << 8) |
  bytes[3].reinterpret_as_uint()
}

///|
/// One share: the x coordinate (1..255), the threshold it was made for,
/// the integrity label of the secret, and one evaluation of each byte's
/// polynomial at x.
priv struct Share {
  index : Int32
  threshold : Int32
  digest : UInt32
  data : Array[Int32]
}

///|
/// Split `secret` into n shares of which any k recover it. Each byte gets
/// its own random polynomial of degree k-1 whose constant term is that
/// byte; share i is the evaluation of every polynomial at x = i. Fewer
/// than k shares leave every possible secret equally likely - that is the
/// information-theoretic guarantee, and it holds for any coefficient
/// stream that is uniform; the caller seeds the stream.
fn shamir_split(
  secret : Array[Int32],
  threshold : Int32,
  shares : Int32,
  seed : UInt64,
) -> Array[Share] {
  let rng = splitmix64(seed)
  let digest = crc32(secret)
  // coefficients[b] is byte b's polynomial, constant term first.
  let coefficients : Array[Array[Int32]] = []
  for byte in secret {
    let poly : Array[Int32] = [byte]
    for _ in 1..<threshold {
      poly.push(rng.next_byte())
    }
    coefficients.push(poly)
  }
  let out : Array[Share] = []
  for x in 1..<=shares {
    let data : Array[Int32] = []
    for poly in coefficients {
      data.push(gf_eval(poly, x))
    }
    out.push({ index: x, threshold, digest, data, })
  }
  out
}

///|
/// Combine k or more shares of one split: the constant term of each
/// byte's polynomial, interpolated at zero. The shares must agree on
/// threshold and digest and carry distinct nonzero x coordinates; the
/// first `threshold` shares by x are the ones interpolated. The returned
/// pair is the recovered bytes and whether the integrity label matches -
/// a mismatch means the shares do not belong to one secret (or one was
/// corrupted), and the recovered bytes are then meaningless by design.
fn shamir_combine(
  shares : Array[Share],
) -> (Array[Int32], Bool) raise InputError {
  let threshold = shares[0].threshold
  let digest = shares[0].digest
  let width = shares[0].data.length()
  for share in shares {
    if share.threshold != threshold {
      raise InputError("shares come from different thresholds")
    }
    if share.digest != digest {
      raise InputError("shares come from different splits")
    }
    if share.index < 1 || share.index > 255 {
      raise InputError("share index must be in 1..255")
    }
    if share.data.length() != width {
      raise InputError("shares have different lengths")
    }
  }
  for i in 0..<shares.length() {
    for j = i + 1; j < shares.length(); j = j + 1 {
      if shares[i].index == shares[j].index {
        raise InputError(
          "duplicate share index: " + shares[i].index.to_string(),
        )
      }
    }
  }
  if shares.length() < threshold {
    raise InputError(
      "need at least " +
      threshold.to_string() +
      " shares to combine, got " +
      shares.length().to_string(),
    )
  }
  // Deterministic choice: the lowest threshold x coordinates interpolate.
  let sorted : Array[Share] = []
  for share in shares {
    sorted.push(share)
  }
  sorted.sort_by(fn(a, b) { a.index - b.index })
  let chosen : Array[Share] = []
  for i in 0..<threshold {
    chosen.push(sorted[i])
  }
  let recovered : Array[Int32] = []
  for b in 0..<width {
    let points : Array[(Int32, Int32)] = []
    for share in chosen {
      points.push((share.index, share.data[b]))
    }
    recovered.push(gf_interpolate_zero(points))
  }
  (recovered, crc32(recovered) == digest)
}

///|
test "any k of n shares recover the same secret" {
  // The algebraic law of the scheme, checked exhaustively: every k-sized
  // subset of the shares interpolates back to the same secret.
  let secret : Array[Int32] = [0, 1, 127, 128, 200, 255]
  let shares = shamir_split(secret, 3, 5, 20261104)
  assert_eq(shares.length(), 5)
  // C(5, 3) = 10 subsets, enumerated by hand over the five indices.
  for i in 0..<5 {
    for j = i + 1; j < 5; j = j + 1 {
      for k = j + 1; k < 5; k = k + 1 {
        let (recovered, verified) = shamir_combine([
          shares[i],
          shares[j],
          shares[k],
        ])
        assert_eq(verified, true)
        assert_eq(recovered, secret)
      }
    }
  }
}

///|
test "fewer than k shares are refused outright" {
  let secret : Array[Int32] = [9, 9, 9, 9]
  let shares = shamir_split(secret, 3, 5, 7)
  // The combine door is closed below the threshold: no wrong-secret
  // output exists to misuse, the refusal names what is missing.
  let refused = try {
    let _ = shamir_combine([shares[0], shares[1]])
    false
  } catch {
    InputError(message) => message == "need at least 3 shares to combine, got 2"
  }
  assert_eq(refused, true)
  // Below the threshold the interpolation itself lands anywhere but the
  // secret: two points of a degree-2 polynomial fix nothing about zero.
  let points : Array[(Int32, Int32)] = [
    (1, shares[0].data[0]),
    (2, shares[1].data[0]),
  ]
  assert_not_eq(gf_interpolate_zero(points), secret[0])
}
