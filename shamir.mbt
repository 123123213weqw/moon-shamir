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
  commit : String
  mac : String
  data : Array[Int32]
}

///|
/// The MAC tag of `bytes` under `key`: the first 16 hex digits (64 bits)
/// of HMAC-SHA256. An empty key answers the empty string, which no share
/// ever carries - the field is simply absent when the split had no key.
fn mac_of(bytes : Array[Int32], key : Array[Int32]) -> String {
  let full = hmac_sha256(key, bytes)
  let head : Array[Int32] = []
  for i in 0..<8 {
    head.push(full[i])
  }
  to_hex(head)
}

///|
/// The label of `bytes` under the named commitment: CRC-32 by default,
/// or the first 32 bits of SHA-256 when the split asked for it. Both
/// travel as 8 hex digits; the commitment kind rides in every share.
fn commit_digest(bytes : Array[Int32], commit : String) -> UInt32 {
  if commit == "sha256" {
    let raw = sha256_raw(bytes)
    digest_of_bytes([raw[0], raw[1], raw[2], raw[3]])
  } else {
    crc32(bytes)
  }
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
  commit : String,
  mac_key : Array[Int32],
) -> Array[Share] {
  let rng = splitmix64(seed)
  let digest = commit_digest(secret, commit)
  let mac = if mac_key.length() > 0 { mac_of(secret, mac_key) } else { "" }
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
    out.push({ index: x, threshold, digest, commit, mac, data, })
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
  mac_key : Array[Int32],
) -> (Array[Int32], Bool) raise InputError {
  let threshold = shares[0].threshold
  let digest = shares[0].digest
  let commit = shares[0].commit
  let mac = shares[0].mac
  let width = shares[0].data.length()
  for share in shares {
    if share.threshold != threshold {
      raise InputError("shares come from different thresholds")
    }
    if share.digest != digest {
      raise InputError("shares come from different splits")
    }
    if share.commit != commit {
      raise InputError("shares come from different commitments")
    }
    if share.mac != mac {
      raise InputError("shares come from different macs")
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
  // The Lagrange weights depend only on the chosen x coordinates, so
  // they are computed once for the whole share set; each byte position
  // then costs k multiplies instead of k^2 inversions.
  let zero_points : Array[(Int32, Int32)] = []
  for share in chosen {
    zero_points.push((share.index, 0))
  }
  let weights = gf_lagrange_weights(zero_points, 0)
  let recovered : Array[Int32] = []
  for b in 0..<width {
    let points : Array[(Int32, Int32)] = []
    for share in chosen {
      points.push((share.index, share.data[b]))
    }
    recovered.push(gf_interpolate_weighted(points, weights))
  }
  // The MAC is the strong check: only key holders could have produced
  // matching tags, so a mismatch means forgery or corruption. The keyed
  // check implies the unkeyed label, so it stands alone when present.
  let label_ok = commit_digest(recovered, commit) == digest
  let verified = if mac == "" {
    label_ok
  } else {
    label_ok && mac_of(recovered, mac_key) == mac
  }
  (recovered, verified)
}

///|
test "any k of n shares recover the same secret" {
  // The algebraic law of the scheme, checked exhaustively: every k-sized
  // subset of the shares interpolates back to the same secret.
  let secret : Array[Int32] = [0, 1, 127, 128, 200, 255]
  let shares = shamir_split(secret, 3, 5, 20261104, "crc32", [])
  assert_eq(shares.length(), 5)
  // C(5, 3) = 10 subsets, enumerated by hand over the five indices.
  for i in 0..<5 {
    for j = i + 1; j < 5; j = j + 1 {
      for k = j + 1; k < 5; k = k + 1 {
        let (recovered, verified) = shamir_combine(
          [shares[i], shares[j], shares[k]],
          [],
        )
        assert_eq(verified, true)
        assert_eq(recovered, secret)
      }
    }
  }
}

///|
test "fewer than k shares are refused outright" {
  let secret : Array[Int32] = [9, 9, 9, 9]
  let shares = shamir_split(secret, 3, 5, 7, "crc32", [])
  // The combine door is closed below the threshold: no wrong-secret
  // output exists to misuse, the refusal names what is missing.
  let refused = try {
    let _ = shamir_combine([shares[0], shares[1]], [])
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

///|
/// Diagnose a share set: enumerate every k-sized subset, interpolate each,
/// and keep the subsets whose recovered bytes carry the label the shares
/// agree on. A share that appears in no consistent subset disagrees with
/// every quorum and is named a suspect; a set with at least one
/// consistent subset is consistent, and its secret is reported. The
/// enumeration is exhaustive, so it is bounded: at most 12 shares of a
/// threshold at most 6 (C(12,6) = 924 interpolations per byte position).
fn shamir_diagnose(
  shares : Array[Share],
  mac_key : Array[Int32],
) -> Value raise InputError {
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
    if share.commit != shares[0].commit {
      raise InputError("shares come from different commitments")
    }
    if share.mac != shares[0].mac {
      raise InputError("shares come from different macs")
    }
    if share.index < 1 || share.index > 255 {
      raise InputError("share index must be in 1..255")
    }
    if share.data.length() != width {
      raise InputError("shares have different lengths")
    }
  }
  if shares.length() > 12 {
    raise InputError("diagnose accepts at most 12 shares")
  }
  if threshold > 6 {
    raise InputError("diagnose accepts a threshold of at most 6")
  }
  if shares.length() < threshold {
    raise InputError(
      "need at least " +
      threshold.to_string() +
      " shares to diagnose, got " +
      shares.length().to_string(),
    )
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
  // Enumerate k-subsets by bitmask over at most 12 shares.
  let total = 1 << shares.length()
  // C(m, k) by the multiplicative formula, in Double to stay exact for
  // every m the bounds allow.
  let mut subsets_total = 1.0
  for i in 0..<threshold {
    subsets_total = subsets_total *
      (shares.length() - i).to_double() /
      (i + 1).to_double()
  }
  let mut consistent_subsets = 0
  let recovered : Array[Int32] = []
  let good : Map[Int32, Bool] = Map([])
  for mask in 1..<total {
    let picked : Array[Share] = []
    for i in 0..<shares.length() {
      if ((mask >> i) & 1) == 1 {
        picked.push(shares[i])
      }
    }
    if picked.length() != threshold {
      continue
    }
    let zero_points : Array[(Int32, Int32)] = []
    for share in picked {
      zero_points.push((share.index, 0))
    }
    let weights = gf_lagrange_weights(zero_points, 0)
    let candidate : Array[Int32] = []
    for b in 0..<width {
      let points : Array[(Int32, Int32)] = []
      for share in picked {
        points.push((share.index, share.data[b]))
      }
      candidate.push(gf_interpolate_weighted(points, weights))
    }
    let label_ok = commit_digest(candidate, shares[0].commit) == digest
    if shares[0].mac != "" && mac_of(candidate, mac_key) != shares[0].mac {
      // A keyed quorum must also match the tag; unkeyed subsets skip.
      continue
    }
    if label_ok {
      consistent_subsets += 1
      if recovered.is_empty() {
        for byte in candidate {
          recovered.push(byte)
        }
      }
      for share in picked {
        good[share.index] = true
      }
    }
  }
  let suspects : Array[Value] = []
  let good_list : Array[Value] = []
  for share in shares {
    if good.contains(share.index) {
      good_list.push(Number(share.index.to_double()))
    } else {
      suspects.push(Number(share.index.to_double()))
    }
  }
  record([
    ("shares", Number(shares.length().to_double())),
    ("threshold", Number(threshold.to_double())),
    ("subsets_checked", Number(subsets_total)),
    ("consistent_subsets", Number(consistent_subsets.to_double())),
    ("consistent", Bool(consistent_subsets > 0)),
    ("good", Array(good_list)),
    ("suspects", Array(suspects)),
    (
      "secret_hex",
      String(if consistent_subsets > 0 { to_hex(recovered) } else { "" }),
    ),
  ])
}

///|
/// Reshare: mint a fresh (threshold_new, shares_new) split from k old
/// shares, without the secret ever existing in memory. A fresh random
/// polynomial h of degree threshold_new - 1 with h(0) = 0 is drawn from
/// the new seed; the new polynomial g = f + h keeps the secret as its
/// constant term, and each new share is g evaluated at its x - which is
/// the old polynomial interpolated at that x, XOR the new polynomial
/// evaluated there. The threshold can grow (degree rises) but never
/// shrink below the old one, or g would silently stay at the old degree;
/// the refusal names that bound. Old and new shares belong to different
/// polynomials: mixing them fails the integrity label, which is the
/// proactive-security point - after a reshare, destroy the old shares.
fn shamir_reshare(
  shares : Array[Share],
  threshold_new : Int32,
  shares_new : Int32,
  seed : UInt64,
) -> Array[Share] raise InputError {
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
    if share.commit != shares[0].commit {
      raise InputError("shares come from different commitments")
    }
    if share.mac != shares[0].mac {
      raise InputError("shares come from different macs")
    }
    if share.index < 1 || share.index > 255 {
      raise InputError("share index must be in 1..255")
    }
    if share.data.length() != width {
      raise InputError("shares have different lengths")
    }
  }
  if shares.length() < threshold {
    raise InputError(
      "need at least " +
      threshold.to_string() +
      " shares to reshare, got " +
      shares.length().to_string(),
    )
  }
  if threshold_new < threshold {
    raise InputError(
      "a reshare threshold cannot fall below the old threshold: " +
      threshold.to_string(),
    )
  }
  if threshold_new > 255 || shares_new < threshold_new || shares_new > 255 {
    raise InputError(
      "threshold and shares must fit 2..255 with shares >= threshold",
    )
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
  // Deterministic input choice: the lowest threshold x coordinates.
  let sorted : Array[Share] = []
  for share in shares {
    sorted.push(share)
  }
  sorted.sort_by(fn(a, b) { a.index - b.index })
  let basis : Array[Share] = []
  for i in 0..<threshold {
    basis.push(sorted[i])
  }
  // One fresh h per byte position, constant term zero.
  let rng = splitmix64(seed)
  let hs : Array[Array[Int32]] = []
  for _ in 0..<width {
    let poly : Array[Int32] = [0]
    for _ in 1..<threshold_new {
      poly.push(rng.next_byte())
    }
    hs.push(poly)
  }
  let out : Array[Share] = []
  // New x coordinates are the smallest values that no old share occupies,
  // so a reshare can mint more shares than it started from and old and
  // new sets never alias an x. The share carries its x either way.
  let mut x = 0
  let mut allocated = 0
  while allocated < shares_new {
    x = x + 1
    if x > 255 {
      raise InputError("no free x coordinate below 256 for a new share")
    }
    let mut taken = false
    for share in shares {
      if share.index == x {
        taken = true
      }
    }
    if taken {
      continue
    }
    allocated = allocated + 1
    // Weights at this x depend only on the basis x coordinates, so one
    // set serves every byte position.
    let basis_x : Array[(Int32, Int32)] = []
    for share in basis {
      basis_x.push((share.index, 0))
    }
    let weights = gf_lagrange_weights(basis_x, x)
    let data : Array[Int32] = []
    for b in 0..<width {
      let points : Array[(Int32, Int32)] = []
      for share in basis {
        points.push((share.index, share.data[b]))
      }
      let f_at = gf_interpolate_weighted(points, weights)
      data.push(f_at ^ gf_eval(hs[b], x))
    }
    out.push({
      index: x,
      threshold: threshold_new,
      digest,
      commit: shares[0].commit,
      mac: shares[0].mac,
      data,
    })
  }
  out
}

///|
/// A canonical byte image of one share for fingerprinting: every field
/// that identifies it, in a fixed order - index, threshold, the label
/// bytes, the commitment and mac as utf-8 with length prefixes, and the
/// payload. Length prefixes keep concatenation unambiguous.
fn share_image(share : Share) -> Array[Int32] {
  let image : Array[Int32] = [
    share.index & 0xFF,
    share.threshold & 0xFF,
    ((share.digest >> 24) & 0xFFU).reinterpret_as_int(),
    ((share.digest >> 16) & 0xFFU).reinterpret_as_int(),
    ((share.digest >> 8) & 0xFFU).reinterpret_as_int(),
    (share.digest & 0xFFU).reinterpret_as_int(),
  ]
  for text in [share.commit, share.mac] {
    let bytes = utf8_bytes(text)
    image.push(bytes.length() & 0xFF)
    for byte in bytes {
      image.push(byte & 0xFF)
    }
  }
  for byte in share.data {
    image.push(byte & 0xFF)
  }
  image
}

///|
/// The fingerprint of a share set: SHA-256 over the images of the
/// shares sorted by index, joined by a 0xFF separator that cannot
/// appear inside a field. The first 8 bytes, 16 hex digits - short
/// enough to compare by eye, long enough that mistyping one character
/// of a payload changes it beyond collision. Order-insensitive by
/// construction; two different sets of one split have different
/// fingerprints, because the set is what it describes.
fn shamir_fingerprint(shares : Array[Share]) -> String raise InputError {
  if shares.length() < 1 || shares.length() > 255 {
    raise InputError("fingerprint needs 1..255 shares")
  }
  let sorted : Array[Share] = []
  for share in shares {
    sorted.push(share)
  }
  sorted.sort_by(fn(a, b) { a.index - b.index })
  for i in 1..<sorted.length() {
    if sorted[i].index == sorted[i - 1].index {
      raise InputError("duplicate share index: " + sorted[i].index.to_string())
    }
  }
  let image : Array[Int32] = []
  for i in 0..<sorted.length() {
    if i > 0 {
      image.push(0xFF)
    }
    for byte in share_image(sorted[i]) {
      image.push(byte)
    }
  }
  to_hex(sha256_raw(image)[:8].to_owned())
}

///|
test "fingerprint is order-insensitive and flip-sensitive" {
  let secret : Array[Int32] = [1, 2, 3, 4]
  let shares = shamir_split(secret, 2, 4, 20261109, "crc32", [])
  let a = shamir_fingerprint([shares[0], shares[2]])
  let b = shamir_fingerprint([shares[2], shares[0]])
  assert_eq(a, b)
  assert_eq(a.length(), 16)
  // A different subset of the same split has a different fingerprint.
  let c = shamir_fingerprint([shares[0], shares[1]])
  assert_not_eq(a, c)
  // One flipped payload byte changes it.
  let tampered = {
    let copy : Array[Int32] = []
    for byte in shares[2].data {
      copy.push(byte)
    }
    copy[0] = copy[0] ^ 1
    {
      index: shares[2].index,
      threshold: shares[2].threshold,
      digest: shares[2].digest,
      commit: shares[2].commit,
      mac: shares[2].mac,
      data: copy,
    }
  }
  let d = shamir_fingerprint([shares[0], tampered])
  assert_not_eq(a, d)
}
