///|
/// HMAC-SHA256 (RFC 2104) over the library's Array[Int32] byte shape:
/// hash((K xor opad) || hash((K xor ipad) || message)) with the key
/// zero-padded to the 64-byte block size. Keys longer than 64 bytes are
/// first hashed down, per the RFC.
fn hmac_sha256(key : Array[Int32], message : Array[Int32]) -> Array[Int32] {
  let block = 64
  let normalized : Array[Int32] = []
  if key.length() > block {
    // RFC 2104: a long key is first hashed down, then zero-padded to
    // the block size - the padding was missing, and any key over 64
    // bytes walked off the array in the ipad loop. RFC 4231's case 3
    // caught it; nothing shorter than the block size ever could.
    let hashed = sha256_raw(key)
    for i in 0..<block {
      normalized.push(if i < hashed.length() { hashed[i] & 0xFF } else { 0 })
    }
  } else {
    for i in 0..<block {
      normalized.push(if i < key.length() { key[i] & 0xFF } else { 0 })
    }
  }
  let ipad : Array[Int32] = []
  let opad : Array[Int32] = []
  for i in 0..<block {
    ipad.push(normalized[i] ^ 0x36)
    opad.push(normalized[i] ^ 0x5C)
  }
  for byte in message {
    ipad.push(byte & 0xFF)
  }
  let inner = sha256_raw(ipad)
  for byte in inner {
    opad.push(byte & 0xFF)
  }
  sha256_raw(opad)
}

///|
/// PBKDF2-HMAC-SHA256 (RFC 8018) for one 32-byte output block: U_1 =
/// PRF(P, S || INT(i)), U_j = PRF(P, U_{j-1}), output = U_1 xor ... xor
/// U_c. Iterations are bounded below by 1 and above by 1000000 - the
/// bound is a service guard, not a security claim; the security lives in
/// the password's entropy times this stretch.
fn pbkdf2_sha256(
  password : Array[Int32],
  salt : Array[Int32],
  iterations : Int32,
) -> Array[Int32] {
  let salted : Array[Int32] = []
  for byte in salt {
    salted.push(byte & 0xFF)
  }
  // Block index 1, big-endian 32 bits (one block covers our 32-byte need).
  salted.push(0)
  salted.push(0)
  salted.push(0)
  salted.push(1)
  let mut u = hmac_sha256(password, salted)
  let out : Array[Int32] = []
  for i in 0..<32 {
    out.push(u[i] & 0xFF)
  }
  for _ in 1..<iterations {
    u = hmac_sha256(password, u)
    for i in 0..<32 {
      out[i] = out[i] ^ (u[i] & 0xFF)
    }
  }
  out
}

///|
test "hmac and pbkdf2 match the RFC vectors" {
  // RFC 4231 test case 1: 20 bytes of 0x0b, data "Hi There" - the
  // short-key path (zero-padded under the block size).
  let short_key : Array[Int32] = []
  for _ in 0..<20 {
    short_key.push(0x0B)
  }
  assert_eq(
    to_hex(hmac_sha256(short_key, utf8_bytes("Hi There"))),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
  let key = utf8_bytes("Jefe")
  let data = utf8_bytes("what do ya want for nothing?")
  let mac = to_hex(hmac_sha256(key, data))
  assert_eq(
    mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  // RFC 6070-style check for PBKDF2-HMAC-SHA256 (known vector: password
  // "password", salt "salt", 1 and 2 iterations).
  assert_eq(
    to_hex(pbkdf2_sha256(utf8_bytes("password"), utf8_bytes("salt"), 1)),
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
  )
  assert_eq(
    to_hex(pbkdf2_sha256(utf8_bytes("password"), utf8_bytes("salt"), 2)),
    "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
  )
  // RFC 4231 test case 3: a 131-byte key, longer than the block - the
  // hash-the-key-down path.
  let long_key : Array[Int32] = []
  for _ in 0..<131 {
    long_key.push(0xAA)
  }
  assert_eq(
    to_hex(
      hmac_sha256(
        long_key,
        utf8_bytes("Test Using Larger Than Block-Size Key - Hash Key First"),
      ),
    ),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  )
  assert_eq(
    to_hex(pbkdf2_sha256(utf8_bytes("password"), utf8_bytes("salt"), 4096)),
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  )
}
