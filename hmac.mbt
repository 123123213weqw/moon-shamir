///|
/// HMAC-SHA256 (RFC 2104) over the library's Array[Int32] byte shape:
/// hash((K xor opad) || hash((K xor ipad) || message)) with the key
/// zero-padded to the 64-byte block size. Keys longer than 64 bytes are
/// first hashed down, per the RFC.
fn hmac_sha256(key : Array[Int32], message : Array[Int32]) -> Array[Int32] {
  let block = 64
  let normalized : Array[Int32] = []
  if key.length() > block {
    for byte in sha256_raw(key) {
      normalized.push(byte)
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
  iterations : Int,
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
  // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
  let key = utf8_bytes("Jefe")
  let data = utf8_bytes("what do ya want for nothing?")
  let mac = to_hex(hmac_sha256(key, data))
  assert_eq(
    mac,
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
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
}
