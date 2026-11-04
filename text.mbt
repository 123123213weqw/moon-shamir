///|
/// Text secrets travel as UTF-8 bytes: encode the string, split the bytes.
/// A refusal names the first reason the text cannot be encoded, though
/// every Unicode scalar value encodes - the check is the ceiling.
fn utf8_bytes(text : String) -> Array[Int32] {
  let encoded = @utf8.encode(text[:])
  let out : Array[Int32] = []
  for i in 0..<encoded.length() {
    out.push(encoded[i].to_int() & 0xFF)
  }
  out
}

///|
/// The recovered bytes as text when they are valid UTF-8, or None when
/// they are not - a share set of a hex secret need not spell text.
fn utf8_text(bytes : Array[Int32]) -> String? {
  let buf : Buffer = Buffer::Buffer()
  for i in 0..<bytes.length() {
    buf.write_byte((bytes[i] & 0xFF).to_byte())
  }
  Some(@utf8.decode(buf.to_bytes()[:])) catch {
    _ => None
  }
}

///|
test "utf8 text round trips through bytes" {
  let plain = "钥匙 backup 生 keys 🔑 12345"
  let bytes = utf8_bytes(plain)
  assert_eq(bytes.length() > 16, true)
  assert_eq(utf8_text(bytes), Some(plain))
  // Bytes that are not UTF-8 decline politely.
  assert_eq(utf8_text([0xFF, 0xFE]), None)
}
