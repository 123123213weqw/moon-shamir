///|
/// Share payloads in base64: shorter on paper than hex. Decoding is
/// strict - padding and alphabet are checked by the core codec, and the
/// byte count still has to match what the share set agrees on.
fn share_bytes_from_base64(text : String) -> Array[Int32] raise InputError {
  let decoded = try {
    @base64.decode(text[:])
  } catch {
    _ => raise InputError("share data is not valid base64")
  }
  let out : Array[Int32] = []
  for i in 0..<decoded.length() {
    out.push(decoded[i].to_int() & 0xFF)
  }
  out
}

///|
fn share_bytes_to_base64(bytes : Array[Int32]) -> String {
  let buf : Buffer = Buffer::Buffer()
  for i in 0..<bytes.length() {
    buf.write_byte((bytes[i] & 0xFF).to_byte())
  }
  @base64.encode(buf.to_bytes()[:])
}

///|
test "base64 share payloads round trip" {
  let bytes : Array[Int32] = [0, 1, 127, 128, 200, 255]
  let text = share_bytes_to_base64(bytes)
  assert_eq(text, "AAF/gMj/")
  assert_eq(share_bytes_from_base64(text), bytes)
}
