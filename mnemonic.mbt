///|
/// Mnemonic shares: bytes as a sequence of English words, one word per
/// byte plus a two-word checksum, so a share can be written down with a
/// pen and typed back without hex dyslexia. The layout is positional:
/// word 0 is the share index, word 1 the threshold, then one word per
/// payload byte, then two words carrying the top 16 bits of the CRC-32
/// over (index, threshold, payload).
fn mnemonic_encode(
  index : Int32,
  threshold : Int32,
  data : Array[Int32],
) -> Array[String] {
  let words : Array[String] = []
  words.push(mnemonic_words[index])
  words.push(mnemonic_words[threshold])
  for byte in data {
    words.push(mnemonic_words[byte])
  }
  let crc_input : Array[Int32] = [index, threshold]
  for byte in data {
    crc_input.push(byte)
  }
  let crc = crc32(crc_input)
  words.push(mnemonic_words[((crc >> 24) & 0xFFU).reinterpret_as_int()])
  words.push(mnemonic_words[((crc >> 16) & 0xFFU).reinterpret_as_int()])
  words
}

///|
priv struct MnemonicShare {
  index : Int32
  threshold : Int32
  data : Array[Int32]
}

///|
/// Decode a word sequence back to a share. Every refusal names the
/// offending word position: unknown words, out-of-role words (index 0 is
/// reserved), a payload shorter than one byte, and a checksum mismatch.
fn mnemonic_decode(words : Array[String]) -> MnemonicShare raise InputError {
  let reverse : Map[String, Int32] = Map([])
  for i in 0..<256 {
    reverse[mnemonic_words[i]] = i
  }
  fn word_at(position : Int32) -> Int32 raise InputError {
    let word = words[position]
    match reverse.get(word) {
      Some(value) => value
      None =>
        raise InputError(
          "mnemonic word " +
          (position + 1).to_string() +
          " is not in the table: " +
          word,
        )
    }
  }
  if words.length() < 5 {
    raise InputError(
      "mnemonic needs at least 5 words, got " + words.length().to_string(),
    )
  }
  let index = word_at(0)
  if index < 1 {
    raise InputError("mnemonic word 1 encodes share index 0, which is reserved")
  }
  let threshold = word_at(1)
  if threshold < 2 {
    raise InputError("mnemonic word 2 encodes threshold below 2")
  }
  let payload : Array[Int32] = []
  let payload_end = words.length() - 2
  for i in 2..<payload_end {
    payload.push(word_at(i))
  }
  if payload.is_empty() {
    raise InputError("mnemonic carries no payload bytes")
  }
  let want_high = word_at(words.length() - 2)
  let want_low = word_at(words.length() - 1)
  let crc_input : Array[Int32] = [index, threshold]
  for byte in payload {
    crc_input.push(byte)
  }
  let crc = crc32(crc_input)
  let have_high = ((crc >> 24) & 0xFFU).reinterpret_as_int()
  let have_low = ((crc >> 16) & 0xFFU).reinterpret_as_int()
  if have_high != want_high || have_low != want_low {
    raise InputError(
      "mnemonic checksum mismatch: word " +
      (words.length() - 1).to_string() +
      " or " +
      words.length().to_string() +
      " is wrong",
    )
  }
  { index, threshold, data: payload, }
}

///|
test "mnemonic shares round trip and catch corruption" {
  let data : Array[Int32] = [0, 1, 127, 128, 255]
  let words = mnemonic_encode(3, 2, data)
  assert_eq(words.length(), 9)
  let decoded = mnemonic_decode(words)
  assert_eq(decoded.index, 3)
  assert_eq(decoded.threshold, 2)
  assert_eq(decoded.data, data)
  // A flipped payload word fails the checksum, by position.
  let corrupted : Array[String] = []
  for i in 0..<5 {
    corrupted.push(words[i])
  }
  corrupted.push(mnemonic_words[0])
  corrupted.push(words[6])
  corrupted.push(words[7])
  corrupted.push(words[8])
  let refused = try {
    let _ = mnemonic_decode(corrupted)
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(refused, "mnemonic checksum mismatch: word 8 or 9 is wrong")
  // A foreign word is named by position.
  let foreign : Array[String] = ["zzzz"]
  for i in 1..<words.length() {
    foreign.push(words[i])
  }
  let unknown = try {
    let _ = mnemonic_decode(foreign)
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(unknown, "mnemonic word 1 is not in the table: zzzz")
}
