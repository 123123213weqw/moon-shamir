///|
/// The standard JSON boundary: one request object in, one report object out.
/// Failures raise InputError with a plain message.
pub fn execute(request : Json) -> Json raise {
  run(from_json(request)).to_json()
}

///|
/// The typed boundary over the same requests.
pub fn run(request : Value) -> Value raise InputError {
  match get(request, "operation") {
    String("split") => split_with(request)
    String("combine") => combine_with(request)
    String("diagnose") => diagnose_with(request)
    String("verify") => verify_with(request)
    String("reshare") => reshare_with(request)
    String("kdf") => kdf_with(request)
    String(other) => raise InputError("unsupported operation: " + other)
    _ => raise InputError("missing field: operation")
  }
}

///|
/// JSON shape of one share, both ways.

///|
fn share_to_value_as(share : Share, encoding : String) -> Value {
  let payload = if encoding == "base64" {
    String(share_bytes_to_base64(share.data))
  } else if encoding == "words" {
    String(mnemonic_encode(share.index, share.threshold, share.data).join(" "))
  } else {
    String(to_hex(share.data))
  }
  record([
    ("index", Number(share.index.to_double())),
    ("threshold", Number(share.threshold.to_double())),
    ("digest", String(digest_hex(share.digest))),
    ("commit", String(share.commit)),
    ("data", payload),
    ("encoding", String(encoding)),
  ])
}

///|
fn share_from_value(value : Value) -> Share raise InputError {
  fields_only(value, [
    "index", "threshold", "digest", "commit", "data", "encoding",
  ])
  let commit = match get(value, "commit") {
    Null => "crc32"
    String("crc32") => "crc32"
    String("sha256") => "sha256"
    String(other) =>
      raise InputError("share commit must be crc32 or sha256, found: " + other)
    _ => raise InputError("share commit must be crc32 or sha256")
  }
  let index = num(required(value, "index"))
  if index.floor() != index || index < 1.0 || index > 255.0 {
    raise InputError("share index must be a whole number 1..255")
  }
  let threshold = num(required(value, "threshold"))
  if threshold.floor() != threshold || threshold < 2.0 || threshold > 255.0 {
    raise InputError("share threshold must be a whole number 2..255")
  }
  let digest_bytes = parse_hex(str(required(value, "digest")))
  if digest_bytes.length() != 4 {
    raise InputError("share digest must be 8 hex digits")
  }
  let data = match get(value, "encoding") {
    Null => parse_hex(str(required(value, "data")))
    String("hex") => parse_hex(str(required(value, "data")))
    String("base64") => share_bytes_from_base64(str(required(value, "data")))
    String("words") => {
      let pieces = str(required(value, "data")).split(" ").collect()
      let words : Array[String] = []
      for piece in pieces {
        words.push(piece.to_owned())
      }
      let decoded = mnemonic_decode(words)
      // The words already encode index and threshold; the fields must
      // agree with them, so two sources of truth cannot disagree quietly.
      if decoded.index != index.to_int() {
        raise InputError("share index field and mnemonic word 1 disagree")
      }
      if decoded.threshold != threshold.to_int() {
        raise InputError("share threshold field and mnemonic word 2 disagree")
      }
      decoded.data
    }
    String(other) =>
      raise InputError(
        "share encoding must be hex, base64 or words, found: " + other,
      )
    _ => raise InputError("share encoding must be hex, base64 or words")
  }
  if data.is_empty() {
    raise InputError("share data must carry at least one byte")
  }
  {
    index: index.to_int(),
    threshold: threshold.to_int(),
    digest: digest_of_bytes(digest_bytes),
    commit,
    data,
  }
}

///|
/// Split a secret (hex) into n shares of which any k recover it. The seed
/// is the entropy of the split - the randomness source is injected by the
/// caller, never read from the environment, and the same (secret, seed)
/// pair reproduces the same shares everywhere.
fn split_with(request : Value) -> Value raise InputError {
  fields_only(request, [
    "operation", "secret_hex", "secret_text", "threshold", "shares", "seed", "share_encoding",
    "commit", "password", "salt_hex", "iterations",
  ])
  let secret = match (get(request, "secret_hex"), get(request, "secret_text")) {
    (Null, Null) => raise InputError("missing field: secret_hex")
    (String(hex), Null) => parse_hex(hex)
    (Null, String(text)) => utf8_bytes(text)
    (Null, other) => {
      let _ = str(other)
      abort("unreachable")
    }
    _ => raise InputError("secret_hex and secret_text are mutually exclusive")
  }
  if secret.is_empty() {
    raise InputError("secret_hex must carry at least one byte")
  }
  if secret.length() > 16384 {
    raise InputError("secret_hex must stay within 16384 bytes")
  }
  let threshold = num(required(request, "threshold"))
  if threshold.floor() != threshold || threshold < 2.0 || threshold > 255.0 {
    raise InputError("threshold must be a whole number 2..255")
  }
  let shares = num(required(request, "shares"))
  if shares.floor() != shares || shares < 2.0 || shares > 255.0 {
    raise InputError("shares must be a whole number 2..255")
  }
  if shares < threshold {
    raise InputError(
      "shares must be at least the threshold: " + threshold.to_string(),
    )
  }
  // Doubles carry 53 significant bits, so a seed above 2^53 - 1 cannot
  // arrive intact through JSON; the bound is part of the contract.
  let seed_and_kdf = read_seed_or_password(request, [
    "operation", "secret_hex", "secret_text", "threshold", "shares", "seed", "share_encoding",
    "commit", "password", "salt_hex", "iterations",
  ])
  let seed = seed_and_kdf.0
  let commit = match get(request, "commit") {
    Null => "crc32"
    String("crc32") => "crc32"
    String("sha256") => "sha256"
    String(other) =>
      raise InputError("commit must be crc32 or sha256, found: " + other)
    _ => raise InputError("commit must be crc32 or sha256")
  }
  let share_encoding = match get(request, "share_encoding") {
    Null => "hex"
    String("hex") => "hex"
    String("base64") => "base64"
    String("words") => "words"
    String(other) =>
      raise InputError(
        "share_encoding must be hex, base64 or words, found: " + other,
      )
    _ => raise InputError("share_encoding must be hex, base64 or words")
  }
  let generated = shamir_split(
    secret,
    threshold.to_int(),
    shares.to_int(),
    seed.to_uint64(),
    commit,
  )
  let encoded : Array[Value] = []
  for share in generated {
    encoded.push(share_to_value_as(share, share_encoding))
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("secret_bytes", Number(secret.length().to_double())),
    ("threshold", Number(threshold)),
    ("shares", Number(shares)),
    ("seed", Number(seed)),
    ("share_encoding", String(share_encoding)),
    ("commit", String(commit)),
    ("digest", String(digest_hex(commit_digest(secret, commit)))),
    (
      "seed_derivation",
      String(if seed_and_kdf.1 == "" { "direct" } else { seed_and_kdf.1 }),
    ),
    ("share_list", Array(encoded)),
  ])
}

///|
/// Recover the secret from k or more shares of one split. Below the
/// threshold the door stays closed - there is no wrong-secret output to
/// misuse. The recovered bytes are checked against the label every share
/// carried; verified is false when they disagree, which means a share was
/// corrupted or does not belong to this split.
fn combine_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 255 {
    raise InputError("shares must list 2..255 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let (recovered, verified) = shamir_combine(parsed)
  let fields : Array[(String, Value)] = [
    ("algorithm", String("shamir-gf256")),
    ("secret_hex", String(to_hex(recovered))),
    ("recovered_digest", String(digest_hex(crc32(recovered)))),
    ("verified", Bool(verified)),
  ]
  match utf8_text(recovered) {
    Some(text) => fields.push(("secret_text", String(text)))
    None => ()
  }
  record(fields)
}

///|
/// Diagnose a share set without asserting it is clean: which shares agree
/// with a quorum, which disagree with every quorum, and whether a
/// consistent secret exists at all.
fn diagnose_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 12 {
    raise InputError("shares must list 2..12 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  shamir_diagnose(parsed)
}

///|
/// Audit a share set without returning the secret: the same interpolation
/// combine performs, reported as a verdict only. When secret_hex is also
/// supplied, the verdict additionally requires the recovered bytes to
/// equal it - a holder can prove a share set belongs to a known secret
/// without the response carrying anything new.
fn verify_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares", "secret_hex"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 255 {
    raise InputError("shares must list 2..255 shares")
  }
  let expected = match get(request, "secret_hex") {
    Null => ""
    other => {
      // A claim about the secret is itself hex and length-checked here,
      // so a malformed claim is a refusal, not a verdict.
      let claimed = parse_hex(str(other))
      to_hex(claimed)
    }
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let (recovered, verified) = shamir_combine(parsed)
  let matches_secret = if expected == "" {
    verified
  } else {
    verified && to_hex(recovered) == expected
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("shares", Number(parsed.length().to_double())),
    ("threshold", Number(threshold_of(parsed).to_double())),
    ("commit", String(parsed[0].commit)),
    ("secret_length", Number(recovered.length().to_double())),
    ("verified", Bool(matches_secret)),
  ])
}

///|
fn threshold_of(shares : Array[Share]) -> Int32 {
  shares[0].threshold
}

///|
/// The seed ceiling a JSON double carries exactly.
fn seed_max() -> Double {
  9007199254740991.0
}

///|
/// A seed field validated in place: whole, 0..2^53-1.
fn read_seed(request : Value) -> Double raise InputError {
  let seed = match get(request, "seed") {
    Null => 0.0
    other => num(other)
  }
  if seed.floor() != seed || seed < 0.0 || seed > seed_max() {
    raise InputError("seed must be a whole number 0..9007199254740991")
  }
  seed
}

///|
/// A password path: either a plain numeric seed (default 0) or a
/// password stretched through PBKDF2-HMAC-SHA256 with a salt and an
/// iteration count. Exactly one of the two forms may be given; the
/// derived seed is the first 7 bytes of the 32-byte output, big-endian,
/// masked to 53 bits so it stays an exact double.
fn read_seed_or_password(
  request : Value,
  allowed : Array[String],
) -> (Double, String) raise InputError {
  let has_password = has(request, "password")
  let has_seed = has(request, "seed")
  if has_password && has_seed {
    raise InputError("seed and password are mutually exclusive")
  }
  if !has_password {
    return (read_seed(request), "")
  }
  fields_only(request, allowed)
  let password = utf8_bytes(str(required(request, "password")))
  if password.length() == 0 {
    raise InputError("password must not be empty")
  }
  if password.length() > 1024 {
    raise InputError("password must stay within 1024 bytes")
  }
  let salt = match get(request, "salt_hex") {
    Null => parse_hex("6d6f6f6e7368616d6972")
    other => parse_hex(str(other))
  }
  let iterations = match get(request, "iterations") {
    Null => 10000.0
    other => num(other)
  }
  if iterations.floor() != iterations ||
    iterations < 1.0 ||
    iterations > 1000000.0 {
    raise InputError("iterations must be a whole number 1..1000000")
  }
  let derived = pbkdf2_sha256(password, salt, iterations.to_int())
  // Seven bytes = 56 bits; mask the top bit away to stay within the 53
  // bits a double numbers exactly.
  let mut seed : UInt64 = 0UL
  for i in 0..<7 {
    seed = (seed << 8) | (derived[i].to_uint64() & 0xFFUL)
  }
  seed = seed >> 3
  (seed.to_double(), "pbkdf2-sha256")
}

///|
/// Derive a split seed from a password: the same stretch split performs,
/// offered standalone so a caller can pin the seed before splitting.
fn kdf_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "password", "salt_hex", "iterations"])
  let password = utf8_bytes(str(required(request, "password")))
  if password.length() == 0 {
    raise InputError("password must not be empty")
  }
  if password.length() > 1024 {
    raise InputError("password must stay within 1024 bytes")
  }
  let salt = match get(request, "salt_hex") {
    Null => parse_hex("6d6f6f6e7368616d6972")
    other => parse_hex(str(other))
  }
  let iterations = match get(request, "iterations") {
    Null => 10000.0
    other => num(other)
  }
  if iterations.floor() != iterations ||
    iterations < 1.0 ||
    iterations > 1000000.0 {
    raise InputError("iterations must be a whole number 1..1000000")
  }
  let derived = pbkdf2_sha256(password, salt, iterations.to_int())
  let mut seed : UInt64 = 0UL
  for i in 0..<7 {
    seed = (seed << 8) | (derived[i].to_uint64() & 0xFFUL)
  }
  seed = seed >> 3
  record([
    ("algorithm", String("pbkdf2-sha256")),
    ("iterations", Number(iterations)),
    ("salt_hex", String(to_hex(salt))),
    ("seed", Number(seed.to_double())),
  ])
}

///|
/// Mint a fresh split from k old shares without the secret passing
/// through memory: a random polynomial with zero constant term is added
/// per byte, drawn from the new seed, and each new share evaluates the
/// sum at a fresh x. The threshold may rise but never fall below the old
/// one; a new x may not collide with an old share index.
fn reshare_with(request : Value) -> Value raise InputError {
  fields_only(request, [
    "operation", "shares", "threshold_new", "shares_new", "seed", "share_encoding",
  ])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 255 {
    raise InputError("shares must list 2..255 shares")
  }
  let threshold_new = num(required(request, "threshold_new"))
  if threshold_new.floor() != threshold_new ||
    threshold_new < 2.0 ||
    threshold_new > 255.0 {
    raise InputError("threshold_new must be a whole number 2..255")
  }
  let shares_new = num(required(request, "shares_new"))
  if shares_new.floor() != shares_new || shares_new < 2.0 || shares_new > 255.0 {
    raise InputError("shares_new must be a whole number 2..255")
  }
  let seed_and_kdf = read_seed_or_password(request, [
    "operation", "shares", "threshold_new", "shares_new", "seed", "share_encoding",
    "password", "salt_hex", "iterations",
  ])
  let seed = seed_and_kdf.0
  let share_encoding = match get(request, "share_encoding") {
    Null => "hex"
    String("hex") => "hex"
    String("base64") => "base64"
    String("words") => "words"
    String(other) =>
      raise InputError(
        "share_encoding must be hex, base64 or words, found: " + other,
      )
    _ => raise InputError("share_encoding must be hex, base64 or words")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let minted = shamir_reshare(
    parsed,
    threshold_new.to_int(),
    shares_new.to_int(),
    seed.to_uint64(),
  )
  let encoded : Array[Value] = []
  for share in minted {
    encoded.push(share_to_value_as(share, share_encoding))
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("threshold_new", Number(threshold_new)),
    ("shares_new", Number(shares_new)),
    ("seed", Number(seed)),
    ("digest", String(digest_hex(minted[0].digest))),
    ("commit", String(minted[0].commit)),
    ("share_encoding", String(share_encoding)),
    ("share_list", Array(encoded)),
  ])
}
