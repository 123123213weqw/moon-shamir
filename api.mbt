///|
/// The standard JSON boundary: one request object in, one report object
/// out, for the split, combine, diagnose, verify, reshare and kdf
/// operations. Failures raise InputError with a plain message.
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
    String("info") => info_with(request)
    String("fingerprint") => fingerprint_with(request)
    String("sort") => sort_with(request)
    String("check") => check_with(request)
    String("quorum_check") => quorum_check_with(request)
    String("split_many") => split_many_with(request)
    String(other) => raise InputError("unsupported operation: " + other)
    _ => raise InputError("missing field: operation")
  }
}

///|
/// The one-call split: a hex secret, a threshold, a share count - every
/// other choice at its documented default (seed 0, crc32 labels, hex
/// payloads, no mac), the same report run answers, as a typed Value.
/// The constructor exists so the common call cannot misspell a field
/// name; seed 0 is a fixed public constant, right for tests and demos
/// and wrong for entropy - production callers inject a real seed, a
/// password derivation or a full-width seed_hex through run.
pub fn split_with_defaults(
  secret_hex : String,
  threshold : Int32,
  shares : Int32,
) -> Value raise InputError {
  run(
    record([
      ("operation", String("split")),
      ("secret_hex", String(secret_hex)),
      ("threshold", Number(threshold.to_double())),
      ("shares", Number(shares.to_double())),
    ]),
  )
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
  let fields : Array[(String, Value)] = [
    ("index", Number(share.index.to_double())),
    ("threshold", Number(share.threshold.to_double())),
    ("digest", String(digest_hex(share.digest))),
    ("commit", String(share.commit)),
    ("data", payload),
    ("encoding", String(encoding)),
  ]
  if share.mac != "" {
    fields.push(("mac", String(share.mac)))
  }
  record(fields)
}

///|
fn share_from_value(value : Value) -> Share raise InputError {
  fields_only(value, [
    "index", "threshold", "digest", "commit", "mac", "data", "encoding",
  ])
  let mac = match get(value, "mac") {
    Null => ""
    String(tag) => {
      if parse_hex(tag).length() != 8 {
        raise InputError("share mac must be 16 hex digits")
      }
      tag
    }
    _ => raise InputError("share mac must be a string of 16 hex digits")
  }
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
    mac,
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
    "operation", "secret_hex", "secret_text", "threshold", "shares", "seed", "seed_hex",
    "share_encoding", "commit", "password", "salt_hex", "iterations", "mac_key_hex",
  ])
  let mac_key = read_mac_key(request)
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
    "operation", "secret_hex", "secret_text", "threshold", "shares", "seed", "seed_hex",
    "share_encoding", "commit", "password", "salt_hex", "iterations",
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
    seed_and_kdf.0,
    commit,
    mac_key,
  )
  let encoded : Array[Value] = []
  for share in generated {
    encoded.push(share_to_value_as(share, share_encoding))
  }
  let fields : Array[(String, Value)] = [
    ("algorithm", String("shamir-gf256")),
    ("secret_bytes", Number(secret.length().to_double())),
    ("threshold", Number(threshold)),
    ("shares", Number(shares)),
    ("share_encoding", String(share_encoding)),
    ("commit", String(commit)),
    ("authenticated", Bool(mac_key.length() > 0)),
    ("digest", String(digest_hex(commit_digest(secret, commit)))),
    (
      "seed_derivation",
      String(if seed_and_kdf.1 == "" { "direct" } else { seed_and_kdf.1 }),
    ),
    ("share_list", Array(encoded)),
  ]
  append_seed_fields(fields, seed)
  record(fields)
}

///|
/// Recover the secret from k or more shares of one split. Below the
/// threshold the door stays closed - there is no wrong-secret output to
/// misuse. The recovered bytes are checked against the label every share
/// carried; verified is false when they disagree, which means a share was
/// corrupted or does not belong to this split.
fn combine_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares", "mac_key_hex"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 255 {
    raise InputError("shares must list 2..255 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let mac_key = read_mac_key_checked(request, parsed)
  let (recovered, verified) = shamir_combine(parsed, mac_key)
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
  fields_only(request, ["operation", "shares", "mac_key_hex"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 2 || raw.length() > 12 {
    raise InputError("shares must list 2..12 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let mac_key = read_mac_key_checked(request, parsed)
  shamir_diagnose(parsed, mac_key)
}

///|
/// Audit a share set without returning the secret: the same interpolation
/// combine performs, reported as a verdict only. When secret_hex is also
/// supplied, the verdict additionally requires the recovered bytes to
/// equal it - a holder can prove a share set belongs to a known secret
/// without the response carrying anything new.
fn verify_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares", "secret_hex", "mac_key_hex"])
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
  let mac_key = read_mac_key_checked(request, parsed)
  let (recovered, verified) = shamir_combine(parsed, mac_key)
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
/// A MAC key from the request: absent means no authentication; present
/// it is 1..64 bytes of hex. Empty hex is refused - an empty key would
/// make the mac field a public constant, silently worse than none.
fn read_mac_key(request : Value) -> Array[Int32] raise InputError {
  match get(request, "mac_key_hex") {
    Null => []
    other => {
      let key = parse_hex(str(other))
      if key.length() == 0 {
        raise InputError("mac_key_hex must not be empty")
      }
      if key.length() > 64 {
        raise InputError("mac_key_hex must stay within 64 bytes")
      }
      key
    }
  }
}

///|
/// Cross-checks the request's key against the share set's mac fields:
/// keyed shares demand a key, a key with unkeyed shares is a silent
/// no-op that must not pass quietly, and the fields must agree.
fn read_mac_key_checked(
  request : Value,
  shares : Array[Share],
) -> Array[Int32] raise InputError {
  let key = read_mac_key(request)
  let mac = shares[0].mac
  for share in shares {
    if share.mac != mac {
      raise InputError("shares come from different macs")
    }
  }
  if mac != "" && key.length() == 0 {
    raise InputError("shares carry a mac but no mac_key_hex was given")
  }
  if mac == "" && key.length() > 0 {
    raise InputError("shares carry no mac but a mac_key_hex was given")
  }
  key
}

///|
/// The seed as report fields: the numeric form only when a double
/// carries it exactly (up to 2^53-1), and always the full-width hex -
/// the numeric form silently lies above the double range.
fn append_seed_fields(fields : Array[(String, Value)], seed : UInt64) -> Unit {
  let bytes : Array[Int32] = []
  for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
    bytes.push(((seed >> shift) & 0xFFUL).to_int())
  }
  fields.push(
    (
      "seed",
      if seed <= 9007199254740991UL {
        Number(seed.to_double())
      } else {
        Null
      },
    ),
  )
  fields.push(("seed_hex", String(to_hex(bytes))))
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
) -> (UInt64, String) raise InputError {
  let has_password = has(request, "password")
  let has_seed = has(request, "seed")
  if has_password && has_seed {
    raise InputError("seed and password are mutually exclusive")
  }
  if !has_password {
    // seed_hex carries a full 64-bit seed; the numeric seed stays for
    // compatibility and is capped by what a double numbers exactly.
    if has(request, "seed_hex") {
      if has_seed {
        raise InputError("seed and seed_hex are mutually exclusive")
      }
      let raw = parse_hex(str(required(request, "seed_hex")))
      if raw.length() != 8 {
        raise InputError("seed_hex must be exactly 8 bytes")
      }
      let mut value : UInt64 = 0UL
      for byte in raw {
        value = (value << 8) | (byte.to_uint64() & 0xFFUL)
      }
      return (value, "")
    }
    return (read_seed(request).to_uint64(), "")
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
  (seed, "pbkdf2-sha256")
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
  let report : Array[(String, Value)] = [
    ("algorithm", String("pbkdf2-sha256")),
    ("iterations", Number(iterations)),
    ("salt_hex", String(to_hex(salt))),
  ]
  append_seed_fields(report, seed)
  record(report)
}

///|
/// Mint a fresh split from k old shares without the secret passing
/// through memory: a random polynomial with zero constant term is added
/// per byte, drawn from the new seed, and each new share evaluates the
/// sum at a fresh x. The threshold may rise but never fall below the old
/// one; a new x may not collide with an old share index.
fn reshare_with(request : Value) -> Value raise InputError {
  fields_only(request, [
    "operation", "shares", "threshold_new", "shares_new", "seed", "seed_hex", "share_encoding",
    "password", "salt_hex", "iterations",
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
    seed,
  )
  let encoded : Array[Value] = []
  for share in minted {
    encoded.push(share_to_value_as(share, share_encoding))
  }
  let report : Array[(String, Value)] = [
    ("algorithm", String("shamir-gf256")),
    ("threshold_new", Number(threshold_new)),
    ("shares_new", Number(shares_new)),
    ("digest", String(digest_hex(minted[0].digest))),
    ("commit", String(minted[0].commit)),
    ("share_encoding", String(share_encoding)),
    ("share_list", Array(encoded)),
  ]
  append_seed_fields(report, seed)
  record(report)
}

///|
/// Identify one share without recovering anything: the x it carries,
/// the threshold it was minted for, the label and commitment kinds, its
/// encoding and payload length, and - for words shares - whether the
/// embedded checksum verifies. A bad checksum is a finding, not a
/// refusal: info exists to describe what is in hand, including what is
/// wrong with it.
fn info_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "share"])
  let raw = required(request, "share")
  // A share that parses is described from its parsed form; a words
  // share that fails its checksum is described anyway - the failure is
  // the finding info exists to report, not a refusal.
  let parsed = Some(share_from_value(raw)) catch { _ => None }
  match parsed {
    Some(share) => {
      let checksum_ok = match get(raw, "encoding") {
        String("words") => {
          let words_text = str(get(raw, "data"))
          let pieces = words_text.split(" ").collect()
          let words : Array[String] = []
          for piece in pieces {
            words.push(piece.to_owned())
          }
          try {
            let decoded = mnemonic_decode(words)
            let _ = decoded
            true
          } catch {
            _ => false
          }
        }
        _ => true
      }
      let fields : Array[(String, Value)] = [
        ("algorithm", String("shamir-gf256")),
        ("index", Number(share.index.to_double())),
        ("threshold", Number(share.threshold.to_double())),
        ("digest", String(digest_hex(share.digest))),
        ("commit", String(share.commit)),
        ("authenticated", Bool(share.mac != "")),
        ("payload_bytes", Number(share.data.length().to_double())),
        ("checksum_ok", Bool(checksum_ok)),
      ]
      if share.mac != "" {
        fields.push(("mac", String(share.mac)))
      }
      record(fields)
    }
    None => {
      // Describing a share that would not parse: fields are read as
      // they stand, payload estimated from the word count (index,
      // threshold, payload words, two checksum words).
      let encoding = str(get(raw, "encoding"))
      if encoding != "words" {
        // Non-words shares have no embedded checksum to dispute; a
        // parse failure there is a genuine refusal.
        raise InputError("share could not be parsed")
      }
      let words_text = str(get(raw, "data"))
      let pieces = words_text.split(" ").collect()
      let word_count = pieces.length()
      let payload = if word_count >= 4 { word_count - 4 } else { 0 }
      let index = num(get(raw, "index"))
      let threshold = num(get(raw, "threshold"))
      record([
        ("algorithm", String("shamir-gf256")),
        ("index", Number(index)),
        ("threshold", Number(threshold)),
        ("digest", get(raw, "digest")),
        ("commit", get(raw, "commit")),
        ("authenticated", Bool(has(raw, "mac"))),
        ("payload_bytes", Number(payload.to_double())),
        ("checksum_ok", Bool(false)),
      ])
    }
  }
}

///|
/// One short id for a share set - the answer to "did I transcribe these
/// correctly" and "is this the same batch as that one". Takes any
/// number of shares of one split (they must agree on threshold, label
/// and commitment; order does not matter) and answers 16 hex digits.
fn fingerprint_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 1 || raw.length() > 255 {
    raise InputError("shares must list 1..255 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("shares", Number(parsed.length().to_double())),
    ("threshold", Number(parsed[0].threshold.to_double())),
    ("fingerprint", String(shamir_fingerprint(parsed))),
  ])
}

///|
/// Put a share list in canonical order: by x coordinate, ascending.
/// Every share is parsed and the set must be one split's - the same
/// threshold, label, commitment and mac agreement every recovering
/// operation demands, with distinct x coordinates - but nothing is
/// interpolated and the secret is never touched, so a set below the
/// threshold sorts as happily as a full quorum. The output re-encodes
/// every payload in one encoding of the caller's choosing (hex by
/// default), so a pile of mixed-encoding shares becomes one uniform,
/// canonically ordered list for storage or paper.
fn sort_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares", "share_encoding"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 1 || raw.length() > 255 {
    raise InputError("shares must list 1..255 shares")
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
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let sorted = shares_agreeing(parsed)
  let encoded : Array[Value] = []
  for share in sorted {
    encoded.push(share_to_value_as(share, share_encoding))
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("shares", Number(sorted.length().to_double())),
    ("threshold", Number(sorted[0].threshold.to_double())),
    ("digest", String(digest_hex(sorted[0].digest))),
    ("commit", String(sorted[0].commit)),
    ("share_encoding", String(share_encoding)),
    ("share_list", Array(encoded)),
  ])
}

///|
/// Count a share set against its threshold without recovering anything:
/// how many shares are in hand, the threshold they name, and how many
/// more are needed before combine's door opens. The one-split agreement
/// is demanded - the same refusals, by name - so `ready` means k
/// consistent shares are in hand, not merely k lines. A single share is
/// a valid question here: one holder asking how far the quorum still is.
fn check_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 1 || raw.length() > 255 {
    raise InputError("shares must list 1..255 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let sorted = shares_agreeing(parsed)
  let count = sorted.length()
  let threshold = sorted[0].threshold
  let gap = if count < threshold { threshold - count } else { 0 }
  record([
    ("algorithm", String("shamir-gf256")),
    ("shares", Number(count.to_double())),
    ("threshold", Number(threshold.to_double())),
    ("gap", Number(gap.to_double())),
    ("ready", Bool(gap == 0)),
    ("digest", String(digest_hex(sorted[0].digest))),
    ("commit", String(sorted[0].commit)),
    ("authenticated", Bool(sorted[0].mac != "")),
    ("payload_bytes", Number(sorted[0].data.length().to_double())),
  ])
}

///|
/// C(n, k) as an exact value, or Null when exactness ends. The
/// multiplicative formula runs in UInt64 with an overflow check at
/// every step, so every answer it returns is the true count; a count
/// past the integers a JSON double carries exactly (2^53 - 1, the
/// bound the numeric seed field already honors) reports Null rather
/// than an approximation. C(255, 8) is the last exact value at the
/// share ceiling; C(255, 9) is already past it.
fn quorums_exact(n : Int32, k : Int32) -> Value {
  if k < 0 || n < k {
    return Number(0.0)
  }
  let kk = if k > n - k { n - k } else { k }
  let mut value : UInt64 = 1UL
  for i in 0..<kk {
    let m = (n - i).to_uint64()
    if m != 0UL && value > 0xFFFFFFFFFFFFFFFFUL / m {
      // The product would wrap; the true count is beyond honest
      // reporting and Null says so.
      return Null
    }
    value = value * m
    // The division is exact by construction: C(n, i) * (n - i) is
    // C(n, i + 1) * (i + 1).
    value = value / (i + 1).to_uint64()
  }
  if value <= 9007199254740991UL {
    Number(value.to_double())
  } else {
    Null
  }
}

///|
/// Plan a recovery without running one. The counted view is check's -
/// shares in hand, threshold, gap, ready - and the planner's fields
/// ride beside it: excess, how many shares are in hand beyond the
/// threshold; quorums, how many distinct minimal quorums the set
/// forms (C(count, threshold), exact or Null by quorums_exact's
/// rule); and crosscheck_ready, whether the excess is enough for
/// combine's crosscheck mode to have anything to validate. The
/// one-split agreement is demanded with the same refusals by name;
/// a single share is a valid question, and the report carries
/// nothing secret-shaped.
fn quorum_check_with(request : Value) -> Value raise InputError {
  fields_only(request, ["operation", "shares"])
  let raw = arr(required(request, "shares"))
  if raw.length() < 1 || raw.length() > 255 {
    raise InputError("shares must list 1..255 shares")
  }
  let parsed : Array[Share] = []
  for entry in raw {
    parsed.push(share_from_value(entry))
  }
  let sorted = shares_agreeing(parsed)
  let count = sorted.length()
  let threshold = sorted[0].threshold
  let gap = if count < threshold { threshold - count } else { 0 }
  let excess = if count > threshold { count - threshold } else { 0 }
  record([
    ("algorithm", String("shamir-gf256")),
    ("shares", Number(count.to_double())),
    ("threshold", Number(threshold.to_double())),
    ("gap", Number(gap.to_double())),
    ("ready", Bool(gap == 0)),
    ("excess", Number(excess.to_double())),
    ("quorums", quorums_exact(count, threshold)),
    ("crosscheck_ready", Bool(gap == 0 && excess >= 1)),
    ("digest", String(digest_hex(sorted[0].digest))),
    ("commit", String(sorted[0].commit)),
    ("authenticated", Bool(sorted[0].mac != "")),
    ("payload_bytes", Number(sorted[0].data.length().to_double())),
  ])
}

///|
/// Split several secrets in one request: the same threshold, share
/// count, encodings and key choices apply to every secret, and each
/// gets its own seed - the request's seed (or password derivation)
/// plus the secret's position - so the shares of secret i are exactly
/// what a standalone split with that derived seed would answer. 1..64
/// secrets per request.
fn split_many_with(request : Value) -> Value raise InputError {
  fields_only(request, [
    "operation", "secrets", "threshold", "shares", "seed", "password", "salt_hex",
    "iterations", "share_encoding", "commit", "mac_key_hex",
  ])
  let raw = arr(required(request, "secrets"))
  if raw.length() < 1 || raw.length() > 64 {
    raise InputError("secrets must list 1..64 secrets (hex strings)")
  }
  let secrets : Array[Array[Int32]] = []
  for entry in raw {
    let bytes = parse_hex(str(entry))
    if bytes.is_empty() {
      raise InputError("secret must carry at least one byte")
    }
    if bytes.length() > 16384 {
      raise InputError("secret_hex must stay within 16384 bytes")
    }
    secrets.push(bytes)
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
  let mac_key = read_mac_key(request)
  let seed_and_kdf = read_seed_or_password(request, [
    "operation", "secrets", "threshold", "shares", "seed", "password", "salt_hex",
    "iterations", "share_encoding", "commit", "mac_key_hex",
  ])
  let base_seed = seed_and_kdf.0
  let splits : Array[Value] = []
  for i, secret in secrets {
    // Position i joins the stream: each secret's shares are exactly a
    // standalone split with seed_i would answer.
    let derived = (base_seed + i.to_uint64()) & 0x1FFFFFFFFFFFFFUL
    let generated = shamir_split(
      secret,
      threshold.to_int(),
      shares.to_int(),
      derived,
      commit,
      mac_key,
    )
    let encoded : Array[Value] = []
    for share in generated {
      encoded.push(share_to_value_as(share, share_encoding))
    }
    splits.push(
      record([
        ("position", Number(i.to_double())),
        ("secret_bytes", Number(secret.length().to_double())),
        ("digest", String(digest_hex(commit_digest(secret, commit)))),
        ("share_list", Array(encoded)),
      ]),
    )
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("secrets", Number(secrets.length().to_double())),
    ("threshold", Number(threshold)),
    ("shares", Number(shares)),
    ("share_encoding", String(share_encoding)),
    ("commit", String(commit)),
    ("authenticated", Bool(mac_key.length() > 0)),
    (
      "seed_derivation",
      String(if seed_and_kdf.1 == "" { "direct" } else { seed_and_kdf.1 }),
    ),
    ("splits", Array(splits)),
  ])
}
