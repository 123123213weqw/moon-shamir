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
    String(other) => raise InputError("unsupported operation: " + other)
    _ => raise InputError("missing field: operation")
  }
}

///|
/// JSON shape of one share, both ways.
fn share_to_value(share : Share) -> Value {
  record([
    ("index", Number(share.index.to_double())),
    ("threshold", Number(share.threshold.to_double())),
    ("digest", String(digest_hex(share.digest))),
    ("data", String(to_hex(share.data))),
  ])
}

///|
fn share_from_value(value : Value) -> Share raise InputError {
  fields_only(value, ["index", "threshold", "digest", "data"])
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
  let data = parse_hex(str(required(value, "data")))
  if data.is_empty() {
    raise InputError("share data must carry at least one byte")
  }
  {
    index: index.to_int(),
    threshold: threshold.to_int(),
    digest: digest_of_bytes(digest_bytes),
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
    "operation", "secret_hex", "threshold", "shares", "seed",
  ])
  let secret = parse_hex(str(required(request, "secret_hex")))
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
  let seed = match get(request, "seed") {
    Null => 0.0
    other => num(other)
  }
  if seed.floor() != seed || seed < 0.0 || seed > 9007199254740991.0 {
    raise InputError("seed must be a whole number 0..9007199254740991")
  }
  let generated = shamir_split(
    secret,
    threshold.to_int(),
    shares.to_int(),
    seed.to_uint64(),
  )
  let encoded : Array[Value] = []
  for share in generated {
    encoded.push(share_to_value(share))
  }
  record([
    ("algorithm", String("shamir-gf256")),
    ("secret_bytes", Number(secret.length().to_double())),
    ("threshold", Number(threshold)),
    ("shares", Number(shares)),
    ("seed", Number(seed)),
    ("digest", String(digest_hex(crc32(secret)))),
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
  record([
    ("algorithm", String("shamir-gf256")),
    ("secret_hex", String(to_hex(recovered))),
    ("recovered_digest", String(digest_hex(crc32(recovered)))),
    ("verified", Bool(verified)),
  ])
}
