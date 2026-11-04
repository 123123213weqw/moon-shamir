///|
test "split and combine through the JSON boundary" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"deadbeef\",\"threshold\":2,\"shares\":4,\"seed\":42}",
      ),
    ),
  )
  assert_eq(get(split, "algorithm"), String("shamir-gf256"))
  assert_eq(get(split, "secret_bytes"), Number(4))
  assert_eq(get(split, "threshold"), Number(2))
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(shares.length(), 4)
  // Opposite corners of the share set still recover the secret.
  for pair in [(0, 3), (1, 2)] {
    let combine = run(
      from_json(
        @json.parse(
          "{\"operation\":\"combine\",\"shares\":[" +
          shares[pair.0].to_json().stringify() +
          "," +
          shares[pair.1].to_json().stringify() +
          "]}",
        ),
      ),
    )
    assert_eq(get(combine, "secret_hex"), String("deadbeef"))
    assert_eq(get(combine, "verified"), Bool(true))
  }
}

///|
test "split is deterministic in the seed and the secret only" {
  fn split_of(seed : Double) -> Value raise {
    run(
      from_json(
        @json.parse(
          "{\"operation\":\"split\",\"secret_hex\":\"0a0b\",\"threshold\":3,\"shares\":5,\"seed\":" +
          seed.to_string() +
          "}",
        ),
      ),
    )
  }
  let first = split_of(2026)
  let again = split_of(2026)
  assert_eq(first, again)
  // A different seed moves the share bytes but never the digest.
  let other = split_of(2027)
  assert_not_eq(get(first, "share_list"), get(other, "share_list"))
  assert_eq(get(first, "digest"), get(other, "digest"))
}

///|
test "combine refuses inconsistent share sets" {
  fn error_of(request : String) -> Value {
    let failed = String(
      match run(from_json(@json.parse(request))) {
        _ => "no error raised"
      },
    ) catch {
      InputError(message) => String(message)
      other => String(other.to_string())
    }
    failed
  }
  assert_eq(
    error_of(
      "{\"operation\":\"combine\",\"shares\":[{\"index\":1,\"threshold\":2,\"digest\":\"00000000\",\"data\":\"ab\"},{\"index\":2,\"threshold\":3,\"digest\":\"00000000\",\"data\":\"cd\"}]}",
    ),
    String("shares come from different thresholds"),
  )
  assert_eq(
    error_of(
      "{\"operation\":\"combine\",\"shares\":[{\"index\":1,\"threshold\":2,\"digest\":\"00000000\",\"data\":\"ab\"},{\"index\":2,\"threshold\":2,\"digest\":\"deadbeef\",\"data\":\"cd\"}]}",
    ),
    String("shares come from different splits"),
  )
  assert_eq(
    error_of(
      "{\"operation\":\"combine\",\"shares\":[{\"index\":1,\"threshold\":2,\"digest\":\"00000000\",\"data\":\"ab\"},{\"index\":1,\"threshold\":2,\"digest\":\"00000000\",\"data\":\"cd\"}]}",
    ),
    String("duplicate share index: 1"),
  )
}

///|
test "corrupted share bytes fail the integrity label" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"0123456789abcdef\",\"threshold\":2,\"shares\":2,\"seed\":5}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // One flipped digit in one share: recovery runs, the label disagrees.
  let tampered = "{\"operation\":\"combine\",\"shares\":[" +
    shares[0].to_json().stringify() +
    ",{\"index\":2,\"threshold\":2,\"digest\":" +
    get(shares[1], "digest").to_json().stringify() +
    ",\"data\":\"ffffffffffffffff\"}]}"
  let combine = run(from_json(@json.parse(tampered)))
  assert_eq(get(combine, "verified"), Bool(false))
}
