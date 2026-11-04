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

///|
test "diagnose names the share that disagrees with every quorum" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"0a0b0c0d\",\"threshold\":3,\"shares\":5,\"seed\":31}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // Corrupt share x=4 by flipping its first data byte, then hand the set
  // to diagnose: the quorum that excludes it recovers the secret, and x=4
  // is named as the suspect.
  let data_text = str(get(shares[4], "data"))
  let corrupted_share = record([
    ("index", Number(5)),
    ("threshold", get(shares[4], "threshold")),
    ("digest", get(shares[4], "digest")),
    ("data", String("ff" + data_text[2:].to_owned())),
  ])
  let report = run(
    from_json(
      @json.parse(
        "{\"operation\":\"diagnose\",\"shares\":" +
        Array([shares[0], shares[1], shares[2], shares[3], corrupted_share])
        .to_json()
        .stringify() +
        "}",
      ),
    ),
  )
  assert_eq(get(report, "consistent"), Bool(true))
  assert_eq(get(report, "suspects"), from_json(@json.parse("[5]")))
  assert_eq(get(report, "good"), from_json(@json.parse("[1,2,3,4]")))
  assert_eq(get(report, "secret_hex"), String("0a0b0c0d"))
}

///|
test "verify audits without returning the secret" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"beef\",\"threshold\":2,\"shares\":3,\"seed\":5}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let request = "{\"operation\":\"verify\",\"shares\":[" +
    shares[0].to_json().stringify() +
    "," +
    shares[2].to_json().stringify() +
    "]}"
  let report = run(from_json(@json.parse(request)))
  assert_eq(get(report, "verified"), Bool(true))
  assert_eq(get(report, "secret_length"), Number(2))
  // A verify response never carries the secret bytes.
  assert_eq(get(report, "secret_hex"), Null)
}

///|
test "text secrets split and recombine through the JSON boundary" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_text\":\"钥匙备份 backup 🔑\",\"threshold\":2,\"shares\":3,\"seed\":2026}",
      ),
    ),
  )
  assert_eq(get(split, "secret_bytes"), Number(24))
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let combine = run(
    from_json(
      @json.parse(
        "{\"operation\":\"combine\",\"shares\":[" +
        shares[0].to_json().stringify() +
        "," +
        shares[2].to_json().stringify() +
        "]}",
      ),
    ),
  )
  assert_eq(get(combine, "verified"), Bool(true))
  assert_eq(get(combine, "secret_text"), String("钥匙备份 backup 🔑"))
}

///|
test "secret_hex and secret_text are mutually exclusive" {
  let refused = String(
    match
      run(
        from_json(
          @json.parse(
            "{\"operation\":\"split\",\"secret_hex\":\"ab\",\"secret_text\":\"ab\",\"threshold\":2,\"shares\":3}",
          ),
        ),
      ) {
      _ => "no error raised"
    },
  ) catch {
    InputError(message) => String(message)
    other => String(other.to_string())
  }
  assert_eq(
    refused,
    String("secret_hex and secret_text are mutually exclusive"),
  )
}
