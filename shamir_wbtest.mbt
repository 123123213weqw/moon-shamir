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

///|
test "reshare mints a working split without exposing the secret" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"0badc0de\",\"threshold\":2,\"shares\":3,\"seed\":11}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let reshare = run(
    from_json(
      @json.parse(
        "{\"operation\":\"reshare\",\"shares\":[" +
        shares[0].to_json().stringify() +
        "," +
        shares[2].to_json().stringify() +
        "],\"threshold_new\":3,\"shares_new\":5,\"seed\":77}",
      ),
    ),
  )
  assert_eq(get(reshare, "threshold_new"), Number(3))
  assert_eq(get(reshare, "digest"), get(split, "digest"))
  let minted = match get(reshare, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(minted.length(), 5)
  // The new set recovers the same secret on its own quorums.
  let combine = run(
    from_json(
      @json.parse(
        "{\"operation\":\"combine\",\"shares\":[" +
        minted[0].to_json().stringify() +
        "," +
        minted[3].to_json().stringify() +
        "," +
        minted[4].to_json().stringify() +
        "]}",
      ),
    ),
  )
  assert_eq(get(combine, "secret_hex"), String("0badc0de"))
  assert_eq(get(combine, "verified"), Bool(true))
  // Mixing old and new shares belongs to different polynomials. With the
  // threshold raised the mix is refused outright (thresholds disagree);
  // with the threshold kept the mix interpolates garbage and the label
  // catches it. Either way old shares die after a reshare.
  let mixed_refused = try {
    let _ = run(
      from_json(
        @json.parse(
          "{\"operation\":\"combine\",\"shares\":[" +
          shares[1].to_json().stringify() +
          "," +
          minted[1].to_json().stringify() +
          "]}",
        ),
      ),
    )
    false
  } catch {
    InputError(message) => message == "shares come from different thresholds"
    other => {
      let _ = other
      false
    }
  }
  assert_eq(mixed_refused, true)
  let kept = run(
    from_json(
      @json.parse(
        "{\"operation\":\"reshare\",\"shares\":[" +
        shares[0].to_json().stringify() +
        "," +
        shares[2].to_json().stringify() +
        "],\"threshold_new\":2,\"shares_new\":3,\"seed\":78}",
      ),
    ),
  )
  let kept_shares = match get(kept, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let mixed_answer = run(
    from_json(
      @json.parse(
        "{\"operation\":\"combine\",\"shares\":[" +
        shares[1].to_json().stringify() +
        "," +
        kept_shares[1].to_json().stringify() +
        "]}",
      ),
    ),
  )
  assert_eq(get(mixed_answer, "verified"), Bool(false))
}

///|
test "sha256 commitment end to end" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_text\":\"commit me\",\"threshold\":2,\"shares\":3,\"seed\":9,\"commit\":\"sha256\"}",
      ),
    ),
  )
  assert_eq(get(split, "commit"), String("sha256"))
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(get(shares[0], "commit"), String("sha256"))
  let combine = run(
    from_json(
      @json.parse(
        "{\"operation\":\"combine\",\"shares\":[" +
        shares[1].to_json().stringify() +
        "," +
        shares[2].to_json().stringify() +
        "]}",
      ),
    ),
  )
  assert_eq(get(combine, "verified"), Bool(true))
  assert_eq(get(combine, "secret_text"), String("commit me"))
}

///|
test "kdf standalone equals the password path of split" {
  let derived = run(
    from_json(
      @json.parse(
        "{\"operation\":\"kdf\",\"password\":\"paper backup\",\"salt_hex\":\"cafe\",\"iterations\":1000}",
      ),
    ),
  )
  let seed = get(derived, "seed")
  let with_password = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"a1b2\",\"threshold\":2,\"shares\":3,\"password\":\"paper backup\",\"salt_hex\":\"cafe\",\"iterations\":1000}",
      ),
    ),
  )
  let with_seed = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"a1b2\",\"threshold\":2,\"shares\":3,\"seed\":" +
        seed.to_json().stringify() +
        "}",
      ),
    ),
  )
  assert_eq(get(with_password, "share_list"), get(with_seed, "share_list"))
  assert_eq(get(with_password, "seed_derivation"), String("pbkdf2-sha256"))
  assert_eq(get(with_seed, "seed_derivation"), String("direct"))
}

///|
test "seed and password are mutually exclusive" {
  let refused = String(
    match
      run(
        from_json(
          @json.parse(
            "{\"operation\":\"split\",\"secret_hex\":\"ab\",\"threshold\":2,\"shares\":3,\"seed\":1,\"password\":\"x\"}",
          ),
        ),
      ) {
      _ => "no error raised"
    },
  ) catch {
    InputError(message) => String(message)
    other => String(other.to_string())
  }
  assert_eq(refused, String("seed and password are mutually exclusive"))
}

///|
fn json_shares(items : Array[Value]) -> String {
  Json::array(items.map(fn(v) { v.to_json() })).stringify()
}

///|
fn json_slice(items : Array[Value], count : Int32) -> String {
  let picked : Array[Value] = []
  for i in 0..<count {
    picked.push(items[i])
  }
  json_shares(picked)
}

///|
test "reshare chains across generations with rising thresholds" {
  // Generation 0: 2-of-4. Each generation reshare rises the threshold by
  // one and mints more shares than the last; every generation recovers
  // the same secret on its own quorum, and the previous generation's
  // shares are refused next to the new ones (thresholds disagree).
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"feedc0de\",\"threshold\":2,\"shares\":4,\"seed\":900}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let mut current = shares
  let mut threshold = 2
  for generation in [9001, 9002, 9003] {
    threshold = threshold + 1
    let new_count = threshold + 2
    let reshare = run(
      from_json(
        @json.parse(
          "{\"operation\":\"reshare\",\"threshold_new\":" +
          threshold.to_string() +
          ",\"shares_new\":" +
          new_count.to_string() +
          ",\"seed\":" +
          generation.to_string() +
          ",\"shares\":" +
          json_slice(current, threshold) +
          "}",
        ),
      ),
    )
    assert_eq(get(reshare, "threshold_new"), Number(threshold.to_double()))
    let minted = match get(reshare, "share_list") {
      Array(items) => items
      _ => abort("share_list missing")
    }
    assert_eq(minted.length(), new_count)
    // Recovery from the first `threshold` minted shares of this generation.
    let chosen : Array[Value] = []
    for i in 0..<threshold {
      chosen.push(minted[i])
    }
    let combine = run(
      from_json(
        @json.parse(
          "{\"operation\":\"combine\",\"shares\":" + json_shares(chosen) + "}",
        ),
      ),
    )
    assert_eq(get(combine, "secret_hex"), String("feedc0de"))
    assert_eq(get(combine, "verified"), Bool(true))
    // The old generation cannot ride along: thresholds disagree now.
    let mixed_refused = try {
      let _ = run(
        from_json(
          @json.parse(
            "{\"operation\":\"combine\",\"shares\":" +
            json_shares([current[0], minted[1]]) +
            "}",
          ),
        ),
      )
      false
    } catch {
      InputError(message) => message == "shares come from different thresholds"
      other => {
        let _ = other
        false
      }
    }
    assert_eq(mixed_refused, true)
    current = minted
  }
  // Three generations later the secret is unchanged and the threshold
  // has climbed from 2 to 5.
  assert_eq(threshold, 5)
}

///|
test "the full ring: 255 shares at threshold 255" {
  // n = 255 is the coordinate ceiling. At threshold 255 the split is
  // pure: every share is needed, one subset exists, and recovery takes
  // the whole ring - the degenerate case the Lagrange code must handle
  // without special pleading.
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"ff\",\"threshold\":255,\"shares\":255,\"seed\":20261107}",
      ),
    ),
  )
  assert_eq(get(split, "threshold"), Number(255))
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(shares.length(), 255)
  // One share short is refused with the count named.
  let short : Array[Value] = []
  for i in 0..<254 {
    short.push(shares[i])
  }
  let refused = try {
    let _ = run(
      from_json(
        @json.parse(
          "{\"operation\":\"combine\",\"shares\":" + json_shares(short) + "}",
        ),
      ),
    )
    false
  } catch {
    InputError(message) =>
      message == "need at least 255 shares to combine, got 254"
    other => {
      let _ = other
      false
    }
  }
  assert_eq(refused, true)
  // All 255 recover the single byte.
  let combine = run(
    from_json(
      @json.parse(
        "{\"operation\":\"combine\",\"shares\":" + json_shares(shares) + "}",
      ),
    ),
  )
  assert_eq(get(combine, "secret_hex"), String("ff"))
  assert_eq(get(combine, "verified"), Bool(true))
}

///|
test "info describes a share and its broken checksum" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"cafebabe\",\"threshold\":2,\"shares\":3,\"seed\":5,\"share_encoding\":\"words\"}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let info = run(
    from_json(
      @json.parse(
        "{\"operation\":\"info\",\"share\":" +
        shares[1].to_json().stringify() +
        "}",
      ),
    ),
  )
  assert_eq(get(info, "index"), Number(2))
  assert_eq(get(info, "threshold"), Number(2))
  assert_eq(get(info, "payload_bytes"), Number(4))
  assert_eq(get(info, "checksum_ok"), Bool(true))
  assert_eq(get(info, "authenticated"), Bool(false))
  // Flip one payload word: the checksum finding appears, no refusal.
  let data = str(get(shares[1], "data"))
  let words = data.split(" ").collect()
  let corrupted : Array[String] = [
    words[0].to_owned(),
    words[1].to_owned(),
    words[2].to_owned(),
    words[3].to_owned(),
    words[4].to_owned(),
    "idly",
  ]
  for i in 6..<words.length() {
    corrupted.push(words[i].to_owned())
  }
  let broken = record([
    ("index", Number(2)),
    ("threshold", Number(2)),
    ("digest", get(shares[1], "digest")),
    ("encoding", String("words")),
    ("data", String(corrupted.join(" "))),
  ])
  let report = run(
    from_json(
      @json.parse(
        "{\"operation\":\"info\",\"share\":" +
        broken.to_json().stringify() +
        "}",
      ),
    ),
  )
  assert_eq(get(report, "checksum_ok"), Bool(false))
}

///|
test "split_many answers exactly the per-secret splits" {
  let batch = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split_many\",\"secrets\":[\"a1b2\",\"c3d4e5\"],\"threshold\":2,\"shares\":3,\"seed\":77,\"share_encoding\":\"words\"}",
      ),
    ),
  )
  let splits = match get(batch, "splits") {
    Array(items) => items
    _ => abort("splits missing")
  }
  assert_eq(splits.length(), 2)
  // Secret 1 is a standalone split at seed 78, word-encoded.
  let solo = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"c3d4e5\",\"threshold\":2,\"shares\":3,\"seed\":78,\"share_encoding\":\"words\"}",
      ),
    ),
  )
  assert_eq(get(splits[1], "share_list"), get(solo, "share_list"))
  assert_eq(get(splits[1], "secret_bytes"), Number(3))
}

///|
test "sort orders by index, normalizes encodings, refuses impostors" {
  let words_split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"a1b2c3d4\",\"threshold\":3,\"shares\":5,\"seed\":42,\"share_encoding\":\"words\"}",
      ),
    ),
  )
  let hex_split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"a1b2c3d4\",\"threshold\":3,\"shares\":5,\"seed\":42}",
      ),
    ),
  )
  let hex_shares = match get(hex_split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let word_shares = match get(words_split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // A shuffled, mixed-encoding pile: words shares 5 and 2, hex share 4.
  let shuffled = record([
    ("operation", String("sort")),
    ("shares", Array([word_shares[4], hex_shares[3], word_shares[1]])),
  ])
  let sorted = run(shuffled)
  assert_eq(get(sorted, "shares"), Number(3))
  assert_eq(get(sorted, "share_encoding"), String("hex"))
  let list = match get(sorted, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // Canonical order, uniform hex, payloads identical to the hex split.
  assert_eq(get(list[0], "index"), Number(2))
  assert_eq(get(list[1], "index"), Number(4))
  assert_eq(get(list[2], "index"), Number(5))
  assert_eq(get(list[0], "data"), get(hex_shares[1], "data"))
  assert_eq(get(list[1], "data"), get(hex_shares[3], "data"))
  assert_eq(get(list[2], "data"), get(hex_shares[4], "data"))
  // Re-encoding to words is the same normalization in the other coat.
  let as_words = run(
    record([
      ("operation", String("sort")),
      ("shares", Array([hex_shares[3], hex_shares[1]])),
      ("share_encoding", String("words")),
    ]),
  )
  let words_list = match get(as_words, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(get(words_list[0], "data"), get(word_shares[1], "data"))
  // A below-threshold set sorts fine - nothing is interpolated here.
  let two = run(
    record([
      ("operation", String("sort")),
      ("shares", Array([hex_shares[4], hex_shares[0]])),
    ]),
  )
  assert_eq(get(two, "shares"), Number(2))
  // The same refusal every recovering operation gives: a duplicate x.
  let duplicated = try {
    let _ = run(
      record([
        ("operation", String("sort")),
        ("shares", Array([hex_shares[0], hex_shares[0]])),
      ]),
    )
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(duplicated, "duplicate share index: 1")
  // And a share from another split cannot hide inside the order.
  let foreign = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"a1b2c3d5\",\"threshold\":3,\"shares\":5,\"seed\":42}",
      ),
    ),
  )
  let foreign_shares = match get(foreign, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let mixed = try {
    let _ = run(
      record([
        ("operation", String("sort")),
        ("shares", Array([hex_shares[0], foreign_shares[1]])),
      ]),
    )
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(mixed, "shares come from different splits")
}
