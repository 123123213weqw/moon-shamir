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

///|
test "check counts the gap without recovering" {
  let split = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"cafebabe\",\"threshold\":3,\"shares\":5,\"seed\":42}",
      ),
    ),
  )
  let shares = match get(split, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // Two of a threshold-3 split: one short, and the door stays closed.
  let short = run(
    record([
      ("operation", String("check")),
      ("shares", Array([shares[4], shares[0]])),
    ]),
  )
  assert_eq(get(short, "shares"), Number(2))
  assert_eq(get(short, "threshold"), Number(3))
  assert_eq(get(short, "gap"), Number(1))
  assert_eq(get(short, "ready"), Bool(false))
  assert_eq(get(short, "payload_bytes"), Number(4))
  // Nothing secret-shaped rides along.
  assert_eq(has(short, "secret_hex"), false)
  // A single share is a valid question: two still needed.
  let one = run(
    record([("operation", String("check")), ("shares", Array([shares[2]]))]),
  )
  assert_eq(get(one, "gap"), Number(2))
  assert_eq(get(one, "ready"), Bool(false))
  // Exactly the quorum: ready, and still nothing interpolated.
  let quorum = run(
    record([
      ("operation", String("check")),
      ("shares", Array([shares[1], shares[3], shares[0]])),
    ]),
  )
  assert_eq(get(quorum, "gap"), Number(0))
  assert_eq(get(quorum, "ready"), Bool(true))
  assert_eq(has(quorum, "secret_hex"), false)
  // Over the quorum stays ready with the gap floored at zero.
  let over = run(
    record([("operation", String("check")), ("shares", Array(shares))]),
  )
  assert_eq(get(over, "ready"), Bool(true))
  assert_eq(get(over, "gap"), Number(0))
  // The same refusals by name: a duplicate x, a foreign digest.
  let duplicated = try {
    let _ = run(
      record([
        ("operation", String("check")),
        ("shares", Array([shares[0], shares[0]])),
      ]),
    )
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(duplicated, "duplicate share index: 1")
  let other = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"cafebabf\",\"threshold\":3,\"shares\":5,\"seed\":42}",
      ),
    ),
  )
  let other_shares = match get(other, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let foreign = try {
    let _ = run(
      record([
        ("operation", String("check")),
        ("shares", Array([shares[0], other_shares[1]])),
      ]),
    )
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(foreign, "shares come from different splits")
}

///|
test "split_with_defaults is the one-call split at the default choices" {
  let report = split_with_defaults("cafebabe", 2, 3)
  assert_eq(get(report, "algorithm"), String("shamir-gf256"))
  assert_eq(get(report, "threshold"), Number(2))
  assert_eq(get(report, "shares"), Number(3))
  assert_eq(get(report, "seed"), Number(0))
  assert_eq(get(report, "commit"), String("crc32"))
  assert_eq(get(report, "share_encoding"), String("hex"))
  assert_eq(get(report, "authenticated"), Bool(false))
  // The same answer run gives with the defaults spelled out.
  let spelled = run(
    from_json(
      @json.parse(
        "{\"operation\":\"split\",\"secret_hex\":\"cafebabe\",\"threshold\":2,\"shares\":3,\"seed\":0}",
      ),
    ),
  )
  assert_eq(get(report, "share_list"), get(spelled, "share_list"))
  assert_eq(get(report, "seed_hex"), get(spelled, "seed_hex"))
  // The shares it mints combine like any other split's.
  let shares = match get(report, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  let combined = run(
    record([
      ("operation", String("combine")),
      ("shares", Array([shares[0], shares[2]])),
    ]),
  )
  assert_eq(get(combined, "secret_hex"), String("cafebabe"))
  assert_eq(get(combined, "verified"), Bool(true))
  // Refusals keep their names through the shortcut.
  let refused = try {
    let _ = split_with_defaults("cafebabe", 1, 3)
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(refused, "threshold must be a whole number 2..255")
}

///|
test "quorum_check plans without recovering: gap, excess, quorums, crosscheck" {
  let report = split_with_defaults("cafebabe", 3, 5)
  let shares = match get(report, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  // Two shares of a 3-threshold split: below the quorum, no way to
  // recover, no cross-validation possible - and nothing secret-shaped.
  let short = run(
    record([
      ("operation", String("quorum_check")),
      ("shares", Array([shares[0], shares[4]])),
    ]),
  )
  assert_eq(get(short, "shares"), Number(2))
  assert_eq(get(short, "threshold"), Number(3))
  assert_eq(get(short, "gap"), Number(1))
  assert_eq(get(short, "ready"), Bool(false))
  assert_eq(get(short, "excess"), Number(0))
  assert_eq(get(short, "quorums"), Number(0))
  assert_eq(get(short, "crosscheck_ready"), Bool(false))
  assert_eq(has(short, "secret_hex"), false)
  // The full set: five shares of threshold three form C(5, 3) = 10
  // distinct minimal quorums, two shares beyond the interpolating one.
  let full = run(
    record([
      ("operation", String("quorum_check")),
      ("shares", Array(shares)),
    ]),
  )
  assert_eq(get(full, "gap"), Number(0))
  assert_eq(get(full, "ready"), Bool(true))
  assert_eq(get(full, "excess"), Number(2))
  assert_eq(get(full, "quorums"), Number(10))
  assert_eq(get(full, "crosscheck_ready"), Bool(true))
}

///|
test "quorum counting is exact until 2^53 says stop" {
  assert_eq(quorums_exact(5, 3), Number(10.0))
  assert_eq(quorums_exact(3, 3), Number(1.0))
  assert_eq(quorums_exact(2, 3), Number(0.0))
  assert_eq(quorums_exact(255, 7), Number(12801990477375.0))
  // C(255, 8) is the last exact value at the share ceiling...
  assert_eq(quorums_exact(255, 8), Number(396861704798625.0))
  // ...C(255, 9) is past the integers a double carries exactly, and
  // Null says so instead of approximating.
  assert_eq(quorums_exact(255, 9), Null)
}

///|
test "crosscheck validates the shares beyond the quorum without letting them interpolate" {
  let shares = shamir_split([7, 8, 9, 10], 2, 4, 99, "crc32", [])
  // All four shares: two interpolate, two are evaluated against the
  // polynomial the chosen pair determines - a clean split agrees.
  let clean = shamir_combine_cross(shares, [], true)
  assert_eq(clean.verified, true)
  assert_eq(clean.crosschecked, 2)
  assert_eq(clean.consistent, true)
  assert_eq(clean.suspects, [])
  // One flipped payload byte in an extra share: named, the verdict
  // closes - while the recovery itself came from the untouched quorum.
  let tampered = {
    let copy : Array[Int32] = []
    for byte in shares[3].data {
      copy.push(byte)
    }
    copy[0] = copy[0] ^ 1
    {
      index: shares[3].index,
      threshold: shares[3].threshold,
      digest: shares[3].digest,
      commit: shares[3].commit,
      mac: shares[3].mac,
      data: copy,
    }
  }
  let mixed = shamir_combine_cross(
    [shares[0], shares[1], shares[2], tampered],
    [],
    true,
  )
  assert_eq(mixed.consistent, false)
  assert_eq(mixed.suspects, [4])
  assert_eq(mixed.verified, false)
  assert_eq(mixed.crosschecked, 2)
  // The corrupted share never entered the interpolation: the secret
  // still recovered, from the untouched quorum.
  assert_eq(mixed.recovered, [7, 8, 9, 10])
  // Without the switch, extras are ignored exactly as before - the
  // default behavior is unchanged.
  let plain = shamir_combine_cross(
    [shares[0], shares[1], shares[2], tampered],
    [],
    false,
  )
  assert_eq(plain.verified, true)
  assert_eq(plain.crosschecked, 0)
  assert_eq(plain.suspects, [])
  // Exactly the quorum: crosscheck on, nothing beyond it, consistent
  // vacuously.
  let exact = shamir_combine_cross([shares[0], shares[1]], [], true)
  assert_eq(exact.crosschecked, 0)
  assert_eq(exact.consistent, true)
  assert_eq(exact.verified, true)
}

///|
test "the audit label rides in the report and nowhere else" {
  let report = run(
    record([
      ("operation", String("split")),
      ("secret_hex", String("cafebabe")),
      ("threshold", Number(2)),
      ("shares", Number(3)),
      ("seed", Number(7)),
      ("label", String("Q4 rotation, ticket OPS-114")),
    ]),
  )
  assert_eq(get(report, "label"), String("Q4 rotation, ticket OPS-114"))
  // The shares carry no label: report metadata, not share content.
  let shares = match get(report, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  for share in shares {
    assert_eq(has(share, "label"), false)
  }
  // The same (secret, seed) without a label answers the same shares -
  // the label is not part of the split's determinism.
  let plain = run(
    record([
      ("operation", String("split")),
      ("secret_hex", String("cafebabe")),
      ("threshold", Number(2)),
      ("shares", Number(3)),
      ("seed", Number(7)),
    ]),
  )
  let plain_shares = match get(plain, "share_list") {
    Array(items) => items
    _ => abort("share_list missing")
  }
  assert_eq(shares, plain_shares)
  // An empty label is refused, not defaulted to absent.
  let empty = try {
    let _ = run(
      record([
        ("operation", String("split")),
        ("secret_hex", String("cafebabe")),
        ("threshold", Number(2)),
        ("shares", Number(3)),
        ("label", String("")),
      ]),
    )
    false
  } catch {
    InputError(message) => message == "label must not be empty"
  }
  assert_eq(empty, true)
  // One byte over the ceiling is a refusal that names the bound.
  let mut oversized_label = ""
  for _ in 0..<257 {
    oversized_label = oversized_label + "a"
  }
  let oversized = try {
    let _ = run(
      record([
        ("operation", String("split")),
        ("secret_hex", String("cafebabe")),
        ("threshold", Number(2)),
        ("shares", Number(3)),
        ("label", String(oversized_label)),
      ]),
    )
    false
  } catch {
    InputError(message) => message == "label must stay within 256 bytes"
  }
  assert_eq(oversized, true)
  // Control characters are refused: the label is audit text a human
  // reads, on paper or in a log line.
  let control = try {
    let _ = run(
      record([
        ("operation", String("split")),
        ("secret_hex", String("cafebabe")),
        ("threshold", Number(2)),
        ("shares", Number(3)),
        ("label", String("bad\ngood")),
      ]),
    )
    false
  } catch {
    InputError(message) => message == "label must be printable text"
  }
  assert_eq(control, true)
}

///|
test "per-share ids are stable, distinct and flip-sensitive" {
  let shares = shamir_split([11, 22, 33, 44], 2, 4, 1234, "crc32", [])
  // The same share answers the same id twice, and through a different
  // encoding of itself - the id is the image's, not the payload's.
  let base = share_id(shares[2])
  assert_eq(base.length(), 8)
  assert_eq(share_id(shares[2]), base)
  // Two shares of one split never share an id in practice: the image
  // carries index and payload, and sha256's first 32 bits separate
  // them across generated splits - pairwise, four shares, no set.
  for i in 0..<4 {
    for j in 0..<4 {
      if i != j {
        assert_not_eq(share_id(shares[i]), share_id(shares[j]))
      }
    }
  }
  // One flipped payload byte changes the id.
  let copy : Array[Int32] = []
  for byte in shares[1].data {
    copy.push(byte)
  }
  copy[0] = copy[0] ^ 1
  let flipped = share_id({
    index: shares[1].index,
    threshold: shares[1].threshold,
    digest: shares[1].digest,
    commit: shares[1].commit,
    mac: shares[1].mac,
    data: copy,
  })
  assert_not_eq(flipped, share_id(shares[1]))
  // The boundary reports the ids aligned to canonical index order.
  let report = run(
    record([
      ("operation", String("fingerprint")),
      (
        "shares",
        Array([
          share_to_value_as(shares[3], "hex"),
          share_to_value_as(shares[0], "hex"),
          share_to_value_as(shares[1], "hex"),
        ]),
      ),
    ]),
  )
  let ids = match get(report, "share_ids") {
    Array(items) => items
    _ => abort("share_ids missing")
  }
  assert_eq(ids.length(), 3)
  // Canonical order: indexes 1, 2, 4 - the input order was 4, 1, 2.
  let expected_shares = [shares[0], shares[1], shares[3]]
  for i, entry in ids {
    assert_eq(
      get(entry, "index"),
      Number(expected_shares[i].index.to_double()),
    )
    assert_eq(get(entry, "id"), String(share_id(expected_shares[i])))
  }
}

///|
test "kdf answers its own weakness class" {
  let report = run(
    record([
      ("operation", String("kdf")),
      ("password", String("paper backup")),
      ("salt_hex", String("cafe")),
      ("iterations", Number(1000)),
    ]),
  )
  assert_eq(get(report, "algorithm"), String("pbkdf2-sha256"))
  assert_eq(get(report, "memory_hard"), Bool(false))
}
