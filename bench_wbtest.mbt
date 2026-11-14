///|
test "bench split 1kib threshold 5" (it : @bench.T) {
  let secret : Array[Int32] = []
  for i in 0..<1024 {
    secret.push((i * 37 + 11) % 256)
  }
  it.bench(fn() {
    it.keep(shamir_split(secret, 5, 20, 20261104, "crc32", []).length())
  })
}

///|
test "bench combine 1kib threshold 5" (it : @bench.T) {
  let all = shamir_split(Array::make(1024, 7), 5, 8, 99, "crc32", [])
  let chosen : Array[Share] = []
  for i in 0..<5 {
    chosen.push(all[i])
  }
  it.bench(fn() {
    let verdict = shamir_combine(chosen, []).1 catch { _ => false }
    it.keep(verdict)
  })
}

///|
test "bench reshare 1kib threshold 5" (it : @bench.T) {
  let all = shamir_split(Array::make(1024, 7), 5, 8, 99, "crc32", [])
  let basis : Array[Share] = []
  for i in 0..<5 {
    basis.push(all[i])
  }
  it.bench(fn() {
    it.keep(shamir_reshare(basis, 5, 8, 20261104).length() catch { _ => 0 })
  })
}

///|
test "bench fingerprint 1kib threshold 5" (it : @bench.T) {
  let all = shamir_split(Array::make(1024, 7), 5, 8, 99, "crc32", [])
  it.bench(fn() { it.keep(shamir_fingerprint(all).length() catch { _ => 0 }) })
}

///|
test "bench diagnose threshold 6 of 12 shares" (it : @bench.T) {
  // The enumeration ceiling: C(12, 6) = 924 subsets of an 8-byte
  // secret, one corrupted payload among the twelve - the exact search
  // diagnose exists for, timed at its documented worst shape.
  let all = shamir_split(Array::make(8, 7), 6, 12, 99, "crc32", [])
  let copy : Array[Int32] = []
  for byte in all[11].data {
    copy.push(byte)
  }
  copy[0] = copy[0] ^ 1
  let suspect = {
    index: all[11].index,
    threshold: all[11].threshold,
    digest: all[11].digest,
    commit: all[11].commit,
    mac: all[11].mac,
    data: copy,
  }
  let mixed : Array[Share] = []
  for i in 0..<11 {
    mixed.push(all[i])
  }
  mixed.push(suspect)
  it.bench(fn() {
    let report = shamir_diagnose(mixed, []) catch { _ => record([]) }
    it.keep(get(report, "consistent"))
  })
}
