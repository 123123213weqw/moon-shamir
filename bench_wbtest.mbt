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
