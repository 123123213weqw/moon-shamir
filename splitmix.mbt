///|
/// SplitMix64, seeded by the caller: a deterministic, non-cryptographic
/// generator whose entire state is one word. The split operation draws its
/// polynomial coefficients from this stream, so the same secret and seed
/// reproduce the same shares bit for bit on every backend. It is not a
/// security primitive: production callers inject a high-entropy seed -
/// entropy, like time in the rest of this family, is injected, never read.
priv struct SplitMix64 {
  mut state : UInt64
}

///|
fn splitmix64(seed : UInt64) -> SplitMix64 {
  { state: seed, }
}

///|
fn SplitMix64::next_u64(self : SplitMix64) -> UInt64 {
  // The mixing constants are the published SplitMix64 constants.
  self.state = self.state + 0x9E3779B97F4A7C15UL
  let mut z = self.state
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL
  z = z ^ (z >> 31)
  z
}

///|
fn SplitMix64::next_byte(self : SplitMix64) -> Int32 {
  (self.next_u64() & 0xFFUL).to_int()
}
