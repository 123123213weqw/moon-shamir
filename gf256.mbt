///|
/// Arithmetic in GF(2^8) with the AES polynomial 0x11B. Bytes are carried
/// as Int in 0..255. Subtraction is addition is XOR, which is what makes
/// the Lagrange interpolation in shamir.mbt lose its minus signs: the
/// weight of point i at zero is the product of x_j times the inverse of
/// x_i XOR x_j.

///|
/// Exponent and logarithm tables over generator 3, which has order 255
/// over 0x11B. Multiplication becomes an add of logarithms - the same
/// field through a different construction than shift-and-reduce, and the
/// two are held equal on every input pair by the exhaustive test below.
let gf_exp : FixedArray[Int32] = FixedArray::make(512, 0)

///|
let gf_log : FixedArray[Int32] = FixedArray::make(256, 0)

///|
fn init {
  // Multiply by 3 is x XOR xtime(x), with xtime reducing past 0x100.
  let mut x = 1
  for i in 0..<255 {
    gf_exp[i] = x
    gf_log[x] = i
    let doubled = x << 1
    let reduced = if doubled >= 256 { doubled ^ 0x11B } else { doubled }
    x = x ^ reduced
  }
  for i in 255..<512 {
    gf_exp[i] = gf_exp[i - 255]
  }
}

///|
/// Table multiplication: zero short-circuits because it has no logarithm.
fn gf_mul(left : Int32, right : Int32) -> Int32 {
  if left == 0 || right == 0 {
    0
  } else {
    gf_exp[gf_log[left] + gf_log[right]]
  }
}

///|
/// The shift-and-reduce multiplier the tables were built against, kept as
/// the independent witness for the exhaustive equality test.
fn gf_mul_shift(left : Int32, right : Int32) -> Int32 {
  let mut product = 0
  let mut x = left
  let mut y = right
  while y > 0 {
    if (y & 1) == 1 {
      product = product ^ x
    }
    x = x << 1
    if x >= 256 {
      x = x ^ 0x11B
    }
    y = y >> 1
  }
  product
}

///|
fn gf_pow(base : Int32, exponent : Int32) -> Int32 {
  let mut result = 1
  let mut square = base
  let mut n = exponent
  while n > 0 {
    if (n & 1) == 1 {
      result = gf_mul(result, square)
    }
    square = gf_mul(square, square)
    n = n >> 1
  }
  result
}

///|
/// The multiplicative inverse by Fermat: a^254, valid for every nonzero a.
fn gf_inv(value : Int32) -> Int32 {
  gf_pow(value, 254)
}

///|
/// Horner evaluation of the coefficient list (constant term first) at x.
fn gf_eval(coefficients : Array[Int32], x : Int32) -> Int32 {
  let mut acc = 0
  for i in 0..<coefficients.length() {
    acc = gf_mul(acc, x) ^ coefficients[coefficients.length() - 1 - i]
  }
  acc
}

///|
/// The value at `at` of the unique polynomial through the points, by
/// Lagrange: sum of y_i times the product of (at XOR x_j) / (x_i XOR x_j)
/// over every j other than i. Points must be distinct; at zero the
/// numerators are x_j, which is the constant-term recovery combine uses.
fn gf_interpolate_at(points : Array[(Int32, Int32)], at : Int32) -> Int32 {
  let mut acc = 0
  for i in 0..<points.length() {
    let (xi, yi) = points[i]
    let mut weight = 1
    for j in 0..<points.length() {
      if j != i {
        let (xj, _) = points[j]
        weight = gf_mul(weight, gf_mul(at ^ xj, gf_inv(xi ^ xj)))
      }
    }
    acc = acc ^ gf_mul(yi, weight)
  }
  acc
}

///|
fn gf_interpolate_zero(points : Array[(Int32, Int32)]) -> Int32 {
  gf_interpolate_at(points, 0)
}

///|
/// The Lagrange weights of the points at `at`, computed once: weight_i =
/// product over j != i of (at XOR x_j) / (x_i XOR x_j). With the weights
/// in hand, interpolating any number of byte positions costs k multiplies
/// each instead of k^2 inversions each - the batch shape combine,
/// diagnose and reshare all want.
pub fn gf_lagrange_weights(
  points : Array[(Int32, Int32)],
  at : Int32,
) -> Array[Int32] {
  let weights : Array[Int32] = []
  for i in 0..<points.length() {
    let (xi, _) = points[i]
    let mut weight = 1
    for j in 0..<points.length() {
      if j != i {
        let (xj, _) = points[j]
        weight = gf_mul(weight, gf_mul(at ^ xj, gf_inv(xi ^ xj)))
      }
    }
    weights.push(weight)
  }
  weights
}

///|
/// Interpolate with precomputed weights: sum of y_i times weight_i, all
/// additions being XOR.
pub fn gf_interpolate_weighted(
  points : Array[(Int32, Int32)],
  weights : Array[Int32],
) -> Int32 {
  let mut acc = 0
  for i in 0..<points.length() {
    acc = acc ^ gf_mul(points[i].1, weights[i])
  }
  acc
}

///|
test "batched weights interpolate identically" {
  // Three random-ish polynomials through the same point set: direct and
  // batched paths must agree at zero and at a nonzero point.
  let points : Array[(Int32, Int32)] = [(1, 87), (4, 202), (9, 14), (77, 231)]
  for at in [0, 2, 255] {
    let direct = gf_interpolate_at(points, at)
    let weights = gf_lagrange_weights(points, at)
    assert_eq(gf_interpolate_weighted(points, weights), direct)
  }
  // Weights are position-only: same x's, different y's, same weights.
  let moved : Array[(Int32, Int32)] = [(1, 5), (4, 6), (9, 7), (77, 8)]
  let a = gf_lagrange_weights(points, 3)
  let b = gf_lagrange_weights(moved, 3)
  assert_eq(a, b)
}

///|
test "gf256 field laws" {
  // Every nonzero element has an inverse; a * inv(a) == 1.
  for a in 1..<256 {
    assert_eq(gf_mul(a, gf_inv(a)), 1)
  }
  // Multiplication is commutative and distributive over XOR on samples.
  assert_eq(gf_mul(53, 203), gf_mul(203, 53))
  assert_eq(gf_mul(7, 11 ^ 29), gf_mul(7, 11) ^ gf_mul(7, 29))
  // A polynomial evaluated at zero is its constant term.
  assert_eq(gf_eval([19, 200, 3], 0), 19)
  // Interpolation recovers the constant term from k points of a degree
  // k-1 polynomial.
  let coefficients : Array[Int32] = [42, 123, 217]
  let points : Array[(Int32, Int32)] = []
  for x in [1, 2, 3] {
    points.push((x, gf_eval(coefficients, x)))
  }
  assert_eq(gf_interpolate_zero(points), 42)
  // Extra points beyond the degree still land on the same polynomial.
  points.push((4, gf_eval(coefficients, 4)))
  assert_eq(gf_interpolate_zero(points), 42)
}

///|
test "table and shift multipliers agree on every pair" {
  // All 65536 input pairs: the two constructions of the field must agree
  // everywhere, and the table's generator must really have order 255.
  for a in 0..<256 {
    for b in 0..<256 {
      assert_eq(gf_mul(a, b), gf_mul_shift(a, b))
    }
  }
  assert_eq(gf_exp[0], 1)
  assert_eq(gf_exp[254] != 1, true)
  assert_eq(gf_exp[255], 1)
  for v in 1..<256 {
    assert_eq(gf_exp[gf_log[v]], v)
  }
}
