///|
test "regex semantics" {
  assert_true(matches("^[a-z]+$", "abc"))
  assert_false(matches("^[a-z]+$", "abc1"))
  assert_true(matches("[0-9]{2,4}", "x123y"))
  assert_false(matches("^[0-9]{2,4}$", "x123y"))
  assert_true(matches("^(dev|prod)$", "prod"))
  assert_true(matches("\\d+\\.\\d+", "v1.25"))
  assert_true(matches("^\\w+@\\w+\\.example$", "ops@acme.example"))
  assert_true(matches("é|键", "x键"))
  let bad = try { ignore(matches("(unclosed", "x")); false } catch { _ => true }
  assert_true(bad)
}
