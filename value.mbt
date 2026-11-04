///|
/// A JSON-shaped semantic value. Requests and reports travel as these; object
/// key order is never significant, and numbers are finite doubles.
pub(all) enum Value {
  Null
  Bool(Bool)
  Number(Double)
  String(String)
  Array(Array[Value])
  Object(Map[String, Value])
} derive(Eq, @debug.Debug)

///|
pub extend Value with Eq::{equal, not_equal}

///|
pub extend Value with @debug.Debug::{to_repr}

///|
pub fn from_json(value : Json) -> Value {
  match value {
    Json::Null => Null
    Json::True => Bool(true)
    Json::False => Bool(false)
    Json::Number(n, ..) => Number(n)
    Json::String(s) => String(s)
    Json::Array(items) => Array(items.map(from_json))
    Json::Object(fields) => Object(fields.map(fn(_, v) { from_json(v) }))
  }
}

///|
pub fn Value::to_json(self : Value) -> Json {
  match self {
    Null => Json::null()
    Bool(b) => Json::boolean(b)
    Number(n) => Json::number(n)
    String(s) => Json::string(s)
    Array(items) => Json::array(items.map(fn(v) { v.to_json() }))
    Object(fields) => Json::object(fields.map(fn(_, v) { v.to_json() }))
  }
}

///|
pub(all) suberror InputError {
  InputError(String)
} derive(Eq, @debug.Debug)

///|
pub extend InputError with Eq::{equal, not_equal}

///|
pub extend InputError with @debug.Debug::{to_repr}

///|
pub impl Show for InputError with fn output(self, logger) {
  let InputError(message) = self
  logger.write_string(message)
}

///|
pub extend InputError with Show::{to_string, output}

///|
pub fn get(value : Value, key : String) -> Value {
  match value {
    Object(fields) => fields.get(key).unwrap_or(Null)
    _ => Null
  }
}

///|
pub fn has(value : Value, key : String) -> Bool {
  match value {
    Object(fields) => fields.contains(key)
    _ => false
  }
}

///|
pub fn required(value : Value, key : String) -> Value raise InputError {
  if !has(value, key) {
    raise InputError("missing field: " + key)
  }
  get(value, key)
}

///|
pub fn str(value : Value) -> String raise InputError {
  match value {
    String(s) => s
    _ => raise InputError("expected string")
  }
}

///|
pub fn arr(value : Value) -> Array[Value] raise InputError {
  match value {
    Array(items) => items
    _ => raise InputError("expected array")
  }
}

///|
pub fn num(value : Value) -> Double raise InputError {
  match value {
    Number(n) if !n.is_nan() && !n.is_inf() => n
    _ => raise InputError("expected finite number")
  }
}

///|
pub fn record(fields : Array[(String, Value)]) -> Value {
  let result : Map[String, Value] = Map([])
  for (key, value) in fields {
    result[key] = value
  }
  Object(result)
}

///|
pub fn fields_only(
  value : Value,
  allowed : Array[String],
) -> Unit raise InputError {
  let fields = match value {
    Object(fields) => fields
    _ => raise InputError("expected object")
  }
  for key, _ in fields {
    if !allowed.contains(key) {
      raise InputError("unknown field: " + key)
    }
  }
}

///|
/// The value of one hex digit code point, or None when it is not one.
/// '0'-'9' are 0..9; 'a'-'f' and 'A'-'F' fold onto 10..15.
fn hex_digit_value(digit : Char) -> Int32? {
  let code = digit.to_int()
  if code >= 48 && code <= 57 {
    Some(code - 48)
  } else if code >= 97 && code <= 102 {
    Some(code - 87)
  } else if code >= 65 && code <= 70 {
    Some(code - 55)
  } else {
    None
  }
}

///|
/// Hex decode with an exact, named refusal: even length, digits only.
fn parse_hex(text : String) -> Array[Int32] raise InputError {
  if text.length() % 2 != 0 {
    raise InputError("hex string must have an even number of digits")
  }
  let out : Array[Int32] = []
  let chars = text.to_array()
  let half = chars.length() / 2
  for i in 0..<half {
    let hi = hex_digit_value(chars[i * 2])
    let lo = hex_digit_value(chars[i * 2 + 1])
    match (hi, lo) {
      (Some(h), Some(l)) => out.push(h * 16 + l)
      _ =>
        raise InputError(
          "hex string may contain digits and a-f only, found an invalid digit",
        )
    }
  }
  out
}

///|
fn to_hex(bytes : Array[Int32]) -> String {
  let digits = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
  ]
  let mut out = ""
  for byte in bytes {
    out = out + digits[(byte >> 4) & 0xF]
    out = out + digits[byte & 0xF]
  }
  out
}

///|
test "hex round trips and refuses junk" {
  assert_eq(to_hex([0, 15, 16, 255]), "000f10ff")
  assert_eq(parse_hex("000f10ff"), [0, 15, 16, 255])
  assert_eq(parse_hex("000F10FF"), [0, 15, 16, 255])
  let odd = try {
    let _ = parse_hex("abc")
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(odd, "hex string must have an even number of digits")
  let junk = try {
    let _ = parse_hex("zz")
    "no error"
  } catch {
    InputError(message) => message
  }
  assert_eq(
    junk, "hex string may contain digits and a-f only, found an invalid digit",
  )
}
