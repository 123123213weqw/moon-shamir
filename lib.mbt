///|
pub fn matches(pattern : String, text : String) -> Bool raise {
  let regex = @string.Regex::Regex(pattern)
  match regex.execute(text) {
    Some(_) => true
    None => false
  }
}
