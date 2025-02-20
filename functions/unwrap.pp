# @summary Unwrap for Hash values
# @param $args Hash possibly with Sensitive data
function vault_lookup::unwrap(Hash $args) >> Hash {
  $args.reduce({}) |$res, $item| {
    if $args[$item[0]] =~ Sensitive {
      $res + { $item[0] => unwrap($args[$item[0]]) }
    } else {
      $res + { $item[0] => $args[$item[0]] }
    }
  }
}
