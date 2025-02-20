# @summary Lazy format function
# Will be evaluated on client side - not during catalog compile on server
# @param format Ruby printf syntax
# @param args arguments passed to sprintf function
# @see https://idiosyncratic-ruby.com/49-what-the-format.html
# @example
#   vault_lookup::fmt("%<x>d + %<y>d = %<z>d", {'x' => 2, 'y' => 2, 'z' => 5})
function vault_lookup::fmt(String $format, Hash $args) >> Deferred {
  Deferred(
    'sprintf',
    [$format, vault_lookup::unwrap($args)]
  )
}
