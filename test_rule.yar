rule test {

 strings:
  // just a random string that's unlikely to be found in any benign program
  $random_string = "Ex5DjFPVS9ryKVTEOAxKqqXIUl9RFtG9BxarO6tZ3gndIqqZon6LoR5JMyxiU8xi"
 condition:
  any of them

}
