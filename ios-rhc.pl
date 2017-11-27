#!/usr/bin/env perl
use Crypt::PBKDF2;

if (@ARGV < 2 ) {   
   print "[!] Error: please specify hash (first argument) and salt (second argument)\n";
   exit (1); 
}
elsif(length($ARGV[0]) != 40 || length($ARGV[1]) != 8){
   print "[!] Error: please decode salt OR hash\n";
   print "The plist has the fields (salt and hash) base64 encoded, please decode them:\n\n";
   print "\t# echo \"[saltORhash]\" | base64 -D | xxd -p\n\n";
   exit (1); 
} 

my $match = pack ("H*", $ARGV[0]); # TODO: check if it is of length 40 
my $salt  = pack ("H*", $ARGV[1]); # of length 8? 
my $iter  = 1000; 
my $pbkdf2 = Crypt::PBKDF2->new (hash_class => 'HMACSHA1', iterations => $iter);
my $num;
for ($num = 0; $num < 10000; $num++) {
   my $pass = sprintf ("%04d", $num);
   my $hash = $pbkdf2->PBKDF2 ($salt, $pass);
#   printf ("%s:%s:%s:%s\n", unpack ("H*", $hash), unpack ("H*", $salt), $iter, $pass);

   if ($match eq $hash) {
      printf ("\n\n%s:%s:%s:%s\n", unpack ("H*", $hash), unpack ("H*", $salt), $iter, $pass);
      exit (0);
   }
}
exit (1);
