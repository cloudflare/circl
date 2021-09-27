!/^#/{split($0, a, ":"); print "::error file="a[1]",line="a[2]",col="a[3]"::"a[4]} END{if(NR!=0) exit 1}
