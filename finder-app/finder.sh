#!/bin/sh
usage="usage:  $0 <filesdir> <searchstr>"
print_error_and_exit()
{
	if [ ! -z error_string ]; then
		echo "$error_string"
	fi
	echo "$usage"
	exit 1
}

if [ -z $1 ]; then
	error_string="finder: Files directory not specified"
	print_error_and_exit
fi
if [ ! -d $1 ]; then
	error_string="finder: Files directory does not exist"
	print_error_and_exit
fi
if [ -z $2 ]; then
	error_string="finder: Search string not specified"
	print_error_and_exit
fi
echo "The number of files are $(ls -1 $1 | wc -l) and the number of matching lines are $(grep -r "$2" $1 | wc -l)"
