#!/bin/sh
usage="usage:  $0 <writefile> <writestr>"
print_error_and_exit()
{
	if [ ! -z error_string ]; then
		echo "$error_string"
	fi
	echo "$usage"
	exit 1
}

if [ -z $1 ]; then
	error_string="writer: writefile not specified"
	print_error_and_exit
fi

if [ -z $2 ]; then
	error_string="writer: writestr not specified"
	print_error_and_exit
fi

mkdir -p $(dirname "$1")

if [ $? -ne 0 ]; then
	error_string="Could not create output directory"
	print_error_and_exit
fi

echo $2 > $1
exit $?
