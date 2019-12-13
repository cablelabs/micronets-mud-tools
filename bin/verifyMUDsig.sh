#!/bin/bash

function bailout()
{
    local shortname="${0##*/}"
    local message="$1"
    echo "$shortname: error: ${message}"
    exit 1;
}

function bailout_with_usage()
{
    local shortname="${0##*/}"
    local message="$1"
    echo "$shortname: error: ${message}"
    print_usage
    exit 1;
}

function print_usage()
{
    local shortname="${0##*/}"
    echo " "
    echo "Usage: ${shortname} "
    echo "          [--mud-url <MUD file URL>]"
    echo "          [--mud-file <MUD file name>]"
    echo "          [--mud-sig-file <MUD file signature>]"
    echo ""
    echo "       ${shortname} verifies the digital signature of a MUD file"
}

function process_arguments()
{
    shopt -s nullglob

    if [ $# -eq 0 ]; then
	bailout_with_usage "No argument provided"
    fi

    while [[ $1 == --* ]]; do
        if [ "$1" == "--mud-url" ]; then
            shift
            mud_url="$1"
            shift
        elif [ "$1" == "--mud-file" ]; then
            shift
            mud_file="$1"
            shift
        elif [ "$1" == "--mud-sig-file" ]; then
            shift
            mud_sig_file="$1"
            shift
        elif [ "$1" == "--help" ]; then
            print_usage
            exit -1
        else 
            bailout_with_usage "Unrecognized option: $1"
        fi
    done
    
    if [ $# -gt 0 ]; then
	bailout_with_usage "Unrecognized additional arguments: $*"
    fi
}

function download_mud_file()
{

	if [[ ${mud_url} == "" ]]; then
	       return 1
	fi

	mud_file=${mud_url##*/}	
	mud_sig_file=${mud_url##*/}.p7s	

	# delete existing MUD file and the signature file
	rm -f ${mud_file} ${mud_sig_file} > /dev/null 2>&1

	#
	# Download the mud file 
	#
	wget ${mud_url} > /dev/null 2>&1 	
	if [[ $? -ne 0 ]]; then
		return 1
	fi

	#
	# Download the mud signature file 
	#
	wget ${mud_url}.p7s > /dev/null 2>&1 	
	if [[ $? -ne 0 ]]; then
		return 1
	fi

#	echo "mud_file: ${mud_file}"
	return 0
}

#
# verify the MUD file signature 
#
function verify_mud_signature 
{
	#
	# verify MUD file digital signature with the siginer certificate 
	#
	openssl smime -verify -in ${mud_sig_file} -inform DER -content ${mud_file}  > /dev/null 2>&1

	if [[ $? -eq 0 ]]; then
		return  0
	fi
	return  1
}

#
# check command line parameters 
#

#if [[ $# -ne 2 ]]; then
#    echo "Usage: ${shortname} <MUD_file> <MUD_signature_file>"
#    exit 1
#fi

#mud_file=$1
#mud_sig_file=$2

#
# Main()
#

mud_url=""
mud_file=""
mud_sig_file=""

process_arguments "$@"

if [[ ${mud_url} != "" ]]; then
	download_mud_file 
	if [[ $? -ne 0 ]]; then
		exit 1
	fi
fi

#echo ${mud_url}
#echo "mud_file = ${mud_file}"
#echo "mud_sig_file = ${mud_sig_file}"

verify_mud_signature 
if [[ $? -eq 0 ]]; then
	exit 0
fi
exit 1

