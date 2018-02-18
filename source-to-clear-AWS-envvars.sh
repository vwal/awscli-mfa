#!/bin/bash

if [ "$0" = "$BASH_SOURCE" ]; then
	echo
	echo "You must source this script to clear the AWS environment variables, like so:"
	echo
	echo "source ./clear-aws.sh"
	echo
fi

unset AWS_PROFILE
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
