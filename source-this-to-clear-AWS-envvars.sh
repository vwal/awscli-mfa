#!/bin/bash

if [ "$0" = "$BASH_SOURCE" ]; then
	echo
	echo "You must source this script to clear the AWS environment variables, like so:"
	echo
	echo "source ./source-to-clear-AWS-envvars.sh"
	echo

	exit 1
fi

unset AWS_ACCESS_KEY_ID
unset AWS_CA_BUNDLE
unset AWS_DEFAULT_OUTPUT
unset AWS_DEFAULT_REGION
unset AWS_PROFILE
unset AWS_PROFILE_IDENT
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_EXPIRY
unset AWS_SESSION_IDENT
unset AWS_SESSION_TOKEN
unset AWS_SESSION_TYPE

#todo: detect if these are active in the environment, 
#      if so, print a notice that they were NOT unset
#      
# AWS_CONFIG_FILE
# AWS_SHARED_CREDENTIALS_FILE
