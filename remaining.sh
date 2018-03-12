#!/bin/bash

# Set the session length in seconds below; note that 
# this only sets the client-side duration for the MFA 
# session token! The maximum length of a valid session
# is enforced by the IAM policy, and is unaffected by 
# this value (if this duration is set to a longer value
# than the enforcing value in the IAM policy, the token
# will stop working before it expires on the client side).
# Matching this value with the enforcing IAM policy provides
# you with accurate detail about how long a token will
# continue to be valid.
#
# The valid session lengths are from 900 seconds 
# (15 minutes) to 129600 seconds (36 hours);
# currently set (below) to 32400 seconds, or 9 hours.
# 
# **NOTE: THIS SHOULD MATCH THE SETTING IN THE 
#         awscli-mfa.sh SCRIPT!
MFA_SESSION_LENGTH_IN_SECONDS=32400

# defined the standard location of the AWS credentials file
CREDFILE=~/.aws/credentials


# FUNCTIONS

# workaround function for lack of 
# macOS bash's assoc arrays
idxLookup() {
	# $1 is _ret (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	declare -a arr=("${!2}")
	local key=$3
 	local result=""

 	maxIndex=${#arr[@]}
 	((maxIndex--))

	for (( i=0; i<=${maxIndex}; i++ ))
	do 
		if [[ "${arr[$i]}" == "$key" ]]; then
			result=$i
			break
		fi
	done

	eval "$1=$result"
}

# return remaining seconds for the given timestamp;
# uses the MFA_SESSION_LENGTH_IN_SECONDS global var;
# 0 indicates expired, -1 indicates NaN input
getRemaining() {
	# $1 is _ret
	# $2 is the timestamp

	local timestamp=$2
	local this_time=$(date +%s)
	local remaining=0

	if [ ! -z "${timestamp##*[!0-9]*}" ]; then
		let session_end=${timestamp}+${MFA_SESSION_LENGTH_IN_SECONDS}
		if [[ $session_end -gt $this_time ]]; then
			let remaining=${session_end}-${this_time}
		else
			remaining=0
		fi
	else
		remaining=-1
	fi
	eval "$1=${remaining}"
}

# return printable output for given 'remaining' timestamp
# (must be pre-incremented with MFA_SESSION_LENGTH_IN_SECONDS,
# such as getRemaining() output)
getPrintableTimeRemaining() {
	# $1 is _ret
	# $2 is the timestamp

	local timestamp=$2

	case $timestamp in
		-1)
			response="N/A"
			;;
		0)
			response="EXPIRED"
			;;
		*)
			response=$(printf '%02dh:%02dm:%02ds' $(($timestamp/3600)) $(($timestamp%3600/60)) $(($timestamp%60)))
			;;
	esac
	eval "$1=${response}"
}

sessionData() {
	idxLookup idx profiles_key_id[@] $AWS_ACCESS_KEY_ID
	if [ "$idx" = "" ]; then
		if [[ ${AWS_PROFILE} != "" ]]; then
			matched="(not the persistent session)"
		else
			matched="(not a persistent session)"
		fi
	else
		if [[ ${AWS_PROFILE} != "" ]]; then
			matched="(same as the persistent session)"
		else
			matched="(same as the persistent session \"${profiles_ident[$idx]}\")"
		fi
	fi

	[[ ${AWS_PROFILE} == "" ]] && AWS_PROFILE="[unnamed]"

	echo "AWS_PROFILE IN THE ENVIRONMENT: ${AWS_PROFILE} ${matched}"

	if [[ "$AWS_SESSION_INIT_TIME" != "" ]]; then
	
		getRemaining _ret_remaining $AWS_SESSION_INIT_TIME
		getPrintableTimeRemaining _ret ${_ret_remaining}
		if [ "${_ret}" = "EXPIRED" ]; then
			echo "  MFA SESSION EXPIRED; YOU SHOULD PURGE THE ENV BY EXECUTING 'source ./source-to-clear-AWS-envvars.sh'"
		else
			echo "  MFA SESSION REMAINING: ${_ret}"
		fi
	fi
}

# -- end functions --


# COLLECT AWS_SESSION DATA FROM THE ENVIRONMENT
AWS_PROFILE=$(env | grep AWS_PROFILE)
[[ "$AWS_PROFILE" =~ ^AWS_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
	AWS_PROFILE="${BASH_REMATCH[1]}"

AWS_ACCESS_KEY_ID=$(env | grep AWS_ACCESS_KEY_ID)
[[ "$AWS_ACCESS_KEY_ID" =~ ^AWS_ACCESS_KEY_ID[[:space:]]*=[[:space:]]*(.*)$ ]] &&
	AWS_ACCESS_KEY_ID="${BASH_REMATCH[1]}"

AWS_SESSION_TOKEN=$(env | grep AWS_SESSION_TOKEN)
[[ "$AWS_SESSION_TOKEN" =~ ^AWS_SESSION_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]] &&
	AWS_SESSION_TOKEN="${BASH_REMATCH[1]}"

AWS_SESSION_INIT_TIME=$(env | grep AWS_SESSION_INIT_TIME)
[[ "$AWS_SESSION_INIT_TIME" =~ ^AWS_SESSION_INIT_TIME[[:space:]]*=[[:space:]]*(.*)$ ]] &&
	AWS_SESSION_INIT_TIME="${BASH_REMATCH[1]}"

IN_ENV_SESSION_TIME=0
if [[ "$AWS_SESSION_INIT_TIME" != "" ]]; then
	let IN_ENV_SESSION_TIME=${AWS_SESSION_INIT_TIME}+${MFA_SESSION_LENGTH_IN_SECONDS}
	ENV_TIME="true"
else
	ENV_TIME="false"
fi

# COLLECT AWS_SESSION DATA FROM ~/.aws/credentials

# define profiles arrays
declare -a profiles_ident
declare -a profiles_type
declare -a profiles_key_id
declare -a profiles_session_token
declare -a profiles_session_init_time
profiles_iterator=0
profiles_init=0

while IFS='' read -r line || [[ -n "$line" ]]; do
	if [[ "$line" =~ ^\[(.*)\].* ]]; then
		_ret=${BASH_REMATCH[1]}

		if [[ $profiles_init -eq 0 ]]; then
			profiles_ident[$profiles_iterator]=$_ret
			profiles_init=1
		fi

		if [[ "${profiles_ident[$profiles_iterator]}" != "$_ret" ]]; then
			((profiles_iterator++))
			profiles_ident[$profiles_iterator]=$_ret
		fi

		if [[ "$_ret" != "" ]] &&
			! [[ "$_ret" =~ -mfasession$ ]]; then

			profiles_type[$profiles_iterator]='profile'
		else
			profiles_type[$profiles_iterator]='session'
		fi

	fi

	[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_key_id[$profiles_iterator]="${BASH_REMATCH[1]}"

	[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_session_token[$profiles_iterator]="${BASH_REMATCH[1]}"

	[[ "$line" =~ ^aws_session_init_time[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_session_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

echo 
echo

done < $CREDFILE


# lookup AWS_PROFILE, AWS_ACCESS_KEY_ID in ~/.aws/credentials
# -> profile is not found or if AWS_ACCESS_KEY_ID is not in credentials,
# this is an env-only profile (differentiate with TOKEN). For MFA
# sessions calculate remaining time (suggest/provide purge commands
# if expired)

# calculate the remaining session times for the MFA sessions also in 
# the ~/.aws/credentials file

echo
echo "ENVIRONMENT"
echo "-----------"
echo

if [[ "$AWS_PROFILE" != "" ]]; then
	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		sessionData
	else
		echo "AWS_PROFILE SELECTING A PERSISTENT PROFILE: ${AWS_PROFILE}"
	fi
else
	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		sessionData
	else
		echo "NO AWS PROFILE PRESENT IN THE ENVIRONMENT"
	fi
fi

echo
echo
echo "PERSISTENT MFA SESSIONS (in ~/.aws/credentials)"
echo "-----------------------------------------------"
echo

maxIndex=${#profiles_ident[@]}
((maxIndex--))

live_session_counter=0

for (( i=0; i<=${maxIndex}; i++ ))
do 
	if [[ "${profiles_type[$i]}" == "session" ]]; then
		echo "MFA SESSION IDENT: ${profiles_ident[$i]}"
		if [[ "${profiles_session_init_time[$i]}" != "" ]]; then
			getRemaining _ret_remaining ${profiles_session_init_time[$i]}
			getPrintableTimeRemaining _ret ${_ret_remaining}
			if [ "${_ret}" = "EXPIRED" ]; then
				echo "  MFA SESSION EXPIRED"
			else
				((live_session_counter++))
				echo "  MFA SESSION REMAINING: ${_ret}"
			fi
		else
			echo "  no recorded init time (legacy or external init?)"
		fi
		echo
	fi
done

echo 

if [[ "$live_session_counter" -gt 0 ]]; then
	echo "** Execute awscli-mfa.sh to select an active MFA session."
	echo
fi
