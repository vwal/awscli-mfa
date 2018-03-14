#!/usr/bin/env bash

DEBUG="false"
# uncomment below to enable the debug output
#DEBUG="true"

# Set the global session length in seconds below; note that 
# this only sets the client-side duration for the MFA session 
# token! The maximum length of a valid session is enforced by 
# the IAM policy, and is unaffected by this value (if this
# duration is set to a longer value than the enforcing value
# in the IAM policy, the token will stop working before it 
# expires on the client side). Matching this value with the 
# enforcing IAM policy provides you with accurate detail 
# about how long a token will continue to be valid.
# 
# THIS VALUE CAN BE OPTIONALLY OVERRIDDEN PER EACH PROFILE
# BY ADDING A "mfasec" ENTRY FOR THE PROFILE IN ~/.aws/config
#
# The valid session lengths are from 900 seconds (15 minutes)
# to 129600 seconds (36 hours); currently set (below) to
# 32400 seconds, or 9 hours.
MFA_SESSION_LENGTH_IN_SECONDS=32400

# define the standard location of the AWS credentials and config files
CONFFILE=~/.aws/config
CREDFILE=~/.aws/credentials

## FUNCTIONS

# `exists` for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

# precheck envvars for existing/stale session definitions
checkEnvSession() {
	# $1 is the check type
	
	local check_type=$1
	local this_time=$(date +%s)

	# COLLECT AWS_SESSION DATA FROM THE ENVIRONMENT
	PRECHECK_AWS_PROFILE=$(env | grep AWS_PROFILE)
	[[ "$PRECHECK_AWS_PROFILE" =~ ^AWS_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_PROFILE="${BASH_REMATCH[1]}"

	PRECHECK_AWS_ACCESS_KEY_ID=$(env | grep AWS_ACCESS_KEY_ID)
	[[ "$PRECHECK_AWS_ACCESS_KEY_ID" =~ ^AWS_ACCESS_KEY_ID[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_ACCESS_KEY_ID="${BASH_REMATCH[1]}"

	PRECHECK_AWS_SECRET_ACCESS_KEY=$(env | grep AWS_SECRET_ACCESS_KEY)
	[[ "$PRECHECK_AWS_SECRET_ACCESS_KEY" =~ ^AWS_SECRET_ACCESS_KEY[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SECRET_ACCESS_KEY="[REDACTED]"

	PRECHECK_AWS_SESSION_TOKEN=$(env | grep AWS_SESSION_TOKEN)
	[[ "$PRECHECK_AWS_SESSION_TOKEN" =~ ^AWS_SESSION_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_TOKEN="[REDACTED]"

	PRECHECK_AWS_SESSION_INIT_TIME=$(env | grep AWS_SESSION_INIT_TIME)
	[[ "$PRECHECK_AWS_SESSION_INIT_TIME" =~ ^AWS_SESSION_INIT_TIME[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_INIT_TIME="${BASH_REMATCH[1]}"

	PRECHECK_AWS_SESSION_DURATION=$(env | grep AWS_SESSION_DURATION)
	[[ "$PRECHECK_AWS_SESSION_DURATION" =~ ^AWS_SESSION_DURATION[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_DURATION="${BASH_REMATCH[1]}"

	PRECHECK_AWS_DEFAULT_REGION=$(env | grep AWS_DEFAULT_REGION)
	[[ "$PRECHECK_AWS_DEFAULT_REGION" =~ ^AWS_DEFAULT_REGION[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_DEFAULT_REGION="${BASH_REMATCH[1]}"

	PRECHECK_AWS_DEFAULT_OUTPUT=$(env | grep AWS_DEFAULT_OUTPUT)
	[[ "$PRECHECK_AWS_DEFAULT_OUTPUT" =~ ^AWS_DEFAULT_OUTPUT[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_DEFAULT_OUTPUT="${BASH_REMATCH[1]}"

	PRECHECK_AWS_CA_BUNDLE=$(env | grep AWS_CA_BUNDLE)
	[[ "$PRECHECK_AWS_CA_BUNDLE" =~ ^AWS_CA_BUNDLE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_CA_BUNDLE="${BASH_REMATCH[1]}"

	PRECHECK_AWS_SHARED_CREDENTIALS_FILE=$(env | grep AWS_SHARED_CREDENTIALS_FILE)
	[[ "$PRECHECK_AWS_SHARED_CREDENTIALS_FILE" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SHARED_CREDENTIALS_FILE="${BASH_REMATCH[1]}"

	PRECHECK_AWS_CONFIG_FILE=$(env | grep AWS_CONFIG_FILE)
	[[ "$PRECHECK_AWS_CONFIG_FILE" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_CONFIG_FILE="${BASH_REMATCH[1]}"

	# makes sure that the MFA session has not expired (whether it's defined 
	# in the environment or in ~/.aws/credentials)
	if [[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
		[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]]; then
		
		getRemaining _ret $PRECHECK_AWS_SESSION_INIT_TIME $PRECHECK_AWS_SESSION_DURATION
		[[ "${_ret}" -eq 0 ]] && continue_maybe
	
	elif [[ "$PRECHECK_AWS_PROFILE" =~ -mfasession$ ]]; then
		# find the profile's init time entry if one exists
		idxLookup idx profiles_ident[@] $PRECHECK_AWS_PROFILE
		profile_time=${profiles_session_init_time[$idx]}

		getDuration parent_duration $PRECHECK_AWS_PROFILE

		if [[ "$profile_time" != "" ]]; then
			getRemaining _ret $profile_time $parent_duration
			[[ "${_ret}" -eq 0 ]] && continue_maybe
		fi
	fi

	# detect and print informative notice of 
	# effective AWS envvars
	if [[ "${AWS_PROFILE}" != "" ]] ||
		[[ "${AWS_ACCESS_KEY_ID}" != "" ]] ||
		[[ "${AWS_SECRET_ACCESS_KEY}" != "" ]] ||
		[[ "${AWS_SESSION_TOKEN}" != "" ]] ||
		[[ "${AWS_SESSION_INIT_TIME}" != "" ]] ||
		[[ "${AWS_SESSION_DURATION}" != "" ]] ||
		[[ "${AWS_DEFAULT_REGION}" != "" ]] ||
		[[ "${AWS_DEFAULT_OUTPUT}" != "" ]] ||
		[[ "${AWS_CA_BUNDLE}" != "" ]] ||
		[[ "${AWS_SHARED_CREDENTIALS_FILE}" != "" ]] ||
		[[ "${AWS_CONFIG_FILE}" != "" ]]; then

			echo
			echo "** NOTE: SOME AWS_* ENVIRONMENT VARIABLES ARE CURRENTLY IN EFFECT:"
			[[ "$PRECHECK_AWS_PROFILE" != "" ]] && echo "AWS_PROFILE: $PRECHECK_AWS_PROFILE"
			[[ "$PRECHECK_AWS_ACCESS_KEY_ID" != "" ]] && echo "AWS_ACCESS_KEY_ID: $PRECHECK_AWS_ACCESS_KEY_ID"
			[[ "$PRECHECK_AWS_SECRET_ACCESS_KEY" != "" ]] && echo "AWS_SECRET_ACCESS_KEY: $PRECHECK_AWS_SECRET_ACCESS_KEY"
			[[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] && echo "AWS_SESSION_TOKEN: $PRECHECK_AWS_SESSION_TOKEN"
			[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]] && echo "AWS_SESSION_INIT_TIME: $PRECHECK_AWS_SESSION_INIT_TIME"
			[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]] && echo "AWS_SESSION_DURATION: $PRECHECK_AWS_SESSION_DURATION"
			[[ "$PRECHECK_AWS_DEFAULT_REGION" != "" ]] && echo "AWS_DEFAULT_REGION: $PRECHECK_AWS_DEFAULT_REGION"
			[[ "$PRECHECK_AWS_DEFAULT_OUTPUT" != "" ]] && echo "AWS_DEFAULT_OUTPUT: $PRECHECK_AWS_DEFAULT_OUTPUT"
			[[ "$PRECHECK_AWS_CA_BUNDLE" != "" ]] && echo "AWS_CA_BUNDLE: $PRECHECK_AWS_CA_BUNDLE"
			[[ "$PRECHECK_AWS_SHARED_CREDENTIALS_FILE" != "" ]] && echo "AWS_SHARED_CREDENTIALS_FILE: $PRECHECK_AWS_SHARED_CREDENTIALS_FILE"
			[[ "$PRECHECK_AWS_CONFIG_FILE" != "" ]] && echo "AWS_CONFIG_FILE: $PRECHECK_AWS_CONFIG_FILE"
			echo
	fi

}

# workaround function for lack of 
# macOS bash's assoc arrays
idxLookup() {
	# $1 is _ret (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	declare -a arr=("${!2}")
	local key=$3
 	local result=""
 	local maxIndex

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

# save the MFA session initialization timestamp
# in the session profile in ~/.aws/credentials
addInitTime() {
	# $1 is the profile (ident)

	this_ident=$1
	this_time=$(date +%s)

	# find the selected profile's existing
	# init time entry if one exists
	getInitTime _ret "$this_ident"
	profile_time=${_ret}

	# update/add session init time
	if [[ $profile_time != "" ]]; then
		# time entry exists for the profile, update
		sed -i '' -e "s/${profile_time}/${this_time}/g" $CREDFILE
	else
		# no time entry exists for the profile; add on a new line after the header "[${this_ident}]"
		replace_me="\[${this_ident}\]"
		DATA="[${this_ident}]\naws_session_init_time = ${this_time}"
		echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'$replace_me'/,var)}1' $CREDFILE)" > $CREDFILE
	fi

	# update the selected profile's existing
	# init time entry in this script
	profiles_session_init_time[$idx]=$this_time
}

# return the MFA session init time for the given profile
getInitTime() {
	# $1 is _ret
	# $2 is the profile ident

	local this_ident=$2
	local profile_time

	# find the profile's init time entry if one exists
	idxLookup idx profiles_ident[@] $this_ident
	profile_time=${profiles_session_init_time[$idx]}

	eval "$1=${profile_time}"
}

getDuration() {
	# $1 is _ret
	# $2 is the profile ident

	local this_profile_ident=$2
	local this_duration

	# use parent profile ident if this is an MFA session
	[[ "$this_profile_ident" =~ ^(.*)-mfasession$ ]] &&
		this_profile_ident="${BASH_REMATCH[1]}"

	# look up possible custom duration for the parent profile
	idxLookup idx confs_ident[@] $this_profile_ident

	[[ $idx != "" && "${confs_mfasec[$idx]}" != "" ]] && 
		this_duration=${confs_mfasec[$idx]}  ||
		this_duration=$MFA_SESSION_LENGTH_IN_SECONDS

	eval "$1=${this_duration}"
}

# Returns remaining seconds for the given timestamp;
# if the custom duration is not provided, the global
# duration setting is used). In the result
# 0 indicates expired, -1 indicates NaN input
getRemaining() {
	# $1 is _ret
	# $2 is the timestamp
	# $3 is the duration

	local timestamp=$2
	local duration=$3
	local this_time=$(date +%s)
	local remaining=0

	[[ "${duration}" == "" ]] &&
		duration=$MFA_SESSION_LENGTH_IN_SECONDS

	if [ ! -z "${timestamp##*[!0-9]*}" ]; then
		let session_end=${timestamp}+${duration}
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
# (must be pre-incremented with profile duration,
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

continue_maybe() {
	echo -e "\nTHE MFA SESSION SELECTED IN THE ENVIRONMENT (${PRECHECK_AWS_PROFILE}) HAS EXPIRED.\n"
	read -s -p "Do you want to continue with the default profile? - [Y]n " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]] ||
		[[ $REPLY == "" ]]; then

		unset AWS_PROFILE
		unset AWS_ACCESS_KEY_ID
		unset AWS_SECRET_ACCESS_KEY
		unset AWS_SESSION_TOKEN
		unset AWS_SESSION_INIT_TIME
		unset AWS_SESSION_DURATION
		unset AWS_DEFAULT_REGION
		unset AWS_DEFAULT_OUTPUT
		unset AWS_CA_BUNDLE
		unset AWS_SHARED_CREDENTIALS_FILE
		unset AWS_CONFIG_FILE

		use_profile='--profile default'
	else
		echo -e "\n\nExecute \"source ./source-to-clear-AWS-envvars.sh\", and try again to proceed.\n"
		exit 1
	fi
}

## PREREQUISITES CHECK

# is AWS CLI installed?
if ! exists aws ; then
	printf "\n******************************************************************************************************************************\n\
This script requires the AWS CLI. See the details here: http://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html\n\
******************************************************************************************************************************\n\n"
	exit 1
fi 

# check for ~/.aws directory, and ~/.aws/{config|credentials} files
if [ ! -d ~/.aws ]; then
	echo
	echo -e "'~/.aws' directory not present.\nMake sure it exists, and that you have at least one profile configured\nusing the 'config' and 'credentials' files within that directory."
	echo
	exit 1
fi

if [[ ! -f ~/.aws/config && ! -f ~/.aws/credentials ]]; then
	echo
	echo -e "'~/.aws/config' and '~/.aws/credentials' files not present.\nMake sure they exist. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
elif [ ! -f ~/.aws/config ]; then
	echo
	echo -e "'~/.aws/config' file not present.\nMake sure it and '~/.aws/credentials' files exists. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
elif [ ! -f ~/.aws/credentials ]; then
	echo
	echo -e "'~/.aws/credentials' file not present.\nMake sure it and '~/.aws/config' files exists. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
fi

# read the credentials file and make sure that at least one profile is configured
ONEPROFILE="false"
while IFS='' read -r line || [[ -n "$line" ]]; do
	[[ "$line" =~ ^\[(.*)\].* ]] &&
		profile_ident=${BASH_REMATCH[1]}

		if [ $profile_ident != "" ]; then
			ONEPROFILE="true"
		fi 
done < $CREDFILE

if [[ "$ONEPROFILE" == "false" ]]; then
	echo
	echo -e "NO CONFIGURED AWS PROFILES FOUND.\nPlease make sure you have '~/.aws/config' (profile configurations),\nand '~/.aws/credentials' (profile credentials) files, and at least\none configured profile. For more info, see AWS CLI documentation at:\nhttp://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html"
	echo

else

	# get default region and output format
	# (since at least one profile should exist at this point, and one should be selected)
	default_region=$(aws --profile default configure get region)
	default_output=$(aws --profile default configure get output)

	if [[ "$default_region" == "" ]]; then
		echo
		echo -e "DEFAULT REGION HAS NOT BEEN CONFIGURED.\nPlease set the default region in '~/.aws/config', for example, like so:\naws configure set region \"us-east-1\""
		echo
		exit 1
	fi

	if [[ "$default_output" == "" ]]; then
		aws configure set output "table"
	fi

	# Check OS for some supported platforms
	OS="`uname`"
	case $OS in
		'Linux')
			OS='Linux'
			;;
		'Darwin') 
			OS='macOS'
			;;
		*) 
			OS='unknown'
			echo
			echo "** NOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM."
			echo
			;;
	esac

	# make sure ~/.aws/credentials has a linefeed in the end
	c=$(tail -c 1 "$CREDFILE")
	if [ "$c" != "" ]; then
		echo "" >> "$CREDFILE"
	fi

	## FUNCTIONAL PREREQS PASSED; PROCEED WITH EXPIRED SESSION CHECK
	## AMD CUSTOM CONFIGURATION/PROPERTY READ-IN

	# define profiles arrays, variables
	declare -a profiles_ident
	declare -a profiles_type
	declare -a profiles_key_id
	declare -a profiles_secret_key
	declare -a profiles_session_token
	declare -a profiles_session_init_time
	persistent_MFA="false"
	profiles_iterator=0
	profiles_init=0
	use_profile=""

	# ugly hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			_ret=${BASH_REMATCH[1]}

			if [[ $profiles_init -eq 0 ]]; then
				profiles_ident[$profiles_iterator]=$_ret
				profiles_init=1
			fi

			if [[ "$_ret" != "" ]] &&
				! [[ "$_ret" =~ -mfasession$ ]]; then

				profiles_type[$profiles_iterator]='profile'
			else
				profiles_type[$profiles_iterator]='session'
			fi

			if [[ "${profiles_ident[$profiles_iterator]}" != "$_ret" ]]; then
				((profiles_iterator++))
				profiles_ident[$profiles_iterator]=$_ret
			fi
		fi

		[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_key_id[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_secret_key[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_session_token[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^aws_session_init_time[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_session_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

	done < $CREDFILE


	# init arrays to hold ident<->mfasec detail
	declare -a confs_ident
	declare -a confs_mfasec
	confs_init=0
	confs_iterator=0

	# read the config file for the optional MFA length param (MAXSEC)
	while IFS='' read -r line || [[ -n "$line" ]]; do

		[[ "$line" =~ ^\[[[:space:]]*profile[[:space:]]*(.*)[[:space:]]*\].* ]] && 
			this_conf_ident=${BASH_REMATCH[1]}

		[[ "$line" =~ ^[[:space:]]*mfasec[[:space:]]*=[[:space:]]*(.*)$ ]] && 
			this_conf_mfasec=${BASH_REMATCH[1]}

		if [[ "$this_conf_mfasec" != "" ]]; then
			confs_ident[$confs_iterator]=$this_conf_ident
			confs_mfasec[$confs_iterator]=$this_conf_mfasec

			((confs_iterator++))
		fi

		this_conf_mfasec=""

	done < $CONFFILE

	# make sure environment doesn't have a stale session before we start
	checkEnvSession "init"

	echo
	current_aws_access_key_id="$(aws configure get aws_access_key_id)"

	idxLookup idx profiles_key_id[@] $current_aws_access_key_id

	if [[ $idx != "" ]]; then 
		currently_selected_profile_ident="${profiles_ident[$idx]}"
	else
		currently_selected_profile_ident="unknown"
	fi

	process_user_arn="$(aws $use_profile sts get-caller-identity --output text --query 'Arn' 2>&1)"

	[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
		process_username="${BASH_REMATCH[1]}"

	if [[ "$process_username" =~ ExpiredToken ]]; then
		continue_maybe

		currently_selected_profile_ident="default"
		process_user_arn="$(aws $use_profile sts get-caller-identity --output text --query 'Arn' 2>&1)"

		[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
			process_username="${BASH_REMATCH[1]}"
	fi

	if [[ "$process_username" =~ error ]] ||
		[[ "$currently_selected_profile_ident" == "unknown" ]]; then
		echo -e "The selected profile is not functional; please check the \"default\" profile\nin your '~/.aws/credentials' file, as well as any 'AWS_' environment variables!"
		exit 1
	else
		echo
		echo
		echo "Executing this script as the AWS/IAM user \"$process_username\" (profile \"$currently_selected_profile_ident\")."
	fi

	echo		

	# declare the arrays for credentials loop
	declare -a cred_profiles
	declare -a cred_profile_status
	declare -a cred_profile_user
	declare -a cred_profile_arn
	declare -a profile_region
	declare -a profile_output
	declare -a mfa_profiles
	declare -a mfa_arns
	declare -a mfa_profile_status
	declare -a mfa_mfasec
	cred_profilecounter=0

	echo -n "Please wait"

	# read the credentials file
	while IFS='' read -r line || [[ -n "$line" ]]; do
		
		[[ "$line" =~ ^\[(.*)\].* ]] && 
			profile_ident=${BASH_REMATCH[1]}

		# transfer possible MFA mfasec from config array 
		idxLookup idx confs_ident[@] $profile_ident
		if [[ $idx != "" ]]; then
			mfa_mfasec[$cred_profilecounter]=${confs_mfasec[$idx]}
		fi

		# only process if profile identifier is present,
		# and if it's not a mfasession profile 
		# (mfasession profiles have '-mfasession' postfix)
		if [[ "$profile_ident" != "" ]] &&
			! [[ "$profile_ident" =~ -mfasession$ ]]; then

			# store this profile ident
			cred_profiles[$cred_profilecounter]=$profile_ident

			# store this profile region and output format
			profile_region[$cred_profilecounter]=$(aws --profile $profile_ident configure get region)
			profile_output[$cred_profilecounter]=$(aws --profile $profile_ident configure get output)

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws sts get-caller-identity --profile $profile_ident --output text --query 'Arn' 2>&1)"
			if [[ "$user_arn" =~ ^arn:aws ]]; then
				cred_profile_arn[$cred_profilecounter]=$user_arn
			else
				# must be a bad profile
				cred_profile_arn[$cred_profilecounter]=""
			fi

			# get the actual username
			# (may be different from the arbitrary profile ident)
			[[ "$user_arn" =~ ([^/]+)$ ]] &&
				profile_username="${BASH_REMATCH[1]}"
			if [[ "$profile_username" =~ error ]]; then
				cred_profile_user[$cred_profilecounter]=""
			else
				cred_profile_user[$cred_profilecounter]="$profile_username"
			fi

			# find the MFA session for the current profile if one exists ("There can be only one")
			# (profile with profilename + "-mfasession" postfix)
			while IFS='' read -r line || [[ -n "$line" ]]; do
				[[ "$line" =~ \[(${profile_ident}-mfasession)\]$ ]] &&
				mfa_profile_ident="${BASH_REMATCH[1]}"
			done < $CREDFILE
			mfa_profiles[$cred_profilecounter]="$mfa_profile_ident"

			# check to see if this profile has access currently
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set, this should produce
			# a reasonably reliable result)
			profile_check="$(aws iam get-user --output text --query "User.Arn" --profile $profile_ident 2>&1)"
			if [[ "$profile_check" =~ ^arn:aws ]]; then
				cred_profile_status[$cred_profilecounter]="OK"
			else
				cred_profile_status[$cred_profilecounter]="LIMITED"
			fi

			# get MFA ARN if available
			# (obviously not available if a MFA device
			# isn't configured for the profile)
			mfa_arn="$(aws iam list-mfa-devices --profile $profile_ident --user-name ${cred_profile_user[$cred_profilecounter]} --output text --query "MFADevices[].SerialNumber" 2>&1)"
			if [[ "$mfa_arn" =~ ^arn:aws ]]; then
				mfa_arns[$cred_profilecounter]="$mfa_arn"
			else
				mfa_arns[$cred_profilecounter]=""
			fi

			# If an existing MFA profile was found, check its status
			# (uses timestamps first if available; falls back to
			# less reliable get-user command -- its output depends
			# on IAM policy settings, and while it's usually accurate
			# it's still not reliable)
			if [ "$mfa_profile_ident" != "" ]; then

				getInitTime _ret_timestamp "$mfa_profile_ident"
				getDuration _ret_duration "$mfa_profile_ident"
				getRemaining _ret_remaining ${_ret_timestamp} ${_ret_duration}

				if [[ ${_ret_remaining} -eq 0 ]]; then
					# session has expired

					mfa_profile_status[$cred_profilecounter]="EXPIRED"
				elif [[ ${_ret_remaining} -gt 0 ]]; then
					# session time remains

					getPrintableTimeRemaining _ret ${_ret_remaining}
					mfa_profile_status[$cred_profilecounter]="${_ret} remaining"
				elif [[ ${_ret_remaining} -eq -1 ]]; then
					# no timestamp; legacy or initialized outside of this utility

					mfa_profile_check="$(aws iam get-user --output text --query "User.Arn" --profile $mfa_profile_ident 2>&1)"
					if [[ "$mfa_profile_check" =~ ^arn:aws ]]; then
						mfa_profile_status[$cred_profilecounter]="OK"
					elif [[ "$mfa_profile_check" =~ ExpiredToken ]]; then
						mfa_profile_status[$cred_profilecounter]="EXPIRED"
					else
						mfa_profile_status[$cred_profilecounter]="LIMITED"
					fi
				fi
			fi

			## DEBUG (enable with DEBUG="true" on top of the file)
			if [ "$DEBUG" == "true" ]; then

				echo
				echo "PROFILE IDENT: $profile_ident (${cred_profile_status[$cred_profilecounter]})"
				echo "USER ARN: ${cred_profile_arn[$cred_profilecounter]}"
				echo "USER NAME: ${cred_profile_user[$cred_profilecounter]}"
				echo "MFA ARN: ${mfa_arns[$cred_profilecounter]}"
				echo "MFA MAXSEC: ${mfa_mfasec[$cred_profilecounter]}"
				if [ "${mfa_profiles[$cred_profilecounter]}" == "" ]; then
					echo "MFA PROFILE IDENT:"
				else
					echo "MFA PROFILE IDENT: ${mfa_profiles[$cred_profilecounter]} (${mfa_profile_status[$cred_profilecounter]})"
				fi
				echo
			## END DEBUG
			else
				echo -n "."
			fi

			# erase variables & increase iterator for the next iteration
			mfa_arn=""
			user_arn=""
			profile_ident=""
			profile_check=""
			profile_username=""
			mfa_profile_ident=""
			mfa_profile_check=""

			((cred_profilecounter++))

		fi
	done < $CREDFILE

	# create the profile selections
	echo
	echo
	echo "AVAILABLE AWS PROFILES:"
	echo
	SELECTR=0
	ITER=1
	for i in "${cred_profiles[@]}"
	do
		if [ "${mfa_arns[$SELECTR]}" != "" ]; then
			mfa_notify=", MFA configured"
		else
			mfa_notify="" 
		fi

		echo "${ITER}: $i (${cred_profile_user[$SELECTR]}${mfa_notify})"

		if [[ "${mfa_profile_status[$SELECTR]}" != "EXPIRED" &&
			"${mfa_profile_status[$SELECTR]}" != "" ]]; then
			echo "${ITER}m: $i MFA profile (${mfa_profile_status[$SELECTR]})"
		fi

		echo
		let ITER=${ITER}+1
		let SELECTR=${SELECTR}+1
	done

	# this is used to determine whether to trigger a MFA request for a MFA profile
	active_mfa="false"

	# this is used to determine whether to print MFA questions/details
	mfaprofile="false"

	# prompt for profile selection
	printf "SELECT A PROFILE BY THE ID: "
	read -r selprofile

	# process the selection
	if [[ "$selprofile" != "" ]]; then
		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_check="${BASH_REMATCH[1]}"
		if [[ "$selprofile_check" != "" ]]; then

			# if the numeric selection was found, 
			# translate it to the array index and validate
			let actual_selprofile=${selprofile_check}-1

			profilecount=${#cred_profiles[@]}
			if [[ $actual_selprofile -ge $profilecount ||
				$actual_selprofile -lt 0 ]]; then
				# a selection outside of the existing range was specified
				echo "There is no profile '${selprofile}'."
				echo
				exit 1
			fi

			# was an existing MFA profile selected?
			[[ $selprofile =~ ^[[:digit:]]+(m)$ ]] &&
				selprofile_mfa_check="${BASH_REMATCH[1]}"

			# if this is an MFA profile, it must be in OK or LIMITED status to select
			if [[ "$selprofile_mfa_check" != "" &&
				"${mfa_profile_status[$actual_selprofile]}" != "EXPIRED" &&
				"${mfa_profile_status[$actual_selprofile]}" != "" ]]; then

				# get the parent profile name
				# transpose selection (starting from 1) to array index (starting from 0)
				mfa_parent_profile_ident="${cred_profiles[$actual_selprofile]}"

				final_selection="${mfa_profiles[$actual_selprofile]}"
				echo "SELECTED MFA PROFILE: ${final_selection} (for base profile '${mfa_parent_profile_ident}')"

				# this is used to determine whether to print MFA questions/details
				mfaprofile="true"

				# this is used to determine whether to trigger a MFA request for a MFA profile
				active_mfa="true"

			elif [[ "$selprofile_mfa_check" != "" &&
				"${mfa_profile_status[$actual_selprofile]}" == "" ]]; then
				# mfa ('m') profile was selected for a profile that no mfa profile exists
				echo "There is no profile '${selprofile}'."
				echo
				exit 1

			else
				# a base profile was selected
				if [[ $selprofile =~ ^[[:digit:]]+$ ]]; then 
					echo "SELECTED PROFILE: ${cred_profiles[$actual_selprofile]}"
					final_selection="${cred_profiles[$actual_selprofile]}"
				else
					# non-acceptable characters were present in the selection
					echo "There is no profile '${selprofile}'."
					echo
					exit 1
				fi
			fi

		else
			# no numeric part in selection
			echo "There is no profile '${selprofile}'."
			echo
			exit 1
		fi
	else
		# empty selection
		echo "There is no profile '${selprofile}'."
		echo
		exit 1
	fi

	# this is an MFA request (an MFA ARN exists but the MFA is not active)
	if [[ "${mfa_arns[$actual_selprofile]}" != "" &&
		"$active_mfa" == "false" ]]; then

		# prompt for the MFA code
		echo
		echo -e "Enter the current MFA one time pass code for profile '${cred_profiles[$actual_selprofile]}' to start/renew the MFA session,"
		echo "or leave empty (just press [ENTER]) to use the selected profile without the MFA."
		
		while :
		do
			read mfacode
			if ! [[ "$mfacode" =~ ^$ || "$mfacode" =~ [0-9]{6} ]]; then
				echo "The MFA code must be exactly six digits, or blank to bypass."
				continue
			else
				break
			fi
		done

	elif [[ "$active_mfa" == "false" ]]; then   # no MFA configured (no MFA ARN); print a notice
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		# reset entered MFA code (just to be safe)
		mfacode=""
		echo
		echo -e "MFA has not been set up for this profile."
	fi

	if [[ "$mfacode" != "" ]]; then
		# init an MFA session (request an MFA session token)
		AWS_USER_PROFILE=${cred_profiles[$actual_selprofile]}
		AWS_2AUTH_PROFILE=${AWS_USER_PROFILE}-mfasession
		ARN_OF_MFA=${mfa_arns[$actual_selprofile]}

		getDuration AWS_SESSION_DURATION $AWS_USER_PROFILE

		echo "NOW GETTING THE MFA SESSION TOKEN FOR THE PROFILE: $AWS_USER_PROFILE"

		read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< \
		$( aws --profile $AWS_USER_PROFILE sts get-session-token \
		  --duration $AWS_SESSION_DURATION \
		  --serial-number $ARN_OF_MFA \
		  --token-code $mfacode \
		  --output text  | awk '{ print $2, $4, $5 }')

		if [ -z "$AWS_ACCESS_KEY_ID" ]; then
			echo
			echo "Could not initialize the requested MFA session."
			echo
			exit 1
		else
			# this is used to determine whether to print MFA questions/details
			mfaprofile="true"

			# optioanlly set the persistent (~/.aws/credentials entries):
			# aws_access_key_id, aws_secret_access_key, and aws_session_token 
			# for the MFA profile
			echo
			getPrintableTimeRemaining _ret $AWS_SESSION_DURATION
			validity_period=${_ret}
			echo -e "Make this MFA session persistent (saved in ~/.aws/credentials)\nso that you can return to it during its validity period (${validity_period})?"
			read -s -p "If you answer 'No', only the envvars will be used? [Y]n " -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ ]] ||
				[[ $REPLY == "" ]]; then

				persistent_MFA="true"
				`aws --profile $AWS_2AUTH_PROFILE configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"`
				`aws --profile $AWS_2AUTH_PROFILE configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"`
				`aws --profile $AWS_2AUTH_PROFILE configure set aws_session_token "$AWS_SESSION_TOKEN"`
				# set init time in the static MFA profile (a custom key in ~/.aws/credentials)
				addInitTime "${AWS_2AUTH_PROFILE}"
			fi			
			# init time for envvar exports (if selected)
			AWS_SESSION_INIT_TIME=$(date +%s)

			# Make sure the final selection profile name has '-mfasession' suffix
			# (before this assignment it's not present when going from a base profile to an MFA profile)
			final_selection=$AWS_2AUTH_PROFILE

			## DEBUG
			if [ "$DEBUG" == "true" ]; then
				echo
				echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
				echo "AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
				echo "AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN"
				echo "AWS_SESSION_INIT_TIME: $AWS_SESSION_INIT_TIME"
				echo "AWS_SESSION_DURATION: $AWS_SESSION_DURATION"
			fi
			## END DEBUG			
		fi

	elif [[ "$active_mfa" == "false" ]]; then
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"
	fi

	# get region and output format for the selected profile
	AWS_DEFAULT_REGION=$(aws --profile $final_selection configure get region)
	AWS_DEFAULT_OUTPUT=$(aws --profile $final_selection configure get output)

	# If the region and output format have not been set for this profile, set them 
	# For the parent/base profiles, use defaults; for MFA profiles use first
	# the base/parent settings if present, then the defaults
	if [[ "${AWS_DEFAULT_REGION}" == "" ]]; then
		# retrieve parent profile region if an MFA profie
		if [[ "${profile_region[$actual_selprofile]}" != "" &&
			  "${mfaprofile}" == "true" ]]; then
			set_new_region=${profile_region[$actual_selprofile]}
			echo "Region had not been configured for the selected MFA profile; it has been set to same as the parent profile ('$set_new_region')."
		fi
		if [[ "${set_new_region}" == "" ]]; then
			set_new_region=${default_region}
			echo "Region had not been configured for the selected profile; it has been set to the default region ('${default_region}')."
		fi

		AWS_DEFAULT_REGION="${set_new_region}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			`aws --profile $final_selection configure set region "${set_new_region}"`
		fi
	fi

	if [ "${AWS_DEFAULT_OUTPUT}" == "" ]; then
		# retrieve parent profile output format if an MFA profile
		if [[ "${profile_output[$actual_selprofile]}" != "" &&
			"${mfaprofile}" == "true" ]]; then
			set_new_output=${profile_output[$actual_selprofile]}
			echo "Output format had not been configured for the selected MFA profile; it has been set to same as the parent profile ('$set_new_output')."
		fi
		if [[ "${set_new_output}" == "" ]]; then
			set_new_output=${default_output}
			echo "Output format had not been configured for the selected profile; it has been set to the default output format ('${default_output}')."
		fi

		AWS_DEFAULT_OUTPUT="${set_new_output}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			`aws --profile $final_selection configure set output "${set_new_output}"`
		fi
	fi

	if [[ "$mfacode" == "" ]]; then  # this is _not_ a new MFA session, so read in selected persistent values;
									 # for new MFA sessions they are already present
		AWS_ACCESS_KEY_ID=$(aws --profile $final_selection configure get aws_access_key_id)
		AWS_SECRET_ACCESS_KEY=$(aws --profile $final_selection configure get aws_secret_access_key)
		
		if [[ "$mfaprofile" == "true" ]]; then  # this is a persistent MFA profile (a subset of [[ "$mfacode" == "" ]])
			AWS_SESSION_TOKEN=$(aws --profile $final_selection configure get aws_session_token)
			getInitTime _ret "${final_selection}"
			AWS_SESSION_INIT_TIME=${_ret}
			getDuration _ret "${final_selection}"
			AWS_SESSION_DURATION=${_ret}
		fi
	fi

	echo
	echo "========================================================================"
	echo
	if [[ "$mfaprofile" == "true" ]]; then
		echo "MFA profile name: '${final_selection}'"
		echo
	else
		echo "Profile name '${final_selection}'"
		echo "** NOTE: This is not an MFA session!"
		echo 
	fi
	echo "Region is set to: $AWS_DEFAULT_REGION"
	echo "Output format is set to: $AWS_DEFAULT_OUTPUT"
	echo

	if [[ "$mfacode" == "" ]] || # re-entering a persistent profile, MFA or not
		( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then # a new persistent MFA session was initialized; 
		# Display the persistent profile's envvar details for export?
		read -s -p "Do you want to export the selected profile's secrets to the environment (for s3cmd, etc)? - y[N] " -n 1 -r
		if [[ $REPLY =~ ^[Nn]$ ]] ||
			[[ $REPLY == "" ]]; then

			secrets_out="false"
		else
			secrets_out="true"
		fi
		echo
		echo
	else
		# A new transient MFA session was initialized; 
		# its details have to be displayed for export or it can't be used
		secrets_out="true"
	fi

	if [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "false" ]]; then
		echo "*** THIS IS A NON-PERSISTENT MFA SESSION; YOU *MUST* EXPORT THE BELOW ENVVARS TO ACTIVATE ***"
		echo
	fi

	if [[ "$OS" == "macOS" ]]; then

		echo "Execute the following in Terminal to activate the selected profile"
		echo "(it's already on your clipboard; just paste it and press [ENTER]):"
		echo
		echo "export AWS_PROFILE=${final_selection}"

		if [[ "$secrets_out" == "false" ]]; then
			echo "unset AWS_ACCESS_KEY_ID"
			echo "unset AWS_SECRET_ACCESS_KEY"
			echo "unset AWS_DEFAULT_REGION"
			echo "unset AWS_DEFAULT_OUTPUT"
			echo "unset AWS_SESSION_INIT_TIME"
			echo "unset AWS_SESSION_DURATION"
			echo "unset AWS_SESSION_TOKEN"
			echo -n "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT" | pbcopy
		else
			echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
			echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}"
				echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}"
				echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}; export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}; export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}" | pbcopy
			else
				echo "unset AWS_SESSION_INIT_TIME"
				echo "unset AWS_SESSION_DURATION"
				echo "unset AWS_SESSION_TOKEN"
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_SESSION_TOKEN" | pbcopy
				echo
			fi
		fi
		echo
		echo "NOTE: Make sure to set/unset all the new values as instructed above to make sure no conflicting profile/secrets remain in the envrionment!"
		echo
		echo -e "To conveniently remove any AWS profile/secrets information from the environment, simply source the attached script, like so:\nsource ./source-to-clear-AWS-envvars.sh"
		echo

	elif [ "$OS" == "Linux" ]; then
		echo "Execute the following on the command line to activate this profile for the 'aws', 's3cmd', etc. commands."
		echo "NOTE: Even if you only use a named profile ('AWS_PROFILE'), it's important to execute all of the export/unset"
		echo "      commands to make sure previously set environment variables won't override the selected configuration."
		echo
		echo "export AWS_PROFILE=${final_selection}"
		echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
		echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
		echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
		echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}"		
		if [[ "$mfaprofile" == "true" ]]; then
			echo "export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}"
			echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}"
			echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
			if exists xclip ; then
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}; export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}; export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}" | xclip -i
				echo "(xclip found; the activation command is now on your X PRIMARY clipboard -- just paste on the command line, and press [ENTER])"
			fi
		else
			echo "unset AWS_SESSION_INIT_TIME"
			echo "unset AWS_SESSION_DURATION"
			echo "unset AWS_SESSION_TOKEN"
			if exists xclip ; then
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_SESSION_TOKEN" | xclip -i
				echo "(xclip found; the activation command is now on your X PRIMARY clipboard -- just paste on the command line, and press [ENTER])"
			fi
		fi
		if ! exists xclip ; then
			echo
			echo "If you're using an X GUI on Linux, install 'xclip' to have the activation command copied to the clipboard automatically."
		fi
		echo
		echo ".. or execute the following to use named profile only, clearning any previoiusly set configuration variables:"
		echo
		echo "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT"
		echo
		echo -e "To conveniently remove any AWS profile/secrets information from the environment, simply source the attached script, like so:\nsource ./source-to-clear-AWS-envvars.sh"
		echo

	else  # not macOS, not Linux, so some other weird OS like Windows..
		echo "Execute the following on the command line to activate this profile for the 'aws', 's3cmd', etc. commands."
		echo "NOTE: Even if you only use a named profile ('AWS_PROFILE'), it's important to execute all of the export/unset"
		echo "      commands to make sure previously set environment variables won't override the selected configuration."
		echo
		echo "export AWS_PROFILE=${final_selection} \\"
		echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \\"
		echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \\"
		echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \\"
		echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT} \\"
		if [[ "$mfaprofile" == "true" ]]; then
			echo "export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}"
			echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}"
			echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
		else
			echo "unset AWS_SESSION_INIT_TIME"
			echo "unset AWS_SESSION_DURATION"
			echo "unset AWS_SESSION_TOKEN"
		fi
		echo
		echo "..or execute the following to use named profile only, clearing any previously set configuration variables:"
		echo
		echo "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT"
		echo
		echo -e "To conveniently remove any AWS profile/secrets information from the environment, simply source the attached script, like so:\nsource ./source-to-clear-AWS-envvars.sh"
		echo

	fi
	echo
fi
