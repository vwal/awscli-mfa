#!/usr/bin/env bash

# todo: handle roles with MFA
# todo: handle root account max session time @3600 & warn if present
# todo: handle secondary role max session time @3600 & warn

# NOTE: Debugging mode prints the secrets on the screen!
DEBUG="false"

# enable debugging with '-d' or '--debug' command line argument..
[[ "$1" == "-d" || "$1" == "--debug" ]] && DEBUG="true"
# .. or by uncommenting the line below:
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

# Define the standard locations for the AWS credentials and
# config files; these can be statically overridden with 
# AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE envvars
# (this script will override these envvars only if the 
# "[default]" profile in the defined custom file(s) is
# defunct, thus reverting to the below default locations).
CONFFILE=~/.aws/config
CREDFILE=~/.aws/credentials

# COLOR DEFINITIONS ==========================================================

# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# Underline
UBlack='\033[4;30m'       # Black
URed='\033[4;31m'         # Red
UGreen='\033[4;32m'       # Green
UYellow='\033[4;33m'      # Yellow
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'      # Purple
UCyan='\033[4;36m'        # Cyan
UWhite='\033[4;37m'       # White

# Background
On_Black='\033[40m'       # Black
On_Red='\033[41m'         # Red
On_Green='\033[42m'       # Green
On_Yellow='\033[43m'      # Yellow
On_Blue='\033[44m'        # Blue
On_Purple='\033[45m'      # Purple
On_Cyan='\033[46m'        # Cyan
On_White='\033[47m'       # White

# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White

# Bold High Intensity
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White

# High Intensity backgrounds
On_IBlack='\033[0;100m'   # Black
On_IRed='\033[0;101m'     # Red
On_IGreen='\033[0;102m'   # Green
On_DGreen='\033[48;5;28m' # Dark Green
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White

# DEBUG MODE WARNING & BASH VERSION ==========================================

if [[ "$DEBUG" == "true" ]]; then
	echo -e "\\n${BIWhite}${On_Red} DEBUG MODE ACTIVE ${Color_Off}\\n\\n${BIRed}${On_Black}NOTE: Debug output may include secrets!!!${Color_Off}\\n\\n"
	echo -e "Using bash version $BASH_VERSION\\n\\n"
fi

# FUNCTIONS ==================================================================

# `exists` for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

# precheck envvars for existing/stale session definitions
checkEnvSession() {
	# $1 is the check type

	local this_time
	this_time=$(date +%s)

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

	# AWS_PROFILE must be empty or refer to *any* profile in ~/.aws/{credentials|config}
	# (Even if all the values are overridden by AWS_* envvars they won't work if the 
	# AWS_PROFILE is set to an unknown value!)
	if [[ "$PRECHECK_AWS_PROFILE" != "" ]]; then

		idxLookup profiles_idx creds_ident[@] "$PRECHECK_AWS_PROFILE"
		idxLookup confs_idx confs_ident[@] "$PRECHECK_AWS_PROFILE"

		if [[ "$profiles_idx" == "" ]] && [[ "$confs_idx" == "" ]]; then

			# AWS_PROFILE ident is not recognized; 
			# cannot continue unless it's changed!
			continue_maybe "invalid"
		fi			
	fi

	# makes sure that the MFA session has not expired (whether it's 
	# defined in the environment or in ~/.aws/credentials).
	# 
	# First checking the envvars
	if [[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
		[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]] &&
		[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]]; then
		# this is a MFA profile in the environment;
		# AWS_PROFILE is either empty or valid

		getRemaining _ret "$PRECHECK_AWS_SESSION_INIT_TIME" "$PRECHECK_AWS_SESSION_DURATION"
		[[ "${_ret}" -eq 0 ]] && continue_maybe "expired"
	
	elif [[ "$PRECHECK_AWS_PROFILE" =~ -mfasession$ ]] &&
			[[ "$profiles_idx" != "" ]]; then
		# AWS_PROFILE is set (and valid, and refers to a persistent mfasession)
		# but TOKEN, INIT_TIME, and/or DURATION are not, so this is 
		# likely a select of a named profile

		# find the selected persistent MFA profile's init time if one exists
		profile_time=${creds_aws_mfasession_init_time[$profiles_idx]}
		
		# if the duration for the current profile is not set
		# (as is usually the case with the mfaprofiles), use
		# the parent/base profile's duration
		if [[ "$profile_time" != "" ]]; then
			getDuration parent_duration "$PRECHECK_AWS_PROFILE"
			getRemaining _ret "$profile_time" "$parent_duration"
			[[ "${_ret}" -eq 0 ]] && continue_maybe "expired"
		fi
	fi
	# empty AWS_PROFILE + no in-env MFA session should flow through

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
			echo "NOTE: THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE CURRENTLY IN EFFECT:"
			echo
			if [[ "$PRECHECK_AWS_PROFILE" != "$AWS_PROFILE" ]]; then
				env_notice=" (overridden to 'default')"
			else
				env_notice=""
			fi
			[[ "$PRECHECK_AWS_PROFILE" != "" ]] && echo "   AWS_PROFILE: ${PRECHECK_AWS_PROFILE}${env_notice}"
			[[ "$PRECHECK_AWS_ACCESS_KEY_ID" != "" ]] && echo "   AWS_ACCESS_KEY_ID: $PRECHECK_AWS_ACCESS_KEY_ID"
			[[ "$PRECHECK_AWS_SECRET_ACCESS_KEY" != "" ]] && echo "   AWS_SECRET_ACCESS_KEY: $PRECHECK_AWS_SECRET_ACCESS_KEY"
			[[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] && echo "   AWS_SESSION_TOKEN: $PRECHECK_AWS_SESSION_TOKEN"
			[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]] && echo "   AWS_SESSION_INIT_TIME: $PRECHECK_AWS_SESSION_INIT_TIME"
			[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]] && echo "   AWS_SESSION_DURATION: $PRECHECK_AWS_SESSION_DURATION"
			[[ "$PRECHECK_AWS_DEFAULT_REGION" != "" ]] && echo "   AWS_DEFAULT_REGION: $PRECHECK_AWS_DEFAULT_REGION"
			[[ "$PRECHECK_AWS_DEFAULT_OUTPUT" != "" ]] && echo "   AWS_DEFAULT_OUTPUT: $PRECHECK_AWS_DEFAULT_OUTPUT"
			[[ "$PRECHECK_AWS_CA_BUNDLE" != "" ]] && echo "   AWS_CA_BUNDLE: $PRECHECK_AWS_CA_BUNDLE"
			[[ "$PRECHECK_AWS_SHARED_CREDENTIALS_FILE" != "" ]] && echo "   AWS_SHARED_CREDENTIALS_FILE: $PRECHECK_AWS_SHARED_CREDENTIALS_FILE"
			[[ "$PRECHECK_AWS_CONFIG_FILE" != "" ]] && echo "   AWS_CONFIG_FILE: $PRECHECK_AWS_CONFIG_FILE"
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

	for (( i=0; i<=maxIndex; i++ ))
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
		
		if [[ "$OS" == "macOS" ]]; then 
			sed -i '' -e "s/${profile_time}/${this_time}/g" "$CREDFILE"
		else 
			sed -i -e "s/${profile_time}/${this_time}/g" "$CREDFILE"
		fi
	else
		# no time entry exists for the profile; 
		# add on a new line after the header "[${this_ident}]"
		replace_me="\\[${this_ident}\\]"
		DATA="[${this_ident}]\\naws_session_init_time = ${this_time}"
		echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${CREDFILE}")" > "${CREDFILE}"
	fi

	# update the selected profile's existing
	# init time entry in this script
	idxLookup idx creds_ident[@] "$this_ident"
	creds_aws_mfasession_init_time[$idx]=$this_time
}

# return the MFA session init time for the given profile
getInitTime() {
	# $1 is _ret
	# $2 is the profile ident

	local this_ident=$2
	local profile_time

	# find the profile's init time entry if one exists
	idxLookup idx creds_ident[@] "$this_ident"
	profile_time=${creds_aws_mfasession_init_time[$idx]}

	eval "$1=${profile_time}"
}

getDuration() {
	# $1 is _ret
	# $2 is the profile ident

	local this_profile_ident="$2"
	local this_duration

	# use parent profile ident if this is an MFA session
	[[ "$this_profile_ident" =~ ^(.*)-mfasession$ ]] &&
		this_profile_ident="${BASH_REMATCH[1]}"

	# look up possible custom duration for the parent profile
	idxLookup idx confs_ident[@] "$this_profile_ident"

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
	local this_time
	this_time=$(date +%s)
	local remaining=0

	[[ "${duration}" == "" ]] &&
		duration=$MFA_SESSION_LENGTH_IN_SECONDS

	if [ ! -z "${timestamp##*[!0-9]*}" ]; then
		((session_end=timestamp+duration))
		if [[ $session_end -gt $this_time ]]; then
			((remaining=session_end-this_time))
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
			response=$(printf '%02dh:%02dm:%02ds' $((timestamp/3600)) $((timestamp%3600/60)) $((timestamp%60)))
			;;
	esac
	eval "$1=${response}"
}

#BEGIN NONE OF THIS MAY BE NEEDED...
does_valid_default_exist() {
	# $1 is _ret

	default_profile_arn="$(aws --profile default sts get-caller-identity  --query 'Arn' --output text 2>&1)"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile default sts get-caller-identity  --query 'Arn' --output text':\\n${ICyan}${default_profile_arn}${Color_Off}"

	if [[ "$default_profile_arn" =~ ^arn:aws:iam:: ]] &&
		[[ ! "$default_profile_arn" =~ 'error occurred' ]]; then

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The default profile exists and is valid.${Color_Off}"
		response="true"
	else
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The default profile not present or invalid.${Color_Off}"
		response="false"
	fi

	eval "$1=${response}"
}

already_failed="false"
# here are my args, so..
continue_maybe() {
	# $1 is "invalid" or "expired"

	local failtype=$1

	if [[ "$already_failed" == "false" ]]; then

		if [[ "${failtype}" == "expired" ]]; then  
			echo -e "\\n${BIRed}${On_Black}NOTE: THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
		else
			echo -e "\\n${BIRed}${On_Black}NOTE: THE AWS PROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}"
		fi

#todo: remove below altogether?
if [[ "true" == "false" ]]; then
		read -s -p "$(echo -e "${BIWhite}${On_Black}Do you want to continue with the default profile?${Color_Off} - ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]] ||
			[[ $REPLY == "" ]]; then

			already_failed="true"

			# If the default profile is already selected
			# and the profile was still defunct (since 
			# we ended up here), make sure non-standard
			# config/credentials files are not used
			if [[ "$AWS_PROFILE" == "" ]] ||
				[[ "$AWS_PROFILE" == "default" ]]; then
			
				unset AWS_SHARED_CREDENTIALS_FILE
				unset AWS_CONFIG_FILE

				custom_configfiles_reset="true"
			fi

			unset AWS_PROFILE
			unset AWS_ACCESS_KEY_ID
			unset AWS_SECRET_ACCESS_KEY
			unset AWS_SESSION_TOKEN
			unset AWS_SESSION_INIT_TIME
			unset AWS_SESSION_DURATION
			unset AWS_DEFAULT_REGION
			unset AWS_DEFAULT_OUTPUT
			unset AWS_CA_BUNDLE

			# override envvar for all the subshell commands
			export AWS_PROFILE=default
			echo
		else
			echo -e "\\n\\nExecute \"source ./source-this-to-clear-AWS-envvars.sh\", and try again to proceed.\\n"
			exit 1
		fi
fi

	fi
}
# END NONE OF THIS MAY BE NEEDED

checkAWSErrors() {
	# $1 is exit_on_error (true/false)
	# $2 is the AWS return (may be good or bad)
	# $3 is the 'default' keyword if present
	# $4 is the custom message if present;
	#    only used when $3 is positively present
	#    (such as at MFA token request)

	local exit_on_error=$1
	local aws_raw_return=$2
	local profile_in_use 
	local custom_error
	[[ "$3" == "" ]] && profile_in_use="selected" || profile_in_use="$3"
	[[ "$4" == "" ]] && custom_error="" || custom_error="${4}\\n"

	local is_error="false"
	if [[ "$aws_raw_return" =~ 'InvalidClientTokenId' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}The AWS Access Key ID does not exist!${Red}\\nCheck the ${profile_in_use} profile configuration including any 'AWS_*' environment variables.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'SignatureDoesNotMatch' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key does not match the Access Key ID!${Red}\\nCheck the ${profile_in_use} profile configuration including any 'AWS_*' environment variables.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'IncompleteSignature' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Incomplete signature!${Red}\\nCheck the Secret Access Key of the ${profile_in_use} for typos/completeness (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'MissingAuthenticationToken' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key is not present!${Red}\\nCheck the ${profile_in_use} profile configuration (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'AccessDeniedException' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Access denied!${Red}\\nThe effective MFA IAM policy may be too restrictive.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'AuthFailure' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Authentication failure!${Red}\\nCheck the credentials for the ${profile_in_use} profile (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'ServiceUnavailable' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Service unavailable!${Red}\\nThis is likely a temporary problem with AWS; wait for a moment and try again.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'ThrottlingException' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Too many requests in too short amount of time!${Red}\\nWait for a few moments and try again.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'InvalidAction' ]] ||
		[[ "$aws_raw_return" =~ 'InvalidQueryParameter' ]] ||
		[[ "$aws_raw_return" =~ 'MalformedQueryString' ]] ||
		[[ "$aws_raw_return" =~ 'MissingAction' ]] ||
		[[ "$aws_raw_return" =~ 'ValidationError' ]] ||
		[[ "$aws_raw_return" =~ 'MissingParameter' ]] ||
		[[ "$aws_raw_return" =~ 'InvalidParameterValue' ]]; then
		
		echo -en "\\n${BIRed}${On_Black}${custom_error}AWS did not understand the request.${Red}\\nThis should never occur with this script. Maybe there was a glitch in\\nthe matrix (maybe the AWS API changed)?\\nRun the script with the '--debug' switch to see the exact error.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'InternalFailure' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}An unspecified error occurred!${Red}\\n\"Internal Server Error 500\". Sorry I don't have more detail.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'error occurred' ]]; then
		echo -e "${BIRed}${On_Black}${custom_error}An unspecified error occurred!${Red}\\nCheck the ${profile_in_use} profile (including any 'AWS_*' environment variables).\\nRun the script with the '--debug' switch to see the exact error.${Color_Off}\\n"
		is_error="true"
	fi

	# do not exit on profile ingest loop
	[[ "$is_error" == "true" && "$exit_on_error" == "true" ]] && exit 1
}

getAccountAlias() {
	# $1 is _ret (returns the index)
	# $2 is the profile_ident

	local local_profile_ident="$2"

	if [[ "$local_profile_ident" == "" ]]; then
		# no input, return blank result right away
		result=""
		eval "$1=$result"
	fi

	# get the account alias (if any) for the user/profile
	account_alias_result="$(aws --profile "$local_profile_ident" iam list-account-aliases --output text --query 'AccountAliases' 2>&1)"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n\
${Cyan}${On_Black}result for: 'aws --profile \"$local_profile_ident\" iam list-account-aliases --query 'AccountAliases' --output text':\\n\
${ICyan}${account_alias_result}${Color_Off}\\n\\n"

	if [[ "$account_alias_result" =~ 'error occurred' ]]; then
		# no access to list account aliases for this profile or other error
		result=""
	else
		result="$account_alias_result"
	fi

	eval "$1=$result"
}

## PREREQUISITES CHECK

#todo: add awscli *version* check

# is AWS CLI installed?
if ! exists aws ; then
	printf "\\n******************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: http://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html\\n\
******************************************************************************************************************************\\n\\n"
	exit 1
fi 

filexit="false"
# check for ~/.aws directory
# if the custom config defs aren't in effect
if ( [[ "$AWS_CONFIG_FILE" == "" ]] ||
	[[ "$AWS_SHARED_CREDENTIALS_FILE" == "" ]] ) &&
	[ ! -d ~/.aws ]; then

	echo
	echo -e "${BIRed}${On_Black}\
AWSCLI configuration directory '~/.aws' is not present.${Color_Off}\\n\
Make sure it exists, and that you have at least one profile configured\\n\
using the 'config' and/or 'credentials' files within that directory."
	filexit="true"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ -f "$AWS_CONFIG_FILE" ]; then

	active_config_file=$AWS_CONFIG_FILE
	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A custom configuration file defined with AWS_CONFIG_FILE envvar in effect: '$AWS_CONFIG_FILE'${Color_Off}"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ ! -f "$AWS_CONFIG_FILE" ]; then

	echo
	echo -e "${BIRed}${On_Black}\
The custom config file defined with AWS_CONFIG_FILE envvar,\\n\
'$AWS_CONFIG_FILE', is not present.${Color_Off}\\n\
Make sure it is present or purge the envvar.\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [ -f "$CONFFILE" ]; then
	active_config_file="$CONFFILE"
else
	echo
	echo -e "${BIRed}${On_Black}\
AWSCLI configuration file '$CONFFILE' was not found.${Color_Off}\\n\
Make sure it and '$CREDFILE' files exist.\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"
fi

# SUPPORT CUSTOM CREDENTIALS FILE SET WITH ENVVAR
if [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	active_credentials_file="$AWS_SHARED_CREDENTIALS_FILE"
	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar in effect: '$AWS_SHARED_CREDENTIALS_FILE'${Color_Off}"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ ! -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	echo
	echo -e "${BIRed}${On_Black}\
The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar,\\n\
'$AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\n\
Make sure it is present, or purge the envvar.\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [ -f "$CREDFILE" ]; then
	active_credentials_file="$CREDFILE"
else
	# assume creds are in ~/.aws/config
	active_credentials_file=""
	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A shared credentials file (~/.aws/credentials) was not found.\\n
         Assuming credentials are stored in the config file (~/.aws/config).${Color_Off}"
fi

if [[ "$filexit" == "true" ]]; then 
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"
custom_configfiles_reset="false"

# read the credentials and/or config files, 
# and make sure that at least one profile is configured
ONEPROFILE="false"
conffile_vars_in_credfile="false"

if [[ $CREDFILE != "" ]]; then
	while IFS='' read -r line || [[ -n "$line" ]]; do
		[[ "$line" =~ ^\[(.*)\].* ]] &&
			profile_ident="${BASH_REMATCH[1]}"

		if [[ "$profile_ident" != "" ]]; then
			ONEPROFILE="true"
		fi 

		if  [[ "$line" =~ ^[[:space:]]*ca_bundle.* ]] ||
			[[ "$line" =~ ^[[:space:]]*cli_timestamp_format.* ]] ||
			[[ "$line" =~ ^[[:space:]]*credential_source.* ]] ||
			[[ "$line" =~ ^[[:space:]]*external_id.* ]] ||
			[[ "$line" =~ ^[[:space:]]*mfa_serial.* ]] ||
			[[ "$line" =~ ^[[:space:]]*output.* ]] ||
			[[ "$line" =~ ^[[:space:]]*parameter_validation.* ]] ||
			[[ "$line" =~ ^[[:space:]]*region.* ]] ||
			[[ "$line" =~ ^[[:space:]]*role_arn.* ]] ||
			[[ "$line" =~ ^[[:space:]]*role_session_name.* ]] ||
			[[ "$line" =~ ^[[:space:]]*source_profile.* ]]; then
			
			conffile_vars_in_credfile="true"
		fi

	done < "$CREDFILE"
fi

if [[ "$conffile_vars_in_credfile" == "true" ]]; then
	echo -e "\\n${BIWhite}${On_Black}\
NOTE: The credentials file ($CREDFILE) contains variables\\n\
      only supported in the config file ($CONFFILE).${Color_Off}\\n\\n\
      The credentials file may only contain credential and session information;\\n\
      please see https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
      and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
      for the details on how to correctly set up config and credentials files."
fi

# check for presence of at least one set of credentials
# in the CONFFILE (in the event CREDFILE is not used)
profile_header_check="false"
access_key_id_check="false"
secret_access_key_check="false"
while IFS='' read -r line || [[ -n "$line" ]]; do
	[[ "$line" =~ ^\[(.*)\].* ]] &&
		profile_ident="${BASH_REMATCH[1]}"

	if [[ "$profile_ident" != "" ]]; then
		profile_header_check="true"
	fi 

	if [[ "$line" =~ ^[[:space:]]*aws_access_key_id.* ]]; then 
		access_key_id_check="true"
	fi

	if [[ "$line" =~ ^[[:space:]]*aws_secret_access_key.* ]]; then
		secret_access_key_check="true"
	fi

done < "$CONFFILE"

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	ONEPROFILE="true"
fi

if [[ "$ONEPROFILE" == "false" ]]; then
	echo
	echo -e "${BIRed}${On_Black}\
NO CONFIGURED AWS PROFILES FOUND.${Color_Off}\\n\
Please make sure you have at least one configured profile.\\n\
For more info on how to set them up, see AWS CLI configuration\\n\
documentation at the following URLs:\\n\
https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html"

else

	# Check OS for some supported platforms
	OS="$(uname)"
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
			echo "NOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM."
			echo
			;;
	esac

	# make sure the selected/default CREDFILE exists 
	# even if the creds are in the CONFFILE, and that
	# it has a linefeed in the end. The session data
	# is always stored in the CREDFILE!
	if [[ $CREDFILE != "" ]]; then 
		c=$(tail -c 1 "$CREDFILE")
		if [[ "$c" != "" ]]; then
			echo "" >> "$CREDFILE"
		fi
	else
		echo "" > $CREDFILE
		chmod 600 $CREDFILE
	fi

	# make sure the selected CONFFILE has a linefeed in the end
	c=$(tail -c 1 "$CONFFILE")
	if [[ "$c" != "" ]]; then
		echo "" >> "$CONFFILE"
	fi

	## FUNCTIONAL PREREQS PASSED; PROCEED WITH EXPIRED SESSION CHECK
	## AMD CUSTOM CONFIGURATION/PROPERTY READ-IN

	# define profiles arrays, variables
	declare -a creds_ident
	declare -a creds_aws_access_key_id
	declare -a creds_aws_secret_access_key
	declare -a creds_aws_session_token
	declare -a creds_aws_mfasession_init_time
	declare -a creds_aws_rolesession_expiry
	declare -a creds_type
	persistent_MFA="false"
	profiles_iterator=0
	profiles_init=0

	# an ugly hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	roles_in_credfile="false"
	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			if [[ $profiles_init -eq 0 ]]; then
				creds_ident[$profiles_iterator]="${_ret}"
				profiles_init=1
			fi

			if [[ "$_ret" != "" ]] &&
				[[ "$_ret" =~ -mfasession$ ]]; then

				creds_type[$profiles_iterator]="mfasession"
			elif [[ "$_ret" != "" ]] &&
				[[ "$_ret" =~ -rolesession$ ]]; then

				creds_type[$profiles_iterator]="rolesession"
			else
				creds_type[$profiles_iterator]="baseprofile"
			fi

			if [[ "${creds_ident[$profiles_iterator]}" != "$_ret" ]]; then
				((profiles_iterator++))
				creds_ident[$profiles_iterator]=$_ret
			fi
		fi

		# aws_access_key_id
		[[ "$line" =~ ^[[:space:]]*aws_access_key_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_access_key_id[$profiles_iterator]="${BASH_REMATCH[1]}"

		# aws_secret_access_key
		[[ "$line" =~ ^[[:space:]]*aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_secret_access_key[$profiles_iterator]="${BASH_REMATCH[1]}"

		# aws_session_token
		[[ "$line" =~ ^[[:space:]]*aws_session_token[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_session_token[$profiles_iterator]="${BASH_REMATCH[1]}"

		# aws_session_init_time
		[[ "$line" =~ ^[[:space:]]*aws_session_init_time[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_mfasession_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

		# role_arn
		if [[ "$line" =~ ^[[:space:]]*role_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			this_role="${BASH_REMATCH[1]}"

			echo -e "\\n${BIRed}${On_Black}\
NOTE: The role '${BASH_REMATCH[1]}' is defined in\\n\
      the credentials file ($CREDFILE) and will be ignored.${Color_Off}\\n\\n\
      The credentials file may only contain profile/session secrets;\\n\
      you can define roles in the config file ($CONFFILE).\\n"

		fi

	done < "$CREDFILE"

	# init arrays to hold profile configuration detail
	# (may also include credentials)
	declare -a confs_ident

#todo: merge from the creds array:
# baseprofile creds -> baseprofile ident
# rolesession creds -> role profile ident
# mfasession creds -> baseprofile mfa arrays -or- new profile for each?

	declare -a confs_aws_access_key_id
	declare -a confs_aws_secret_access_key
	declare -a confs_aws_session_init_time
	declare -a confs_aws_session_token
	declare -a confs_ca_bundle
	declare -a confs_cli_timestamp_format
	declare -a confs_credential_source
	declare -a confs_external_id
	declare -a confs_mfa_serial
	declare -a confs_mfasec
	declare -a confs_output
	declare -a confs_parameter_validation
	declare -a confs_region
	declare -a confs_role_arn
	declare -a confs_role_session_name
	declare -a confs_role_source
	declare -a confs_type
	confs_init=0
	confs_iterator=0

	# read in the config file params
	while IFS='' read -r line || [[ -n "$line" ]]; do

		if [[ "$line" =~ ^\[[[:space:]]*profile[[:space:]]*(.*)[[:space:]]*\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			if [[ $confs_init -eq 0 ]]; then
				confs_ident[$confs_iterator]="${_ret}"
				confs_init=1
			elif [[ "${confs_ident[$confs_iterator]}" != "$_ret" ]]; then
				((confs_iterator++))
				confs_ident[$confs_iterator]="${_ret}"
			fi

			# assume baseprofile type; this is overridden for roles
			confs_type[$confs_iterator]="baseprofile"
		fi

		# aws_access_key_id
		[[ "$line" =~ ^[[:space:]]*aws_access_key_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_access_key_id[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_secret_access_key
		[[ "$line" =~ ^[[:space:]]*aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_secret_access_key[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_session_init_time (should always be blank in cofig, but just in case)
		[[ "$line" =~ ^[[:space:]]*aws_session_init_time[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_mfasession_init_time[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_session_token
		[[ "$line" =~ ^[[:space:]]*aws_session_token[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_session_token[$confs_iterator]="${BASH_REMATCH[1]}"

		# ca_bundle
		[[ "$line" =~ ^[[:space:]]*ca_bundle[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_ca_bundle[$confs_iterator]=${BASH_REMATCH[1]}

		# cli_timestamp_format
		[[ "$line" =~ ^[[:space:]]*cli_timestamp_format[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_cli_timestamp_format[$confs_iterator]=${BASH_REMATCH[1]}

		# credential_source
		[[ "$line" =~ ^[[:space:]]*credential_source[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_credential_source[$confs_iterator]=${BASH_REMATCH[1]}

		# external_id
		[[ "$line" =~ ^[[:space:]]*external_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_external_id[$confs_iterator]=${BASH_REMATCH[1]}

		# mfa_serial
		[[ "$line" =~ ^[[:space:]]*mfa_serial[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_mfa_serial[$confs_iterator]=${BASH_REMATCH[1]}

		# mfasec
		[[ "$line" =~ ^[[:space:]]*mfasec[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_mfasec[$confs_iterator]=${BASH_REMATCH[1]}

		# output
		[[ "$line" =~ ^[[:space:]]*output[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_output[$confs_iterator]=${BASH_REMATCH[1]}

		# parameter_validation
		[[ "$line" =~ ^[[:space:]]*parameter_validation[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_parameter_validation[$confs_iterator]=${BASH_REMATCH[1]}

		# region
		[[ "$line" =~ ^[[:space:]]*region[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_region[$confs_iterator]=${BASH_REMATCH[1]}

		# role_arn
		if [[ "$line" =~ ^[[:space:]]*role_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_arn[$confs_iterator]=${BASH_REMATCH[1]}
			confs_type[$confs_iterator]="role"
		fi

		# role_session_name
		[[ "$line" =~ ^[[:space:]]*role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_name[$confs_iterator]=${BASH_REMATCH[1]}

		# role_source
		[[ "$line" =~ ^[[:space:]]*role_source[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_source[$confs_iterator]=${BASH_REMATCH[1]}

	done < "$CONFFILE"

	# make sure environment has either no config
	# or a functional config before we proceed
	checkEnvSession

	# get default region and output format
	# (since at least one profile should exist
	# at this point, and one should be selected)
	default_region=$(aws --profile default configure get region)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws configure get region --profile default':\\n${ICyan}'${default_region}'${Color_Off}\\n\\n"

	default_output=$(aws --profile default configure get output)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws configure get output --profile default':\\n${ICyan}'${default_output}'${Color_Off}\\n\\n"

	if [[ "$default_output" == "" ]]; then
		# default output is not set in the config;
		# set the default to the AWS default
		# internally (so that it's available
		# for the MFA sessions)
		default_output="json"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}default output for this script was set to: ${ICyan}json${Color_Off}\\n\\n"
		echo -e "\\n${BIWhite}${On_Black}\
The default output format has not been configured; 'json' format is used.\\n\
You can modify it, for example, like so:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
aws configure set output \"table\"${Color_Off}\\n"
	fi

	if [[ "$default_region" == "" ]]; then
		echo -e "${BIWhite}${On_Black}\
NOTE: The default region has not been configured.${Color_Off}\\n\
      Some operations may fail if each [parent] profile doesn't\\n\
      have the region set. You can set the default region in\\n\
      '$CONFFILE', for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set region \"us-east-1\"${Color_Off}\\n
      (do not use the '--profile' switch when configuring the defaults)"
	fi

	echo

# todo: remove default requirement below altogether?
# 
## BEGIN REMOVE?
if [[ "true" == "false" ]]; then

	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		current_aws_access_key_id="${AWS_ACCESS_KEY_ID}"
	else
		current_aws_access_key_id="$(aws configure get aws_access_key_id)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure get aws_access_key_id':\\n${ICyan}${current_aws_access_key_id}${Color_Off}\\n\\n"
	fi

	idxLookup idx creds_aws_access_key_id[@] "$current_aws_access_key_id"

	if [[ $idx != "" ]]; then 
		currently_selected_profile_ident_printable="'${creds_ident[$idx]}'"
	else
		if [[ "${PRECHECK_AWS_PROFILE}" != "" ]]; then
			currently_selected_profile_ident_printable="'${PRECHECK_AWS_PROFILE}' [transient]"
		else
			currently_selected_profile_ident_printable="unknown/transient"
		fi
	fi

	process_user_arn="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${process_user_arn}${Color_Off}\\n\\n"

	# prompt to switch to default on any error
	if [[ "$process_user_arn" =~ 'error occurred' ]]; then
		continue_maybe "invalid"

		currently_selected_profile_ident_printable="'default'"
		process_user_arn="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --query 'Arn' --output text' \\(after profile reset\\):\\n${ICyan}${process_user_arn}${Color_Off}\\n\\n"
	fi

	# this bails out on errors
	checkAWSErrors "true" "$process_user_arn" "$currently_selected_profile_ident_printable"

	# we didn't bail out; continuing...
	# get the actual username and user account
	# (username may be different from the arbitrary profile ident)
	if [[ "$process_user_arn" =~ ([[:digit:]]+):user.*/([^/]+)$ ]]; then
		profile_user_acc="${BASH_REMATCH[1]}"
		process_username="${BASH_REMATCH[2]}"
	fi

	getAccountAlias _ret
	if [[ "${_ret}" != "" ]]; then
		account_alias_if_any="@${_ret}"
	else 
		account_alias_if_any="@${profile_user_acc}"
	fi

	echo -e "Executing this script as the AWS/IAM user $process_username $account_alias_if_any (profile $currently_selected_profile_ident_printable).\\n"

fi
## END REMOVE?

	# declare the arrays for baseprofile loop
	declare -a baseprofile_ident
	declare -a baseprofile_status
	declare -a baseprofile_user
	declare -a baseprofile_arn
	declare -a baseprofile_account
	declare -a baseprofile_account_alias
	declare -a baseprofile_region
	declare -a baseprofile_output
	declare -a baseprofile_mfa
	declare -a baseprofile_mfa_arn
	declare -a baseprofile_mfa_status
	declare -a baseprofile_mfa_mfasec
	cred_profilecounter=0

	echo -ne "${BIWhite}${On_Black}Please wait"



#todo: instead of re-reading credentials file, loop over the unified array?
#todo: create at least roleprofile_ arrays; mfaprofiles are probably embedded in baseprofile arrays

	# read the credentials file
	while IFS='' read -r line || [[ -n "$line" ]]; do
		
		[[ "$line" =~ ^\[(.*)\].* ]] && 
			profile_ident="${BASH_REMATCH[1]}"

		# transfer possible MFA mfasec from config array 
		idxLookup idx confs_ident[@] "$profile_ident"
		if [[ $idx != "" ]]; then
			baseprofile_mfa_mfasec[$cred_profilecounter]=${confs_mfasec[$idx]}
		fi
#----------------
		# only process if profile identifier is present,
		# and if it's not a mfasession profile 
		# (mfasession profiles have '-mfasession' postfix)
		if [[ "$profile_ident" != "" ]] &&
			[[ ! "$profile_ident" =~ -mfasession$ ]] &&
			[[ ! "$profile_ident" =~ -rolesession$ ]] ; then

			# store this profile ident
			baseprofile_ident[$cred_profilecounter]="$profile_ident"

#todo: we already have this info in the profiles (creds) array, no?
			# store this profile region and output format
			baseprofile_region[$cred_profilecounter]=$(aws --profile "$profile_ident" configure get region)
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" configure get region':\\n${ICyan}${baseprofile_region[$cred_profilecounter]}${Color_Off}\\n\\n"
			baseprofile_output[$cred_profilecounter]=$(aws --profile "$profile_ident" configure get output)
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" configure get output':\\n${ICyan}${baseprofile_output[$cred_profilecounter]}${Color_Off}\\n\\n"

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws --profile "$profile_ident" sts get-caller-identity --output text --query 'Arn' 2>&1)"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${user_arn}${Color_Off}\\n\\n"

			if [[ "$user_arn" =~ ^arn:aws ]]; then
				baseprofile_arn[$cred_profilecounter]=$user_arn
			else
				# must be a bad profile
				baseprofile_arn[$cred_profilecounter]=""
			fi

			# get the actual username
			# (may be different from the arbitrary profile ident)
			if [[ "$user_arn" =~ ([[:digit:]]+):user.*/([^/]+)$ ]]; then
				profile_user_acc="${BASH_REMATCH[1]}"
				profile_username="${BASH_REMATCH[2]}"
			fi

			if [[ "$user_arn" =~ 'error occurred' ]]; then
				baseprofile_user[$cred_profilecounter]=""
				baseprofile_account[$cred_profilecounter]=""
			else
				baseprofile_user[$cred_profilecounter]="$profile_username"
				baseprofile_account[$cred_profilecounter]="$profile_user_acc"
			fi

			# get the account alias (if any) for the user/profile
			getAccountAlias _ret "$profile_ident"
			baseprofile_account_alias[$cred_profilecounter]="${_ret}"

			# find the MFA session for the current profile if one exists ("There can be only one")
			# (profile with profilename + "-mfasession" postfix)

#todo: this information is already in the profiles (creds) array, stop re-reading the CREDFILE over and over again!
			while IFS='' read -r line || [[ -n "$line" ]]; do
				[[ "$line" =~ \[(${profile_ident}-mfasession)\]$ ]] &&
				mfa_profile_ident="${BASH_REMATCH[1]}"
			done < "$CREDFILE"
			baseprofile_mfa[$cred_profilecounter]="$mfa_profile_ident"

			# check to see if this profile has access currently
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set following the example policy,
			# this should produce a reasonably reliable result)
			profile_check="$(aws --profile "$profile_ident" iam get-user --query 'User.Arn' --output text 2>&1)"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" iam get-user --query 'User.Arn' --output text':\\n${ICyan}${profile_check}${Color_Off}\\n\\n"

			if [[ "$profile_check" =~ ^arn:aws ]]; then
				baseprofile_status[$cred_profilecounter]="OK"
			else
				baseprofile_status[$cred_profilecounter]="LIMITED"
			fi

			# get MFA ARN if available
			# (obviously not available if a vMFA device
			# isn't configured for the profile)
			mfa_arn="$(aws --profile "$profile_ident" iam list-mfa-devices \
				--user-name "${baseprofile_user[$cred_profilecounter]}" \
				--output text \
				--query 'MFADevices[].SerialNumber' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" iam list-mfa-devices --user-name \"${baseprofile_user[$cred_profilecounter]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${mfa_arn}${Color_Off}\\n\\n"

			if [[ "$mfa_arn" =~ ^arn:aws ]]; then
				baseprofile_mfa_arn[$cred_profilecounter]="$mfa_arn"
			else
				baseprofile_mfa_arn[$cred_profilecounter]=""
			fi

			# If an existing MFA profile was found, check its status
			# (uses timestamps first if available; falls back to
			# less reliable get-user command -- its output depends
			# on IAM policy settings, and while it's usually accurate
			# it's still not as reliable)
			if [[ "$mfa_profile_ident" != "" ]]; then

				getInitTime _ret_timestamp "$mfa_profile_ident"
				getDuration _ret_duration "$mfa_profile_ident"
				getRemaining _ret_remaining "${_ret_timestamp}" "${_ret_duration}"

				if [[ ${_ret_remaining} -eq 0 ]]; then
					# session has expired

					baseprofile_mfa_status[$cred_profilecounter]="EXPIRED"
				elif [[ ${_ret_remaining} -gt 0 ]]; then
					# session time remains

					getPrintableTimeRemaining _ret "${_ret_remaining}"
					baseprofile_mfa_status[$cred_profilecounter]="${_ret} remaining"
				elif [[ ${_ret_remaining} -eq -1 ]]; then
					# no timestamp; legacy or initialized outside of this utility

					mfa_profile_check="$(aws --profile "$mfa_profile_ident" iam get-user --query 'User.Arn' --output text 2>&1)"
					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$mfa_profile_ident\" iam get-user --query 'User.Arn' --output text':\\n${ICyan}${mfa_profile_check}${Color_Off}\\n\\n"

					if [[ "$mfa_profile_check" =~ ^arn:aws ]]; then
						baseprofile_mfa_status[$cred_profilecounter]="OK"
					elif [[ "$mfa_profile_check" =~ ExpiredToken ]]; then
						baseprofile_mfa_status[$cred_profilecounter]="EXPIRED"
					else
						baseprofile_mfa_status[$cred_profilecounter]="LIMITED"
					fi
				fi
			fi
#----------------
			## DEBUG (enable with DEBUG="true" on top of the file)
			if [[ "$DEBUG" == "true" ]]; then

				echo
				echo "PROFILE IDENT: $profile_ident (${baseprofile_status[$cred_profilecounter]})"
				echo "USER ARN: ${baseprofile_arn[$cred_profilecounter]}"
				echo "USER NAME: ${baseprofile_user[$cred_profilecounter]}"
				echo "ACCOUNT ALIAS: ${baseprofile_account_alias[$cred_profilecounter]}"
				echo "MFA ARN: ${baseprofile_mfa_arn[$cred_profilecounter]}"
				echo "MFA SESSION CUSTOM LENGTH (MFASEC): ${baseprofile_mfa_mfasec[$cred_profilecounter]}"
				if [[ "${baseprofile_mfa[$cred_profilecounter]}" == "" ]]; then
					echo "MFA PROFILE IDENT:"
				else
					echo "MFA PROFILE IDENT: ${baseprofile_mfa[$cred_profilecounter]} (${baseprofile_mfa_status[$cred_profilecounter]})"
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

		else

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}Skipping a role or MFA session profile: '$profile_ident'${Color_Off}\\n"

		fi
	done < "$CREDFILE"
	echo -e "${Color_Off}"

	# select the profile (first, single profile + a possible persistent MFA session)
	mfa_req="false"
	if [[ ${#baseprofile_ident[@]} == 1 ]]; then
		echo
		[[ "${baseprofile_user[0]}" != "" ]] && prcpu="${baseprofile_user[0]}" || prcpu="unknown — a bad profile?"

		if [[ "${baseprofile_account_alias[0]}" != "" ]]; then
			prcpaa=" @${baseprofile_account_alias[0]}"
		elif [[ "${baseprofile_account[0]}" != "" ]]; then
			# use the AWS account number if no alias has been defined
			prcpaa=" @${baseprofile_account[0]}"
		else
			# or nothing for a bad profile
			prcpaa=""
		fi

		echo -e "${Green}${On_Black}You have one configured profile: ${BIGreen}${baseprofile_ident[0]} ${Green}(IAM: ${prcpu}${prcpaa})${Color_Off}"

		mfa_session_status="false"	
		if [[ "${baseprofile_mfa_arn[0]}" != "" ]]; then
			echo ".. its vMFAd is enabled"

			if [[ "${baseprofile_mfa_status[0]}" != "EXPIRED" &&
				"${baseprofile_mfa_status[0]}" != "" ]]; then

				echo -e ".. and it ${BIWhite}${On_Black}has an active MFA session with ${baseprofile_mfa_status[0]}${Color_Off}"

				mfa_session_status="true"
			else
				echo -e ".. but no active persistent MFA sessions exist"
			fi
		else
			echo -e "${BIRed}${On_Black}.. but it doesn't have a virtual MFA device attached/enabled;\\n   cannot continue${Color_Off} (use 'enable-disable-vmfa-device.sh' script\\n   first to enable a vMFAd)!"
			echo
			exit 1
		fi

		echo
		echo "Do you want to:"
		echo -e "${BIWhite}${On_Black}1${Color_Off}: Start/renew an MFA session for the profile mentioned above?"
		echo -e "${BIWhite}${On_Black}2${Color_Off}: Use the above profile as-is (without MFA)?"
		[[ "${mfa_session_status}" == "true" ]] && echo -e "${BIWhite}${On_Black}3${Color_Off}: Resume the existing active MFA session (${baseprofile_mfa_status[0]})?"
		echo
		while :
		do	
			read -s -n 1 -r
			case $REPLY in
				1)
					echo "Starting an MFA session.."
					selprofile="1"
					mfa_req="true"
					break
					;;
				2)
					echo "Selecting the profile as-is (no MFA).."
					selprofile="1"
					break
					;;
				3)
					if [[ "${mfa_session_status}" == "true" ]]; then
						echo "Resuming the existing MFA session.."
						selprofile="1m"
						break
					else 
						echo "Please select one of the options above!"
					fi
					;;
				*)
					echo "Please select one of the options above!"
					;;
			esac
		done

	else  # more than 1 profile

		# create the profile selections
		echo
		echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS PROFILES: ${Color_Off}"
		echo
		SELECTR=0
		ITER=1
		for i in "${baseprofile_ident[@]}"
		do
			if [[ "${baseprofile_mfa_arn[$SELECTR]}" != "" ]]; then
				mfa_notify="; ${Green}${On_Black}vMFAd enabled${Color_Off}"
			else
				mfa_notify="; vMFAd not configured" 
			fi

			[[ "${baseprofile_user[$SELECTR]}" != "" ]] && prcpu="${baseprofile_user[$SELECTR]}" || prcpu="unknown — a bad profile?"

			if [[ "${baseprofile_account_alias[$SELECTR]}" != "" ]]; then
				prcpaa=" @${baseprofile_account_alias[$SELECTR]}"
			elif [[ "${baseprofile_account[$SELECTR]}" != "" ]]; then
				# use the AWS account number if no alias has been defined
				prcpaa=" @${baseprofile_account[$SELECTR]}"
			else
				# or nothing for a bad profile
				prcpaa=""
			fi

			echo -en "${BIWhite}${On_Black}${ITER}: $i${Color_Off} (IAM: ${prcpu}${prcpaa}${mfa_notify})\\n"

			if [[ "${baseprofile_mfa_status[$SELECTR]}" != "EXPIRED" &&
				"${baseprofile_mfa_status[$SELECTR]}" != "" ]]; then
				echo -e "${BIWhite}${On_Black}${ITER}m: $i MFA profile${Color_Off} (${baseprofile_mfa_status[$SELECTR]})"
			fi

			echo
			((ITER++))
			((SELECTR++))
		done

		# this is used to determine whether to trigger a MFA request for a MFA profile
		active_mfa="false"

		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		# prompt for profile selection
		printf "You can switch to a base profile to use it as-is, start an MFA session\\nfor a profile if it is marked as \"vMFAd enabled\", or switch to an existing\\nactive MFA session if any are available (indicated by the letter 'm' after\\nthe profile ID, e.g. '1m'; NOTE: the expired MFA sessions are not shown).\\n"
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE ID:${Color_Off} "
		read -r selprofile
		echo -en  "\\n"

	fi  # end profile selection

	# process the selection
	if [[ "$selprofile" != "" ]]; then
		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_check="${BASH_REMATCH[1]}"
		if [[ "$selprofile_check" != "" ]]; then

			# if the numeric selection was found, 
			# translate it to the array index and validate
			((actual_selprofile=selprofile_check-1))

			profilecount=${#baseprofile_ident[@]}
			if [[ $actual_selprofile -ge $profilecount ||
				$actual_selprofile -lt 0 ]]; then
				# a selection outside of the existing range was specified
				echo -e "There is no profile '${selprofile}'.\\n"

				exit 1
			fi

			# was an existing MFA profile selected?
			[[ $selprofile =~ ^[[:digit:]]+(m)$ ]] &&
				selprofile_mfa_check="${BASH_REMATCH[1]}"

			# if this is an MFA profile, it must be in OK or LIMITED status to select
			if [[ "$selprofile_mfa_check" != "" &&
				"${baseprofile_mfa_status[$actual_selprofile]}" != "EXPIRED" &&
				"${baseprofile_mfa_status[$actual_selprofile]}" != "" ]]; then

				# get the parent profile name
				# transpose selection (starting from 1) to array index (starting from 0)
				mfa_parent_profile_ident="${baseprofile_ident[$actual_selprofile]}"

				final_selection="${baseprofile_mfa[$actual_selprofile]}"
				echo "SELECTED MFA PROFILE: ${final_selection} (for the base profile \"${mfa_parent_profile_ident}\")"

				# this is used to determine whether to print MFA questions/details
				mfaprofile="true"

				# this is used to determine whether to trigger a MFA request for a MFA profile
				active_mfa="true"

			elif [[ "$selprofile_mfa_check" != "" &&
				"${baseprofile_mfa_status[$actual_selprofile]}" == "" ]]; then
				# mfa ('m') profile was selected for a profile that no mfa profile exists
				echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n"
				exit 1

			else
				# a base profile was selected
				if [[ $selprofile =~ ^[[:digit:]]+$ ]]; then 
					echo "SELECTED PROFILE: ${baseprofile_ident[$actual_selprofile]}"
					final_selection="${baseprofile_ident[$actual_selprofile]}"
				else
					# non-acceptable characters were present in the selection
					echo -e "${BIRed}There is no profile '${selprofile}'.${Color_Off}\\n"
					exit 1
				fi
			fi

		else
			# no numeric part in selection
			echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n"
			exit 1
		fi
	else
		# empty selection
		echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n"
		exit 1
	fi

	# this is an MFA request (an MFA ARN exists but the MFA is not active)
	if ( [[ "${baseprofile_mfa_arn[$actual_selprofile]}" != "" &&
		"$active_mfa" == "false" ]] ) ||
		[[ "$mfa_req" == "true" ]]; then  # mfa_req is a single profile MFA request

		# prompt for the MFA code
		echo -e "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${baseprofile_ident[$actual_selprofile]}'${Color_Off} to start/renew an MFA session,\\n\
or leave empty (just press [ENTER]) to use the selected profile without the MFA.\\n"

		while :
		do
			echo -en "${BIWhite}${On_Black}"
			read -p ">>> " -r mfacode
			echo -en "${Color_Off}"
			if ! [[ "$mfacode" =~ ^$ || "$mfacode" =~ [0-9]{6} ]]; then
				echo -e "${BIRed}${On_Black}The MFA pass code must be exactly six digits, or blank to bypass (to use the profile without an MFA session).${Color_Off}"
				continue
			else
				break
			fi
		done

	elif [[ "$active_mfa" == "false" ]]; then   # no vMFAd configured (no vMFAd ARN); print a notice
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		# reset entered MFA code (just to be safe)
		mfacode=""
		echo -e "\\nA vMFAd has not been set up for this profile (run 'enable-disable-vmfa-device.sh' script to configure the vMFAd)."
	fi

	if [[ "$mfacode" != "" ]]; then
		# init an MFA session (request an MFA session token)
		AWS_USER_PROFILE="${baseprofile_ident[$actual_selprofile]}"
		AWS_2AUTH_PROFILE="${AWS_USER_PROFILE}-mfasession"
		ARN_OF_MFA=${baseprofile_mfa_arn[$actual_selprofile]}

		# make sure an entry exists for the MFA profile in ~/.aws/config
		profile_lookup="$(grep "$CONFFILE" -e '^[[:space:]]*\[[[:space:]]*profile '"${AWS_2AUTH_PROFILE}"'[[:space:]]*\][[:space:]]*$')"
		if [[ "$profile_lookup" == "" ]]; then
			echo -en "\\n\\n">> "$CONFFILE"
			echo "[profile ${AWS_2AUTH_PROFILE}]" >> "$CONFFILE"
		fi

		echo -e "\\nAcquiring MFA session token for the profile: ${BIWhite}${On_Black}${AWS_USER_PROFILE}${Color_Off}..."

		getDuration AWS_SESSION_DURATION "$AWS_USER_PROFILE"

		mfa_credentials_result=$(aws --profile "$AWS_USER_PROFILE" sts get-session-token \
			--duration "$AWS_SESSION_DURATION" \
			--serial-number "$ARN_OF_MFA" \
			--token-code $mfacode \
			--output text)

		if [[ "$DEBUG" == "true" ]]; then
			echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$AWS_USER_PROFILE\" sts get-session-token --duration \"$AWS_SESSION_DURATION\" --serial-number \"$ARN_OF_MFA\" --token-code $mfacode --output text':\\n${ICyan}${mfa_credentials_result}${Color_Off}\\n\\n"
		fi

		# this bails out on errors
		checkAWSErrors "true" "$mfa_credentials_result" "$AWS_USER_PROFILE" "An error occurred while attempting to acquire the MFA session credentials; cannot continue!"

		# we didn't bail out; continuing...
		read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< $(printf '%s' "$mfa_credentials_result" | awk '{ print $2, $4, $5 }')

		if [ -z "$AWS_ACCESS_KEY_ID" ]; then
			echo -e "\\n${BIRed}${On_Black}Could not initialize the requested MFA session.${Color_Off}\\n"
			exit 1
		else
			# this is used to determine whether to print MFA questions/details
			mfaprofile="true"
			echo -e "${Green}${On_Black}MFA session token acquired.${Color_Off}\\n"

			# export the selection to the remaining subshell commands in this script
			# so that "--profile" selection is not required, and in fact should not
			# be used for setting the credentials (or else they go to the conffile)
			export AWS_PROFILE=${AWS_2AUTH_PROFILE}
			# Make sure the final selection profile name has '-mfasession' suffix
			# (before this assignment it's not present when going from a base profile to an MFA profile)
			final_selection="$AWS_2AUTH_PROFILE"

			# optionally set the persistent (~/.aws/credentials or custom cred file entries):
			# aws_access_key_id, aws_secret_access_key, and aws_session_token 
			# for the MFA profile
			getPrintableTimeRemaining _ret "$AWS_SESSION_DURATION"
			validity_period=${_ret}

			echo -e "${BIWhite}${On_Black}\
Make this MFA session persistent?${Color_Off} (Saves the session in $CREDFILE\\n\
so that you can return to it during its validity period, ${validity_period}.)"

			read -s -p "$(echo -e "${BIWhite}${On_Black}Yes (default) - make peristent${Color_Off}; No - only the envvars will be used ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
			echo		
			if [[ $REPLY =~ ^[Yy]$ ]] ||
				[[ $REPLY == "" ]]; then

				persistent_MFA="true"
				# NOTE: These do not require the "--profile" switch because AWS_PROFILE
				#       has been exported above. If you set --profile, the details
				#       go to the CONFFILE instead of CREDFILE (so don't set it! :-)
				aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
				aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
				aws configure set aws_session_token "$AWS_SESSION_TOKEN"

				# MFA session profiles: set Init Time in the static profile (a custom key in ~/.aws/credentials)
				# Role session profiles: set Expiration time in the static profile (a custom key in ~/.aws/credentials)
				addInitTime "${AWS_2AUTH_PROFILE}"
			fi
			# init time for envvar exports (if selected)
			AWS_SESSION_INIT_TIME=$(date +%s)

			## DEBUG
			if [[ "$DEBUG" == "true" ]]; then
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

	# export final selection to the environment
	# (no change for the initialized MFA sessions)
	export AWS_PROFILE=$final_selection

	# get region and output format for the selected profile
	AWS_DEFAULT_REGION=$(aws --profile "${final_selection}" configure get region)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${final_selection}\" configure get region':\\n${ICyan}${AWS_DEFAULT_REGION}${Color_Off}\\n\\n"

	AWS_DEFAULT_OUTPUT=$(aws --profile "${final_selection}" configure get output)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${final_selection}\" configure get output':\\n${ICyan}${AWS_DEFAULT_OUTPUT}${Color_Off}\\n\\n"

	# If the region and output format have not been set for this profile, set them.
	# For the parent/base profiles, use defaults; for MFA profiles use first
	# the base/parent settings if present, then the defaults
	if [[ "${AWS_DEFAULT_REGION}" == "" ]]; then
		# retrieve parent profile region if an MFA profie
		if [[ "${baseprofile_region[$actual_selprofile]}" != "" &&
			  "${mfaprofile}" == "true" ]]; then
			set_new_region=${baseprofile_region[$actual_selprofile]}
			echo -e "\\n
NOTE: Region had not been configured for the selected MFA profile;\\n
      it has been set to same as the parent profile ('$set_new_region')."
		fi
		if [[ "${set_new_region}" == "" ]]; then
			if [[ "$default_region" != "" ]]; then
				set_new_region=${default_region}
				echo -e "\\n
NOTE: Region had not been configured for the selected profile;\\n
      it has been set to the default region ('${default_region}')."
      		else
				echo -e "\\n${BIRed}${On_Black}\
NOTE: Region had not been configured for the selected profile\\n\
      and the defaults were not available (the base profiles:\\n\
      the default region; the MFA/role sessions: the region of\\n\
      the parent profile, then the default region). Cannot continue.\\n\\n\
      Please set the default region, or region for the profile\\n\
      (or the parent profile for MFA/role sessions) and try again."

      			exit 1
      		fi
		fi

		AWS_DEFAULT_REGION="${set_new_region}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			aws configure --profile "${final_selection}" set region "${set_new_region}"
		fi
	fi

	if [[ "${AWS_DEFAULT_OUTPUT}" == "" ]]; then
		# retrieve parent profile output format if an MFA profile
		if [[ "${baseprofile_output[$actual_selprofile]}" != "" &&
			"${mfaprofile}" == "true" ]]; then
			set_new_output=${baseprofile_output[$actual_selprofile]}
			echo -e "\
NOTE: The output format had not been configured for the selected MFA profile;\\n
      it has been set to same as the parent profile ('$set_new_output')."
		fi
		if [[ "${set_new_output}" == "" ]]; then
			set_new_output=${default_output}
			echo -e "\
NOTE: The output format had not been configured for the selected profile;\\n
      it has been set to the default output format ('${default_output}')."
		fi
#todo^ was the default set, or is 'json' being used as the default internally?

		AWS_DEFAULT_OUTPUT="${set_new_output}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			aws configure --profile "${final_selection}" set output "${set_new_output}"
		fi
	fi

	if [[ "$mfacode" == "" ]]; then  # this is _not_ a new MFA session, so read in selected persistent values;
									 # for new MFA sessions they are already present
		AWS_ACCESS_KEY_ID=$(aws configure --profile "${final_selection}" get aws_access_key_id)
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure --profile \"${final_selection}\" get aws_access_key_id':\\n${ICyan}${AWS_ACCESS_KEY_ID}${Color_Off}\\n\\n"

		AWS_SECRET_ACCESS_KEY=$(aws configure --profile "${final_selection}" get aws_secret_access_key)
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure --profile \"${final_selection}\" get aws_access_key_id':\\n${ICyan}${AWS_SECRET_ACCESS_KEY}${Color_Off}\\n\\n"
		
		if [[ "$mfaprofile" == "true" ]]; then  # this is a persistent MFA profile (a subset of [[ "$mfacode" == "" ]])
			AWS_SESSION_TOKEN=$(aws configure --profile "${final_selection}" get aws_session_token)
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure --profile \"${final_selection}\" get aws_session_token':\\n${ICyan}${AWS_SESSION_TOKEN}${Color_Off}\\n\\n"

			getInitTime _ret "${final_selection}"
			AWS_SESSION_INIT_TIME=${_ret}
			getDuration _ret "${final_selection}"
			AWS_SESSION_DURATION=${_ret}
		fi
	fi

	echo -e "\\n\\n${BIWhite}${On_DGreen}                            * * * PROFILE DETAILS * * *                            ${Color_Off}\\n"

	if [[ "$mfaprofile" == "true" ]]; then
		echo -e "${BIWhite}${On_Black}MFA profile name: '${final_selection}'${Color_Off}"
		echo
	else
		echo -e "${BIWhite}${On_Black}Profile name '${final_selection}'${Color_Off}"
		echo -e "\\n${BIWhite}${On_Black}NOTE: This is not an MFA session!${Color_Off}"
		echo 
	fi
	echo -e "Region is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_REGION}${Color_Off}"
	echo -e "Output format is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_OUTPUT}${Color_Off}"
	echo

	if [[ "$mfacode" == "" ]] || # re-entering a persistent profile, MFA or not
		( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then # a new persistent MFA session was initialized; 
		# Display the persistent profile's envvar details for export?
		read -s -p "$(echo -e "${BIWhite}${On_Black}Do you want to export the selected profile's secrets to the environment${Color_Off} (for s3cmd, etc)? - Y/${BIWhite}${On_Black}[N]${Color_Off} ")" -n 1 -r
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
		echo -e "${BIWhite}${On_Black}*** THIS IS A NON-PERSISTENT MFA SESSION${Color_Off}! THE MFA SESSION ACCESS KEY ID,\\n    SECRET ACCESS KEY, AND THE SESSION TOKEN ARE *ONLY* SHOWN BELOW!"
		echo
	fi

	if [[ "$OS" == "macOS" ]] ||
		[[ "$OS" == "Linux" ]] ; then

		echo -e "${BIGreen}${On_Black}\
*** It is imperative that the following environment variables are exported/unset\\n\
    as specified below in order to activate your selection! The required\\n\
    export/unset commands have already been copied on your clipboard!\\n\
    ${BIWhite}Just paste on the command line with Command-v, then press [ENTER]\\n\
    to complete the process!${Color_Off}"
		echo

		# since the custom configfile settings were reset,
		# the selected profile is from the default config,
		# and so we need to reset the references in env for
		# consistency
		if [[ "$custom_configfiles_reset" == "true" ]]; then
			envvar_config_clear_custom_config="; unset AWS_CONFIG_FILE; unset AWS_SHARED_CREDENTIALS_FILE"
		else
			envvar_config_clear_custom_config=""
		fi

		if [[ "$final_selection" == "default" ]]; then
			# default profile doesn't need to be selected with an envvar
			envvar_config="unset AWS_PROFILE; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}" 
			if [[ "$OS" == "macOS" ]]; then
				echo -n "$envvar_config" | pbcopy
			elif [[ "$OS" == "Linux" ]] &&
				exists xclip; then

				echo -n "$envvar_config" | xclip -i
				xclip -o | xclip -sel clip

				echo
			fi
			echo "unset AWS_PROFILE"
		else
			envvar_config="export AWS_PROFILE=\"${final_selection}\"; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}"
			if [[ "$OS" == "macOS" ]]; then
				echo -n "$envvar_config" | pbcopy
			elif [[ "$OS" == "Linux" ]] &&
				exists xclip; then

				echo -n "$envvar_config" | xclip -i
				xclip -o | xclip -sel clip
			fi
			echo "export AWS_PROFILE=\"${final_selection}\""
		fi

		if [[ "$custom_configfiles_reset" == "true" ]]; then
			echo "unset AWS_CONFIG_FILE"
			echo "unset AWS_SHARED_CREDENTIALS_FILE"
		fi

		if [[ "$secrets_out" == "false" ]]; then
			echo "unset AWS_ACCESS_KEY_ID"
			echo "unset AWS_SECRET_ACCESS_KEY"
			echo "unset AWS_DEFAULT_REGION"
			echo "unset AWS_DEFAULT_OUTPUT"
			echo "unset AWS_SESSION_INIT_TIME"
			echo "unset AWS_SESSION_DURATION"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\""
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\""
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}"
				echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME}; export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}; export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"${envvar_config_clear_custom_config}"

				if [[ "$OS" == "macOS" ]]; then
					echo -n "$envvar_config" | pbcopy
				elif [[ "$OS" == "Linux" ]] &&
					exists xclip; then

					echo -n "$envvar_config" | xclip -i
					xclip -o | xclip -sel clip
				fi
			else
				echo "unset AWS_SESSION_INIT_TIME"
				echo "unset AWS_SESSION_DURATION"
				echo "unset AWS_SESSION_TOKEN"

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_SESSION_TOKEN${envvar_config_clear_custom_config}"

				if [[ "$OS" == "macOS" ]]; then
					echo -n "$envvar_config" | pbcopy
				elif [[ "$OS" == "Linux" ]] &&
					exists xclip; then

					echo -n "$envvar_config" | xclip -i
					xclip -o | xclip -sel clip
				fi
			fi
		fi
		echo
		if [[ "$OS" == "Linux" ]]; then
			if exists xclip; then
				echo -e "${BIGreen}${On_Black}\
NOTE: xclip found; the envvar configuration command is now on\\n\
      your X PRIMARY clipboard -- just paste on the command line,\\n\
      and press [ENTER])${Color_Off}"

			else

				echo -e "\\n\
NOTE: If you're using an X GUI on Linux, install 'xclip' to have\\n\\
      the activation command copied to the clipboard automatically!"
			fi
		fi

		echo -e "${Green}${On_Black}\\n\
** Make sure to export/unset all the new values as instructed above to\\n\
   make sure no conflicting profile/secrets remain in the environment!${Color_Off}\\n"

		echo -e "${Green}${On_Black}\
** You can temporarily override the profile set/selected in the environment\\n\
   using the \"--profile AWS_PROFILE_NAME\" switch with awscli. For example:${Color_Off}\\n\
   ${BIGreen}${On_Black}aws --profile default sts get-caller-identity${Color_Off}\\n"

		echo -e "${Green}${On_Black}\
** To easily remove any all AWS profile settings and secrets information\\n
   from the environment, simply source the included script, like so:${Color_Off}\\n\
   ${BIGreen}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n"

		echo -e "\\n${BIWhite}${On_Black}\
PASTE THE PROFILE ACTIVATION COMMAND FROM THE CLIPBOARD\\n\
ON THE COMMAND LINE NOW, AND PRESS ENTER! THEN YOU'RE DONE!${Color_Off}\\n"

	else  # not macOS, not Linux, so some other weird OS like Windows..

		echo -e "\
It is imperative that the following environment variables\\n\
are exported/unset to activate the selected profile!\\n"

 		echo -e "\
Execute the following on the command line to activate\\n\
this profile for the 'aws', 's3cmd', etc. commands.\\n"

		echo -e "\
NOTE: Even if you only use a named profile ('AWS_PROFILE'),\\n\
      it's important to execute all of the export/unset commands\\n\
      to make sure previously set environment variables won't override\\n\
      the selected configuration.\\n"

		if [[ "$final_selection" == "default" ]]; then
			# default profile doesn't need to be selected with an envvar
			echo "unset AWS_PROFILE \\"
		else
			echo "export AWS_PROFILE=\"${final_selection}\" \\"
		fi

		# since the custom configfile settings were reset,
		# the selected profile is from the default config,
		# and so we need to reset the references in env for
		# consistency
		if [[ "$custom_configfiles_reset" == "true" ]]; then
			echo "unset AWS_CONFIG_FILE \\"
			echo "unset AWS_SHARED_CREDENTIALS_FILE \\"
		fi

		if [[ "$secrets_out" == "false" ]]; then
			echo "unset AWS_ACCESS_KEY_ID \\"
			echo "unset AWS_SECRET_ACCESS_KEY \\"
			echo "unset AWS_DEFAULT_REGION \\"
			echo "unset AWS_DEFAULT_OUTPUT \\"
			echo "unset AWS_SESSION_INIT_TIME \\"
			echo "unset AWS_SESSION_DURATION \\"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_PROFILE=\"${final_selection}\" \\"
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\" \\"
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\" \\"
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \\"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT} \\"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_INIT_TIME=${AWS_SESSION_INIT_TIME} \\"
				echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION} \\"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""
			else
				echo "unset AWS_SESSION_INIT_TIME \\"
				echo "unset AWS_SESSION_DURATION \\"
				echo "unset AWS_SESSION_TOKEN"
			fi
		fi

		echo -e "\\n\
** Make sure to export/unset all the new values as instructed above to\\n\
   make sure no conflicting profile/secrets remain in the envrionment!\\n"

		echo -e "\\n\
** You can temporarily override the profile set/selected in the environment\\n\
   using the \"--profile AWS_PROFILE_NAME\" switch with awscli. For example:\\n\
   aws --profile default sts get-caller-identity\\n"

		echo -e "\\n\
** To easily remove any all AWS profile settings and secrets information\\n\
   from the environment, simply source the included script, like so:\\n\
   source ./source-this-to-clear-AWS-envvars.sh\\n"

	fi
	echo
fi
