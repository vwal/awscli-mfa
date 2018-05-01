#!/usr/bin/env bash

# todo: handle roles with MFA

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


# DEBUG MODE WARNING =========================================================

[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIWhite}${On_Red} DEBUG MODE ACTIVE ${Color_Off}\\n\\n${BIRed}${On_Black}NOTE: Debug output may include secrets!!!${Color_Off}\\n\\n"


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

		idxLookup profiles_idx profiles_ident[@] "$PRECHECK_AWS_PROFILE"
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
		profile_time=${profiles_session_init_time[$profiles_idx]}
		
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
			echo "** NOTE: THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE CURRENTLY IN EFFECT:"
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

# return the MFA session init time for the given profile
getInitTime() {
	# $1 is _ret
	# $2 is the profile ident

	local this_ident=$2
	local profile_time

	# find the profile's init time entry if one exists
	idxLookup idx profiles_ident[@] "$this_ident"
	profile_time=${profiles_session_init_time[$idx]}

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

already_failed="false"
# here are my args, so..
continue_maybe() {
	# $1 is "invalid" or "expired"

	local failtype=$1

	if [[ "$already_failed" == "false" ]]; then

		if [[ "${failtype}" == "expired" ]]; then  
			echo -e "\\n${BIRed}${On_Black}THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}\\n"
		else
			echo -e "\\n${BIRed}${On_Black}THE AWS PROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}\\n"
		fi

		read -s -p "$(echo -e "${BIWhite}${On_Black}Do you want to continue with the default profile?${Color_Off} - ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]] ||
			[[ $REPLY == "" ]]; then

			already_failed="true"

			# If the defaut profile is already selected
			# and the profile was still defunct (since 
			# we ended up here), make sure non-standard
			# config/credentials files are not used
			if [[ "$AWS_PROFILE" == "" ]] ||
				[[ "$AWS_PROFILE" == "default" ]]; then
			
				unset AWS_SHARED_CREDENTIALS_FILE
				unset AWS_CONFIG_FILE
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
			echo -e "\\n\\nExecute \"source ./source-to-clear-AWS-envvars.sh\", and try again to proceed.\\n"
			exit 1
		fi
	fi
}

checkAWSErrors() {
	# $1 is _ret (_is_error)
	# $2 is exit_on_error (true/false)
	# $3 is the AWS return (may be good or bad)
	# $4 is the 'default' keyword if present
	# $5 is the custom message if present;
	#    only used when $3 is positively present
	#    (such as at MFA token request)

	local exit_on_error=$2
	local aws_raw_return=$3
	local profile_in_use 
	local custom_error
	[[ "$4" == "" ]] && profile_in_use="selected" || profile_in_use="$4"
	[[ "$5" == "" ]] && custom_error="" || custom_error="${5}\\n\\n"

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
	elif [[ "$aws_raw_return" =~ 'AccessDenied' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Access denied!${Red}\\nThe active/selected profile is not authorized for this action.\\nEither you haven't activated an authorized profile, \\nor the effective MFA IAM policy is too restrictive.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'AuthFailure' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Authentication failure!${Red}\\nCheck the credentials for the ${profile_in_use} profile (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'ServiceUnavailable' ]]; then
		echo -en "\\n${BIRed}${On_Black}${custom_error}Service unavailable!${Red}\\nThis is likely a temporary problem with AWS; wait for a moment and try again.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'Throttling' ]]; then
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

	if [[ "$is_error" == "true" && "$exit_on_error" == "true" ]]; then
		exit 1
	elif [[ "$is_error" == "true" ]]; then
		result="true"
	else
		result="false"
	fi

	eval "$1=$result"
}

print_mfa_notice() {
	echo -e "\\n\
To disable/detach a vMFAd from the profile, you must either have\\n\
an active MFA session established with it, or use an admin profile\\n\
that is authorized to remove the MFA for the given profile. Use the\\n\
'awscli-mfa.sh' script to establish an MFA session for the profile\\n\
(or select/activate an MFA session if one exists already), then run\\n\
this script again."

	echo -e "\\n\
If you do not have possession of the vMFAd (in your GA/Authy app) for\\n\
the profile whose vMFAd you wish to disable, please send a request to\\n\
ops to do so. Or, if you have admin credentials for AWS, first activate\\n\
them with the 'awscli-mfa.sh' script, then run this script again.\\n"
}

getAccountAlias() {
	# $1 is _ret (returns the index)
	# $2 is the profile_ident

	local local_profile_ident=$2

	if [[ "$local_profile_ident" != "" ]]; then
		profile_param="--profile $local_profile_ident"
	else
		profile_param=""
	fi

	# get the account alias (if any) for the user/profile
	account_alias_result="$(aws iam list-account-aliases $profile_param --output text --query 'AccountAliases' 2>&1)"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-account-aliases $profile_param --query 'AccountAliases' --output text':\\n${ICyan}${account_alias_result}${Color_Off}\\n\\n"

	if [[ "$account_alias_result" =~ 'error occurred' ]]; then
		# no access to list account aliases for this profile or other error
		result=""
	else
		result="$account_alias_result"
	fi

	eval "$1=$result"
}

## PREREQUISITES CHECK

# is AWS CLI installed?
if ! exists aws ; then
	printf "\\n******************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: http://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html\\n\
******************************************************************************************************************************\\n\\n"
	exit 1
fi 

filexit="false"
# check for ~/.aws directory, and ~/.aws/{config|credentials} files
# # if the custom config defs aren't in effect
if [[ "$AWS_CONFIG_FILE" == "" ]] &&
	[[ "$AWS_SHARED_CREDENTIALS_FILE" == "" ]] &&
	[ ! -d ~/.aws ]; then

	echo
	echo -e "${BIRed}${On_Black}AWSCLI configuration directory '~/.aws' is not present.${Color_Off}\\nMake sure it exists, and that you have at least one profile configured\\nusing the 'config' and 'credentials' files within that directory."
	filexit="true"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ -f "$AWS_CONFIG_FILE" ]; then

	active_config_file=$AWS_CONFIG_FILE
	echo
	echo -e "${BIWhite}${On_Black}** NOTE: A custom configuration file defined with AWS_CONFIG_FILE envvar in effect: '$AWS_CONFIG_FILE'${Color_Off}"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ ! -f "$AWS_CONFIG_FILE" ]; then

	echo
	echo -e "${BIRed}${On_Black}The custom config file defined with AWS_CONFIG_FILE envvar, '$AWS_CONFIG_FILE', is not present.${Color_Off}\\nMake sure it is present or purge the envvar.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"

elif [ -f "$CONFFILE" ]; then
	active_config_file="$CONFFILE"
else
	echo
	echo -e "${BIRed}${On_Black}AWSCLI configuration file '$CONFFILE' was not found.${Color_Off}\\nMake sure it and '$CREDFILE' files exist.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"
fi

# SUPPORT CUSTOM CREDENTIALS FILE SET WITH ENVVAR
if [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	active_credentials_file=$AWS_SHARED_CREDENTIALS_FILE
	echo
	echo -e "${BIWhite}${On_Black}** NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar in effect: '$AWS_SHARED_CREDENTIALS_FILE'${Color_Off}"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ ! -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	echo
	echo -e "${BIRed}${On_Black}The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar, '$AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\nMake sure it is present or purge the envvar.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"

elif [ -f "$CREDFILE" ]; then
	active_credentials_file="$CREDFILE"
else
	echo
	echo -e "${BIRed}${On_Black}AWSCLI credentials file '$CREDFILE' was not found.${Color_Off}\\nMake sure it and '$CONFFILE' files exist.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"
fi

if [[ "$filexit" == "true" ]]; then 
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"

# read the credentials file and make sure that at least one profile is configured
ONEPROFILE="false"
while IFS='' read -r line || [[ -n "$line" ]]; do
	[[ "$line" =~ ^\[(.*)\].* ]] &&
		profile_ident="${BASH_REMATCH[1]}"

		if [[ "$profile_ident" != "" ]]; then
			ONEPROFILE="true"
		fi 
done < "$CREDFILE"

if [[ "$ONEPROFILE" == "false" ]]; then
	echo
	echo -e "${BIRed}${On_Black}NO CONFIGURED AWS PROFILES FOUND.${Color_Off}\\nPlease make sure you have '$CONFFILE' (profile configurations),\\nand '$CREDFILE' (profile credentials) files, and at least\\none configured profile. For more info, see AWS CLI documentation at:\\nhttp://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html"
	echo

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
			echo "** NOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM."
			echo
			;;
	esac

	# make sure ~/.aws/credentials has a linefeed in the end
	c=$(tail -c 1 "$CREDFILE")
	if [[ "$c" != "" ]]; then
		echo "" >> "$CREDFILE"
	fi

	# make sure ~/.aws/config has a linefeed in the end
	c=$(tail -c 1 "$CONFFILE")
	if [[ "$c" != "" ]]; then
		echo "" >> "$CONFFILE"
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
	profiles_iterator=0
	profiles_init=0

	# ugly hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			if [[ $profiles_init -eq 0 ]]; then
				profiles_ident[$profiles_iterator]=$_ret
				profiles_init=1
			fi

			if [[ "$_ret" != "" ]] &&
				! [[ "$_ret" =~ -mfasession$ ]]; then

				profiles_type[$profiles_iterator]="profile"
			else
				profiles_type[$profiles_iterator]="session"
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
			profiles_session_init_time[$profiles_iterator]=${BASH_REMATCH[1]}

	done < "$CREDFILE"

	# init arrays to hold ident<->mfasec detail
	declare -a confs_ident
	declare -a confs_region
	declare -a confs_output
	declare -a confs_mfasec
	confs_init=0
	confs_iterator=0

	# read in the config file params
	while IFS='' read -r line || [[ -n "$line" ]]; do

		if [[ "$line" =~ ^\[[[:space:]]*profile[[:space:]]*(.*)[[:space:]]*\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			if [[ $confs_init -eq 0 ]]; then
				confs_ident[$confs_iterator]=$_ret
				confs_init=1
			elif [[ "${confs_ident[$confs_iterator]}" != "$_ret" ]]; then
				((confs_iterator++))
				confs_ident[$confs_iterator]=$_ret
			fi
		fi

		[[ "$line" =~ ^[[:space:]]*region[[:space:]]*=[[:space:]]*(.*)$ ]] && 
			confs_region[$confs_iterator]=${BASH_REMATCH[1]}

		[[ "$line" =~ ^[[:space:]]*output[[:space:]]*=[[:space:]]*(.*)$ ]] && 
			confs_output[$confs_iterator]=${BASH_REMATCH[1]}

		[[ "$line" =~ ^[[:space:]]*mfasec[[:space:]]*=[[:space:]]*(.*)$ ]] && 
			confs_mfasec[$confs_iterator]=${BASH_REMATCH[1]}

	done < "$CONFFILE"

	# make sure environment has either no config or a functional config
	# before we proceed
	checkEnvSession

	# get default region and output format
	# (since at least one profile should exist at this point, and one should be selected)
	default_region=$(aws configure get region --profile default)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws configure get region --profile default':\\n${ICyan}${default_region}${Color_Off}\\n\\n"

	default_output=$(aws configure get output --profile default)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws configure get output --profile default':\\n${ICyan}${default_output}${Color_Off}\\n\\n"

	if [[ "$default_region" == "" ]]; then
		echo
		echo -e "${BIWhite}${On_Black}THE DEFAULT REGION HAS NOT BEEN CONFIGURED.${Color_Off}\\nPlease set the default region in '$CONFFILE', for example like so:\\naws configure set region \"us-east-1\""
		echo
		exit 1
	fi

	if [[ "$default_output" == "" ]]; then
		aws configure set output "table"
	fi

	echo

	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		current_aws_access_key_id="${AWS_ACCESS_KEY_ID}"
	else
		current_aws_access_key_id="$(aws configure get aws_access_key_id)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}result for: 'aws configure get aws_access_key_id':\\n${ICyan}${current_aws_access_key_id}${Color_Off}\\n\\n"
	fi

	idxLookup idx profiles_key_id[@] "$current_aws_access_key_id"

	if [[ $idx != "" ]]; then 
		currently_selected_profile_ident="'${profiles_ident[$idx]}'"
	else
		if [[ "${PRECHECK_AWS_PROFILE}" != "" ]]; then
			currently_selected_profile_ident="'${PRECHECK_AWS_PROFILE}' [transient]"
		else
			currently_selected_profile_ident="unknown/transient"
		fi
	fi

	process_user_arn="$(aws sts get-caller-identity --query 'Arn' --output text 2>&1)"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}$process_user_arn}${Color_Off}\\n\\n"

	if [[ "$process_user_arn" =~ 'error occurred' ]]; then
		continue_maybe "invalid"

		currently_selected_profile_ident="'default'"
		process_user_arn="$(aws sts get-caller-identity --query 'Arn' --output text 2>&1)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --query 'Arn' --output text' \\(after profile reset\\):\\n${ICyan}${process_user_arn}${Color_Off}\\n\\n"

		[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
			process_username="${BASH_REMATCH[1]}"
	fi

	# this bails out on errors
	checkAWSErrors _is_error "true" "$process_user_arn" "$currently_selected_profile_ident_printable"

	# we didn't bail out; continuing...
	# get the actual username and user account
	# (username may be different from the arbitrary profile ident)
	if [[ "$process_user_arn" =~ ([[:digit:]]+):user/([^/]+)$ ]]; then
		profile_user_acc="${BASH_REMATCH[1]}"
		process_username="${BASH_REMATCH[2]}"
	fi

	getAccountAlias _ret
	if [[ "${_ret}" != "" ]]; then
		account_alias_if_any="@${_ret}"
	else 
		account_alias_if_any="@${profile_user_acc}"
	fi

	# we didn't bail out; continuing...
	echo "Executing this script as the AWS/IAM user $process_username $account_alias_if_any (profile $currently_selected_profile_ident)."

	echo		

	# declare the arrays for credentials loop
	declare -a cred_profiles
	declare -a cred_profile_status
	declare -a cred_profile_user
	declare -a cred_profile_arn
	declare -a cred_profile_account_alias
	declare -a profile_region
	declare -a profile_output
	declare -a mfa_profiles
	declare -a mfa_arns
	declare -a mfa_profile_status
	declare -a mfa_mfasec
	cred_profilecounter=0

	echo -ne "${BIWhite}${On_Black}Please wait"

	# read the credentials file
	while IFS='' read -r line || [[ -n "$line" ]]; do
		
		[[ "$line" =~ ^\[(.*)\].* ]] && 
			profile_ident="${BASH_REMATCH[1]}"

		# transfer possible MFA mfasec from config array 
		idxLookup idx confs_ident[@] "$profile_ident"
		if [[ $idx != "" ]]; then
			mfa_mfasec[$cred_profilecounter]=${confs_mfasec[$idx]}
		fi

		# only process if profile identifier is present,
		# and if it's not a mfasession profile 
		# (mfasession profiles have '-mfasession' postfix)
		if [[ "$profile_ident" != "" ]] &&
			! [[ "$profile_ident" =~ -mfasession$ ]]; then

			# store this profile ident
			cred_profiles[$cred_profilecounter]="$profile_ident"

			# store this profile region and output format
			profile_region[$cred_profilecounter]=$(aws configure get region --profile "$profile_ident")
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure get region --profile \"$profile_ident\"':\\n${ICyan}${profile_region[$cred_profilecounter]}${Color_Off}\\n\\n"
			profile_output[$cred_profilecounter]=$(aws configure get output --profile "$profile_ident")
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws configure get output --profile \"$profile_ident\"':\\n${ICyan}${profile_output[$cred_profilecounter]}${Color_Off}\\n\\n"

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws sts get-caller-identity --profile "$profile_ident" --query 'Arn' --output text 2>&1)"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --profile \"$profile_ident\" --query 'Arn' --output text':\\n${ICyan}${user_arn}${Color_Off}\\n\\n"

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
			if [[ "$profile_username" =~ 'error occurred' ]]; then
				cred_profile_user[$cred_profilecounter]=""
			else
				cred_profile_user[$cred_profilecounter]="$profile_username"
			fi

			# get the account alias (if any) for the user/profile
			getAccountAlias _ret "$profile_ident"
			cred_profile_account_alias[$cred_profilecounter]="${_ret}"

			# find the MFA session for the current profile if one exists ("There can be only one")
			# (profile with profilename + "-mfasession" postfix)
			while IFS='' read -r line || [[ -n "$line" ]]; do
				[[ "$line" =~ \[(${profile_ident}-mfasession)\]$ ]] &&
				mfa_profile_ident="${BASH_REMATCH[1]}"
			done < "$CREDFILE"
		 	mfa_profiles[$cred_profilecounter]="$mfa_profile_ident"

			# check to see if this profile has access currently
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set, this should produce
			# a reasonably reliable result)
			profile_check="$(aws iam get-user --profile "$profile_ident" --query 'User.Arn' --output text 2>&1)"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam get-user --profile \"$profile_ident\" --query 'User.Arn' --output text':\\n${ICyan}${profile_check}${Color_Off}\\n\\n"

			if [[ "$profile_check" =~ ^arn:aws ]]; then
				cred_profile_status[$cred_profilecounter]="OK"
			else
				cred_profile_status[$cred_profilecounter]="LIMITED"
			fi

			# get MFA ARN if available
			# (obviously not available if a MFA device
			# isn't configured for the profile)
			mfa_arn="$(aws iam list-mfa-devices \
				--profile "$profile_ident" \
				--user-name "${cred_profile_user[$cred_profilecounter]}" \
				--output text \
				--query 'MFADevices[].SerialNumber' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-mfa-devices --profile \"$profile_ident\" --user-name \"${cred_profile_user[$cred_profilecounter]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${mfa_arn}${Color_Off}\\n\\n"

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
			if [[ "$mfa_profile_ident" != "" ]]; then

				getInitTime _ret_timestamp "$mfa_profile_ident"
				getDuration _ret_duration "$mfa_profile_ident"
				getRemaining _ret_remaining "${_ret_timestamp}" "${_ret_duration}"

				if [[ ${_ret_remaining} -eq 0 ]]; then
					# session has expired

					mfa_profile_status[$cred_profilecounter]="EXPIRED"
				elif [[ ${_ret_remaining} -gt 0 ]]; then
					# session time remains

					getPrintableTimeRemaining _ret "${_ret_remaining}"
					mfa_profile_status[$cred_profilecounter]="${_ret} remaining"
				elif [[ ${_ret_remaining} -eq -1 ]]; then
					# no timestamp; legacy or initialized outside of this utility

					mfa_profile_check="$(aws iam get-user --profile "$mfa_profile_ident" --query 'User.Arn' --output text 2>&1)"

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam get-user --profile \"$mfa_profile_ident\" --query 'User.Arn' --output text':\\n${ICyan}${mfa_profile_check}${Color_Off}\\n\\n"

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
			if [[ "$DEBUG" == "true" ]]; then

				echo
				echo "PROFILE IDENT: $profile_ident (${cred_profile_status[$cred_profilecounter]})"
				echo "USER ARN: ${cred_profile_arn[$cred_profilecounter]}"
				echo "USER NAME: ${cred_profile_user[$cred_profilecounter]}"
				echo "ACCOUNT ALIAS: ${cred_profile_account_alias[$cred_profilecounter]}"
				echo "MFA ARN: ${mfa_arns[$cred_profilecounter]}"
				echo "MFA SESSION CUSTOM LENGTH (MFASEC): ${mfa_mfasec[$cred_profilecounter]}"
				if [[ "${mfa_profiles[$cred_profilecounter]}" == "" ]]; then
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
			account_alias_result=""
			profile_ident=""
			profile_check=""
			profile_username=""
			mfa_profile_ident=""
			mfa_profile_check=""

			((cred_profilecounter++))

		fi
	done < "$CREDFILE"
	echo -e "${Color_Off}"

	# select the profile (first, single profile + a possible persistent MFA session)
	if [[ ${#cred_profiles[@]} == 1 ]]; then
		echo
		[[ "${cred_profile_user[0]}" != "" ]] && prcpu="${cred_profile_user[0]}" || prcpu="unknown -- a bad profile?"
		[[ "${cred_profile_account_alias[0]}" != "" ]] && prcpaa="@${cred_profile_account_alias[0]}" || prcpaa=""
		echo -e "${Green}${On_Black}You have one configured profile: ${BIGreen}${cred_profiles[0]} ${Green}(IAM: ${prcpu}${prcpaa})${Color_Off}"

		if [[ "${mfa_arns[0]}" != "" ]]; then
			echo -en ".. and its virtual MFA device is already enabled.\\n\\n${BIWhite}${On_Black}Do you want to disable its vMFAd? Y/N${Color_Off} "

			while :
			do	
				read -s -n 1 -r
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					selprofile="-1"
					break;
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					echo -e "\\n\\nA vMFAd not disabled/detached. Exiting.\\n"
					exit 1
					break;
				fi
			done
			echo

		else
			echo -en ".. but it doesn't have a virtual MFA device attached/enabled.\\n\\n${BIWhite}${On_Black}Do you want to attach/enable a vMFAd? Y/N${Color_Off} "
			while :
			do	
				read -s -n 1 -r
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					selprofile="-1"
					break;
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					echo -e "\\n\\nvA MFAd not attached/enabled. Exiting.\\n"
					exit 1
					break;
				fi
			done
			echo

		fi

	else  # more than 1 profile

		declare -a iter_to_profile

		# create the profile selections for "no vMFAd configured" and "vMFAd enabled"
		echo
		echo -e "${BIWhite}${On_Red} AWS PROFILES WITH NO ATTACHED/ENABLED VIRTUAL MFA DEVICE (vMFAd): ${Color_Off}"
		echo -e " ${BIWhite}${On_Black}Select a profile to which you want to attach/enable a vMFAd.${Color_Off}\\n A new vMFAd is created/initialized if one doesn't exist."
		echo
		SELECTR=0
		ITER=1
		for i in "${cred_profiles[@]}"
		do
			if [[ "${mfa_arns[$SELECTR]}" == "" ]]; then
				# no vMFAd configured
				[[ "${cred_profile_user[$SELECTR]}" != "" ]] && prcpu="${cred_profile_user[$SELECTR]}" || prcpu="unknown -- a bad profile?"
				[[ "${cred_profile_account_alias[$SELECTR]}" != "" ]] && prcpaa=" @${cred_profile_account_alias[$SELECTR]}" || prcpaa=""
				echo -en "${BIWhite}${On_Black}${ITER}: $i${Color_Off} (IAM: ${prcpu}${prcpaa})\\n\\n"

				# add to the translation table for the selection
				iter_to_profile[$ITER]=$SELECTR
				((ITER++))
			fi
			((SELECTR++))
		done

		echo
		echo -e "${BIWhite}${On_DGreen} AWS PROFILES WITH ACTIVE (ENABLED) VIRTUAL MFA DEVICE (vMFAd): ${Color_Off}"
		echo -e " ${BIWhite}${On_Black}Select a profile whose vMFAd you want to disable/detach.${Color_Off}\\n Once detached, you'll have the option to delete the vMFAd.\\n NOTE: A profile must have an active MFA session to disable!"
		echo
		SELECTR=0
		for i in "${cred_profiles[@]}"
		do
			if [[ "${mfa_arns[$SELECTR]}" != "" ]]; then
				# vMFAd configured
				[[ "${cred_profile_user[$SELECTR]}" != "" ]] && prcpu="${cred_profile_user[$SELECTR]}" || prcpu="unknown -- a bad profile?"
				[[ "${cred_profile_account_alias[$SELECTR]}" != "" ]] && prcpaa=" @${cred_profile_account_alias[$SELECTR]}" || prcpaa=""
				echo -en "${BIWhite}${On_Black}${ITER}: $i${Color_Off} (IAM: ${prcpu}${prcpaa})\\n\\n"
				# add to the translation table for the selection
				iter_to_profile[$ITER]=$SELECTR
				((ITER++))
			fi
			((SELECTR++))
		done

		# prompt for profile selection
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE NUMBER:${Color_Off} "
		read -r selprofile

	fi  # end profile selection

	# process the selection
	if [[ "$selprofile" == "-1" ]]; then
		selprofile="1"
	fi
	
	if [[ "$selprofile" != "" ]]; then
		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_check="${BASH_REMATCH[1]}"

		if [[ "$selprofile_check" != "" ]]; then
			# if the numeric selection was found, 
			# translate it to the array index and validate
			profilecount=${#cred_profiles[@]}
			if [[ $selprofile_check -gt $profilecount ||
				$selprofile_check -lt 1 ]]; then

				# a selection outside of the existing range was specified
				echo -e "${BIRed}${On_Black}There is no profile with the ID '${selprofile}'.${Color_Off}"
				echo
				exit 1
			else
				translated_selprofile=${iter_to_profile[$selprofile]}
			fi

			# a base profile was selected (sessions are not considered)
			if [[ $selprofile =~ ^[[:digit:]]+$ ]]; then 
				echo 
				final_selection="${cred_profiles[$translated_selprofile]}"

				echo -n "Preparing to "
				idxLookup idx cred_profiles[@] "$final_selection"
				if [[ "${mfa_arns[$idx]}" == "" ]]; then
					echo "enable the vMFAd for the profile..."
					echo

					selected_profile_arn=${cred_profile_arn[idx]}

					if [[ "$selected_profile_arn" =~ ^arn:aws:iam::([[:digit:]]*):user/(.*)$ ]]; then 
						aws_account_id="${BASH_REMATCH[1]}"
						aws_iam_user="${BASH_REMATCH[2]}"
					else
						echo -e "${BIRed}${On_Black}Could not acquire AWS account ID or current IAM user name. A bad profile? Cannot continue.${Color_Off}"
						echo
						exit 1
					fi

					available_user_vmfad=$(aws iam list-virtual-mfa-devices \
						--profile "${final_selection}" \
						--assignment-status Unassigned \
						--output text \
						--query 'VirtualMFADevices[?SerialNumber==`arn:aws:iam::'"${aws_account_id}"':mfa/'"${aws_iam_user}"'`].SerialNumber' 2>&1)

					if [[ "$DEBUG" == "true" ]]; then
						echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-virtual-mfa-devices --profile \"${final_selection}\" --assignment-status Unassigned --query 'VirtualMFADevices[?SerialNumber==´arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}´].SerialNumber' --output text':\\n${ICyan}${available_user_vmfad}${Color_Off}\\n\\n"
					fi

					existing_mfa_deleted="false"
					if [[ "$available_user_vmfad" =~ 'error occurred' ]]; then
						echo -e "${BIRed}${On_Black}Could not execute list-virtual-mfa-devices. Cannot continue.${Color_Off}"
						echo
						exit 1
					elif [[ "$available_user_vmfad" != "" ]]; then
						unassigned_vmfad_preexisted="true"

						echo -e "${Green}${On_Black}Unassigned vMFAd found for the profile:\\n${BIGreen}$available_user_vmfad${Color_Off}\\n"
						echo -en "${BIWhite}${On_Black}Do you have access to the above vMFAd on your GA/Authy device?${Color_Off}\\nNOTE: 'No' will delete the vMFAd and create a new one\\n(thus voiding a possible existing GA/Authy entry), so\\nmake your choice: ${BIWhite}${On_Black}Y/N${Color_Off} "

						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Yy]$ ]]; then
								break;
							elif [[ $REPLY =~ ^[Nn]$ ]]; then
								mfa_deletion_result=$(aws iam delete-virtual-mfa-device \
									--profile "${final_selection}" \
									--serial-number "${available_user_vmfad}" 2>&1)

								if [[ "$DEBUG" == "true" ]]; then
									echo -e "\\n${Cyan}${On_Black}result for: 'aws iam delete-virtual-mfa-device --profile \"${final_selection}\" --serial-number \"${available_user_vmfad}\"':\\n${ICyan}${mfa_deletion_result}${Color_Off}\\n\\n"
								fi

								# this bails out on errors
								checkAWSErrors _is_error "true" "$mfa_deletion_result" "$final_selection" "Could not delete the inaccessible vMFAd. Cannot continue!"

								# we didn't bail out; continuing...
								echo -e "\\n\\nThe old vMFAd has been deleted."
								existing_mfa_deleted="true"
								break;
							fi
						done
					fi

					if [[ "$available_user_vmfad" == "" ]] ||
						[[ "$existing_mfa_deleted" == "true" ]]; then
						# no vMFAd was found, create new..

						unassigned_vmfad_preexisted="false"

						qr_file_name="${final_selection} vMFAd QRCode.png"

						if [[ "$OS" == "macOS" ]]; then
							qr_file_target="on your DESKTOP"
							qr_with_path="${HOME}/Desktop/${qr_file_name}"
						elif [[ -d $HOME/Desktop ]]; then
							qr_file_target="on your DESKTOP"
							qr_with_path="${HOME}/Desktop/${qr_file_name}"
						else
							qr_file_target="in your HOME DIRECTORY ($HOME)"
							qr_with_path="${HOME}/${qr_file_name}"
						fi

						echo
						echo "No available vMFAd found; creating new..."
						echo
						vmfad_creation_status=$(aws iam create-virtual-mfa-device \
							--profile "${final_selection}" \
							--virtual-mfa-device-name "${aws_iam_user}" \
							--outfile "${qr_with_path}" \
							--bootstrap-method QRCodePNG 2>&1)

						if [[ "$DEBUG" == "true" ]]; then
							echo -e "\\n${Cyan}${On_Black}result for: 'aws iam create-virtual-mfa-device --profile \"${final_selection}\" --virtual-mfa-device-name \"${aws_iam_user}\" --outfile \"${qr_with_path}\" --bootstrap-method QRCodePNG':\\n${ICyan}${vmfad_creation_status}${Color_Off}\\n\\n"
						fi

						# this bails out on errors
						checkAWSErrors _is_error "true" "$vmfad_creation_status" "$final_selection" "Could not execute create-virtual-mfa-device. No virtual MFA device to enable. Cannot continue!"

						# we didn't bail out; continuing...
						echo -e "${BIGreen}${On_Black}A new vMFAd has been created. ${BIWhite}${On_Black}Please scan\\nthe QRCode with Authy to add the vMFAd on\\nyour portable device.${Color_Off}\\n" 
						echo -e "NOTE: The QRCode file, \"${qr_file_name}\",\\nis $qr_file_target!"
						echo
						echo -e "${BIWhite}${On_Black}Press 'x' once you have scanned the QRCode to proceed.${Color_Off}"
						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Xx]$ ]]; then
								break;
							fi
						done

						echo
						echo -en "NOTE: Anyone who gains possession of the QRCode file\\n      can initialize the vMFDd like you just did, so\\n      optimally it should not be kept around.\\n\\n${BIWhite}${On_Black}Do you want to delete the QRCode securely? Y/N${Color_Off} "

						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Yy]$ ]]; then
								rm -fP "${qr_with_path}"
								echo
								echo -e "${BIWhite}${On_Black}QRCode file deleted securely.${Color_Off}"
								break;
							elif [[ $REPLY =~ ^[Nn]$ ]]; then
								echo
								echo -e "${BIWhite}${On_Black}You chose not to delete the vMFAd initializer QRCode;\\nplease store it securely as if it were a password!${Color_Off}"
								break;
							fi
						done
						echo

						available_user_vmfad=$(aws iam list-virtual-mfa-devices \
							--profile "${final_selection}" \
							--assignment-status Unassigned \
							--output text \
							--query 'VirtualMFADevices[?SerialNumber==`arn:aws:iam::'"${aws_account_id}"':mfa/'"${aws_iam_user}"'`].SerialNumber' 2>&1)
							
						if [[ "$DEBUG" == "true" ]]; then
							echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-virtual-mfa-devices --profile \"${final_selection}\" --assignment-status Unassigned --query \'VirtualMFADevices[?SerialNumber==´arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}´].SerialNumber' --output text':\\n${ICyan}${available_user_vmfad}${Color_Off}\\n\\n"
						fi

						# this bails out on errors
						checkAWSErrors _is_error "true" "$available_user_vmfad" "$final_selection" "Could not execute list-virtual-mfa-devices. Cannot continue!"

						# we didn't bail out; continuing...
					fi

					if [[ "$available_user_vmfad" == "" ]]; then
						# no vMFAd existed, none could be created
						echo -e "\\n\\n${BIRed}${On_Black}No virtual MFA device to enable. Cannot continue.${Color_Off}"
						exit 1
					else
						[[ "$unassigned_vmfad_preexisted" == "true" ]] && vmfad_source="existing" || vmfad_source="newly created"
						echo -e "\\n\\nEnabling the $vmfad_source virtual MFA device:\\n$available_user_vmfad\\n"
					fi

					echo
					echo -e "${BIWhite}${On_Black}Please enter two consecutively generated authcodes from your\\nGA/Authy app for this profile.${Color_Off} Enter the two six-digit codes\\nseparated by a space (e.g. 123456 456789), then press enter\\nto complete the process.\\n"

					while :
					do	
						read -p ">>> " -r authcodes
						if [[ $authcodes =~ ^([[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]])[[:space:]]+([[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]])$ ]]; then
							authcode1="${BASH_REMATCH[1]}"
							authcode2="${BASH_REMATCH[2]}"
							break;
						else
							echo -e "${BIRed}${On_Black}Bad authcodes.${Color_Off} Please enter two consecutively generated six-digit numbers separated by a space."
						fi
					done

					echo

					vmfad_enablement_status=$(aws iam enable-mfa-device \
						--profile "${final_selection}" \
						--user-name "${aws_iam_user}" \
						--serial-number "${available_user_vmfad}" \
						--authentication-code-1 "${authcode1}" \
						--authentication-code-2 "${authcode2}"  2>&1)

					if [[ "$DEBUG" == "true" ]]; then
						echo -e "\\n${Cyan}${On_Black}result for: 'aws iam enable-mfa-device --profile \"${final_selection}\" --user-name \"${aws_iam_user}\" --serial-number \"${available_user_vmfad}\" --authentication-code-1 \"${authcode1}\" --authentication-code-2 \"${authcode2}\"':\\n${ICyan}${vmfad_enablement_status}${Color_Off}\\n\\n"
					fi

					# this bails out on errors
					checkAWSErrors _is_error "true" "$vmfad_enablement_status" "$final_selection" "Could not enable vMFAd. Cannot continue.\\n${Red}Mistyped authcodes, or wrong/old vMFAd?"

					# we didn't bail out; continuing...
					echo -e "${BIGreen}${On_Black}vMFAd successfully enabled for the profile '${final_selection}' ${Green}(IAM user name '$aws_iam_user').${Color_Off}"
					echo -e "${BIGreen}${On_Black}You can now use the 'awscli-mfa.sh' script to start an MFA session for this profile!${Color_Off}"
					echo

				else
					echo -e "disable the vMFAd for the profile...\\n"

					transient_mfa_profile_check="$(aws sts get-caller-identity --profile "${final_selection}" --query 'Arn' --output text 2>&1)"
					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws sts get-caller-identity --profile \"${final_selection}\" --query 'Arn' --output text':\\n${ICyan}${transient_mfa_profile_check}${Color_Off}\\n\\n"

					# this bails out on errors
					checkAWSErrors _is_error "true" "$transient_mfa_profile_check" "transient/unknown" "Could not acquire AWS account ID or current IAM user name. A bad profile? Cannot continue!"

					# we didn't bail out; continuing...
					if [[ "$transient_mfa_profile_check" =~ ^arn:aws:iam::([[:digit:]]*):user/(.*)$ ]]; then 
						aws_account_id="${BASH_REMATCH[1]}" # this AWS account
						aws_iam_user="${BASH_REMATCH[2]}" # IAM user of the (hopefully :-) active MFA session
					else
						# .. but so does this, just in case to make sure script exits
						# if there is nothing to work with
						echo -e "${BIRed}${On_Black}Could not acquire AWS account ID or current IAM user name. A bad profile? Cannot continue.${Color_Off}\\n"
						echo
						exit 1
					fi

					_ret_remaining="undefined"
					# First checking the envvars
					if [[ "$PRECHECK_AWS_PROFILE" =~ ^${final_selection}$ || 
						  "$PRECHECK_AWS_PROFILE" == "" ]] &&

						[[ "$PRECHECK_AWS_SESSION_TOKEN" == "" ]] &&
						[[ "$PRECHECK_AWS_SESSION_INIT_TIME" == "" ]] &&
						[[ "$PRECHECK_AWS_SESSION_DURATION" == "" ]]; then
						# this is a authorized (?) base profile or 'default'

						echo -en "${BIWhite}${On_Black}A base profile ${currently_selected_profile_ident} (IAM: ${process_username} ${account_alias_if_any})\\nis currently in effect instead of an MFA session for the profile\\nwhose vMFAd you want to disable. Do you want to attempt to disable\\nthe vMFAd with the selected profile (the selected profile must have\\nthe authority to disable a vMFAd without an active MFA session\\nand/or for the IAM users other than itself)? Y/N${Color_Off} "

						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Yy]$ ]]; then
								break;
							elif [[ $REPLY =~ ^[Nn]$ ]]; then
								echo -e "\\n\\nThe vMFAd not disabled/detached. Exiting.\\n"
								exit 1
								break;
							fi
						done
						echo

					elif [[ "$PRECHECK_AWS_PROFILE" =~ ^${final_selection}-mfasession$ ]] &&
						[[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
						[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]] &&
						[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]]; then
						# this is a MFA profile in the environment

						getRemaining _ret_remaining "$PRECHECK_AWS_SESSION_INIT_TIME" "$PRECHECK_AWS_SESSION_DURATION"
					
					elif [[ "$PRECHECK_AWS_PROFILE" =~ ^${final_selection}-mfasession$ ]] &&
							[[ "$profiles_idx" != "" ]]; then
							# this is a selected persistent MFA profile

						# find the selected persistent MFA profile's init time if one exists
						profile_time=${profiles_session_init_time[$profiles_idx]}
						
						# if the duration for the current profile is not set
						# (as is usually the case with the mfaprofiles), use
						# the parent/base profile's duration
						if [[ "$profile_time" != "" ]]; then
							getDuration parent_duration "$PRECHECK_AWS_PROFILE"
							getRemaining _ret_remaining "$profile_time" "$parent_duration"
						fi

					elif [[ "$PRECHECK_AWS_PROFILE" == "" ]] &&
							[[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
							[[ "$PRECHECK_AWS_SESSION_INIT_TIME" != "" ]] &&
							[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]]; then
							# this is a transient profile, check for which base profile

						idxLookup persistent_equivalent_idx cred_profile_user[@] "$aws_iam_user"
						if [[ "${persistent_equivalent_idx}" != "" ]]; then
							# IAM user of the transient in-env MFA session matches
							# the IAM user of the selected persistent base profile								

							getRemaining _ret_remaining "$PRECHECK_AWS_SESSION_INIT_TIME" "$PRECHECK_AWS_SESSION_DURATION"

						else
							echo -e "${BIRed}${On_Black}This is an unknown in-env MFA session. Cannot continue.${Color_Off}\\n"
							print_mfa_notice
							exit 1
						fi						

						echo -e "${BIRed}${On_Black}No active MFA session found for the profile '${final_selection}'.\\nAn active MFA session for the profile, or an authorized\\nbase profile is required for this action.${Color_Off}\\n"
						print_mfa_notice
						echo
						exit 1
					fi

					if [[ "${_ret_remaining}" != "undefined" && ${_ret_remaining} -gt 120 || # at least 120 seconds of the session remains
						"${_ret_remaining}" == "undefined" ]]; then # .. or we try with a base profile

						# the profile is not defined below because an active MFA session or an admin profile must be used

						vmfad_deactivation_result=$(aws iam deactivate-mfa-device \
							--user-name "${aws_iam_user}" \
							--serial-number "arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}" 2>&1)

						[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam deactivate-mfa-device --profile \"${final_selection}\" --user-name \"${aws_iam_user}\" --serial-number \"arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\"':\\n${ICyan}${vmfad_deactivation_result}${Color_Off}\\n\\n"

						# this bails out on errors
						checkAWSErrors _is_error "false" "$vmfad_deactivation_result" "$final_selection" "Could not disable/detach vMFAd for the profile '${final_selection}'. Cannot continue!"

						if [[ "${_is_error}" == "true" ]]; then
							print_mfa_notice
							exit 1
						fi

						# we didn't bail out; continuing...
						echo
						echo -e "${BIGreen}${On_Black}vMFAd disabled/detached for the profile '${final_selection}'.${Color_Off}"
						echo

						echo -en "${BIWhite}${On_Black}Do you want to ${BIRed}DELETE${BIWhite} the disabled/detached vMFAd? Y/N${Color_Off} "
						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Yy]$ ]]; then
								vmfad_delete_result=$(aws iam delete-virtual-mfa-device \
									--profile "${final_selection}" \
									--serial-number "arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}")

								[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam delete-virtual-mfa-device --profile \"${final_selection}\" --serial-number \"arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\"':\\n${ICyan}${vmfad_delete_result}${Color_Off}\\n\\n"

								# this bails out on errors
								checkAWSErrors _is_error "true" "$vmfad_delete_result" "$final_selection" "Could not delete vMFAd for the profile '${final_selection}'. Cannot continue!"

								# we didn't bail out; continuing...
								echo -e "\\n${BIGreen}${On_Black}vMFAd deleted for the profile '${final_selection}'.${Color_Off}"
								echo 
								echo "To set up a new vMFAd, run this script again."
								echo
								break;
							elif [[ $REPLY =~ ^[Nn]$ ]]; then
								echo -e "\\n\\n${BIWhite}${On_Black}The following vMFAd was disabled/detached, but not deleted:${Color_Off}\\narn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\\n\\nNOTE: Detached vMFAd's may be automatically deleted after some time.\\n"
								exit 1
								break;
							fi
						done

					else
						echo -e "\\n${BIRed}${On_Black}The MFA session for the profile \"${final_selection}\" has expired.${Color_Off}\\n"
						print_mfa_notice
						echo
						exit 1
					fi
					exit 1
				fi
			else
				# non-acceptable characters were present in the selection
				echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}"
				echo
				exit 1
			fi
		else
			# no numeric part in selection
			echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}"
			echo
			exit 1
		fi
	else
		# empty selection
		echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}"
		echo
		exit 1
	fi
fi
