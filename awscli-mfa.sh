#!/usr/bin/env bash

# todo: handle roles with MFA
# todo: handle root account max session time @3600 & warn if present

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
		# no time entry exists for the profile; add on a new line after the header "[${this_ident}]"
		replace_me="\\[${this_ident}\\]"
		DATA="[${this_ident}]\\naws_session_init_time = ${this_time}"
		echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${CREDFILE}")" > "${CREDFILE}"
	fi

	# update the selected profile's existing
	# init time entry in this script
	idxLookup idx profiles_ident[@] "$this_ident"
	profiles_session_init_time[$idx]=$this_time
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
			echo -e "\\n${BIRed}THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}\\n"
		else
			echo -e "\\n${BIRed}THE AWS PROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}\\n"
		fi

		read -s -p "$(echo -e "${BIWhite}Do you want to continue with the default profile?${Color_Off} - ${BIWhite}[Y]${Color_Off}/N ")" -n 1 -r
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
			echo -e "\\n\\nExecute \"source ./source-to-clear-AWS-envvars.sh\", and try again to proceed.\\n"
			exit 1
		fi
	fi
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
	echo -e "${BIRed}AWSCLI configuration directory '~/.aws' is not present.${Color_Off}\\nMake sure it exists, and that you have at least one profile configured\\nusing the 'config' and 'credentials' files within that directory."
	filexit="true"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ -f "$AWS_CONFIG_FILE" ]; then

	active_config_file=$AWS_CONFIG_FILE
	echo
	echo -e "${BIWhite}** NOTE: A custom configuration file defined with AWS_CONFIG_FILE envvar in effect: '$AWS_CONFIG_FILE'${Color_Off}"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[ ! -f "$AWS_CONFIG_FILE" ]; then

	echo
	echo -e "${BIRed}The custom config file defined with AWS_CONFIG_FILE envvar, '$AWS_CONFIG_FILE', is not present.${Color_Off}\\nMake sure it is present or purge the envvar.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"

elif [ -f "$CONFFILE" ]; then
	active_config_file="$CONFFILE"
else
	echo
	echo -e "${BIRed}AWSCLI configuration file '$CONFFILE' was not found.${Color_Off}\\nMake sure it and '$CREDFILE' files exist.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"
fi

# SUPPORT CUSTOM CREDENTIALS FILE SET WITH ENVVAR
if [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	active_credentials_file=$AWS_SHARED_CREDENTIALS_FILE
	echo
	echo -e "${BIWhite}** NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar in effect: '$AWS_SHARED_CREDENTIALS_FILE'${Color_Off}"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[ ! -f "$AWS_SHARED_CREDENTIALS_FILE" ]; then

	echo
	echo -e "${BIRed}The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar, '$AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\nMake sure it is present or purge the envvar.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"

elif [ -f "$CREDFILE" ]; then
	active_credentials_file="$CREDFILE"
else
	echo
	echo -e "${BIRed}AWSCLI credentials file '$CREDFILE' was not found.${Color_Off}\\nMake sure it and '$CONFFILE' files exist.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"
fi

if [[ "$filexit" == "true" ]]; then 
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"
custom_configfiles_reset="false"

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
	echo -e "${BIRed}NO CONFIGURED AWS PROFILES FOUND.${Color_Off}\\nPlease make sure you have '$CONFFILE' (profile configurations),\\nand '$CREDFILE' (profile credentials) files, and at least\\none configured profile. For more info, see AWS CLI documentation at:\\nhttp://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html"
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
	persistent_MFA="false"
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
	default_output=$(aws configure get output --profile default)

	if [[ "$default_region" == "" ]]; then
		echo
		echo -e "${BIWhite}THE DEFAULT REGION HAS NOT BEEN CONFIGURED.${Color_Off}\\nPlease set the default region in '$CONFFILE', for example like so:\\naws configure set region \"us-east-1\""
		echo
		exit 1
	fi

	if [[ "$default_output" == "" ]]; then
		aws configure set output "table"
	fi

	echo

	[[ "$AWS_ACCESS_KEY_ID" != "" ]] &&  
		current_aws_access_key_id="${AWS_ACCESS_KEY_ID}" ||
		current_aws_access_key_id="$(aws configure get aws_access_key_id)"

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

	process_user_arn="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"

	[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
		process_username="${BASH_REMATCH[1]}"

	if [[ "$process_username" =~ ExpiredToken ]]; then
		continue_maybe "invalid"

		currently_selected_profile_ident="'default'"
		process_user_arn="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"

		[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
			process_username="${BASH_REMATCH[1]}"
	fi

	if [[ "$process_username" =~ error ]]; then
		echo -e "${BIRed}The selected profile is not functional${Color_Off}; please check the 'default' profile\\nin your '${CREDFILE}' file, and purge any 'AWS_' environment variables by executing\\n${Green}source ./source-to-clear-AWS-envvars.sh${Color_Off}"
		exit 1
	else
		echo "Executing this script as the AWS/IAM user '$process_username' (profile $currently_selected_profile_ident)."
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

	echo -ne "${BIWhite}Please wait"

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
			profile_region[$cred_profilecounter]=$(aws --profile "$profile_ident" configure get region)
			profile_output[$cred_profilecounter]=$(aws --profile "$profile_ident" configure get output)

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws sts get-caller-identity --profile "$profile_ident" --output text --query 'Arn' 2>&1)"
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
			done < "$CREDFILE"
			mfa_profiles[$cred_profilecounter]="$mfa_profile_ident"

			# check to see if this profile has access currently
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set, this should produce
			# a reasonably reliable result)
			profile_check="$(aws iam get-user --output text --query "User.Arn" --profile "$profile_ident" 2>&1)"
			if [[ "$profile_check" =~ ^arn:aws ]]; then
				cred_profile_status[$cred_profilecounter]="OK"
			else
				cred_profile_status[$cred_profilecounter]="LIMITED"
			fi

			# get MFA ARN if available
			# (obviously not available if a MFA device
			# isn't configured for the profile)
			mfa_arn="$(aws iam list-mfa-devices --profile "$profile_ident" --user-name "${cred_profile_user[$cred_profilecounter]}" --output text --query "MFADevices[].SerialNumber" 2>&1)"
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

					mfa_profile_check="$(aws iam get-user --output text --query "User.Arn" --profile "$mfa_profile_ident" 2>&1)"
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
				echo "MFA ARN: ${mfa_arns[$cred_profilecounter]}"
				echo "MFA MAXSEC: ${mfa_mfasec[$cred_profilecounter]}"
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
	mfa_req="false"
	if [[ ${#cred_profiles[@]} == 1 ]]; then
		echo
		[[ "${cred_profile_user[0]}" != "" ]] && prcpu="${cred_profile_user[0]}" || prcpu="unknown -- a bad profile?"
		echo -e "${Green}You have one configured profile: ${BIGreen}${cred_profiles[0]} ${Green}(IAM: ${prcpu})${Color_Off}"

		mfa_session_status="false"	
		if [[ "${mfa_arns[0]}" != "" ]]; then
			echo ".. its vMFAd is enabled"

			if [[ "${mfa_profile_status[0]}" != "EXPIRED" &&
				"${mfa_profile_status[0]}" != "" ]]; then

				echo -e ".. and it ${BIWhite}has an active MFA session with ${mfa_profile_status[0]}${Color_Off}"

				mfa_session_status="true"
			else
				echo -e ".. but no active persistent MFA sessions exist"
			fi
		else
			echo -e "${BIRed}.. but it doesn't have a virtual MFA device attached/enabled;\\n   cannot continue${Color_Off} (use 'enable-disable-vmfa-device.sh' script\\n   first to enable a vMFAd)!"
			echo
			exit 1
		fi

		echo
		echo "Do you want to:"
		echo -e "${BIWhite}1${Color_Off}: Start/renew an MFA session for the profile mentioned above?"
		echo -e "${BIWhite}2${Color_Off}: Use the above profile as-is (without MFA)?"
		[[ "${mfa_session_status}" == "true" ]] && echo -e "${BIWhite}3${Color_Off}: Resume the existing active MFA session (${mfa_profile_status[0]})?"
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
		for i in "${cred_profiles[@]}"
		do
			if [[ "${mfa_arns[$SELECTR]}" != "" ]]; then
				mfa_notify="; ${Green}vMFAd enabled${Color_Off}"
			else
				mfa_notify="; vMFAd not configured" 
			fi
			[[ "${cred_profile_user[$SELECTR]}" != "" ]] && prcpu="${cred_profile_user[$SELECTR]}" || prcpu="unknown -- a bad profile?"
			echo -en "${BIWhite}${ITER}: $i${Color_Off} (IAM: ${prcpu}${mfa_notify})\\n"

			if [[ "${mfa_profile_status[$SELECTR]}" != "EXPIRED" &&
				"${mfa_profile_status[$SELECTR]}" != "" ]]; then
				echo -e "${BIWhite}${ITER}m: $i MFA profile${Color_Off} (${mfa_profile_status[$SELECTR]})"
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
		echo -en  "\\n${BIWhite}SELECT A PROFILE BY THE ID: "
		read -r selprofile
		echo -en  "\\n${Color_Off}"

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
				echo "SELECTED MFA PROFILE: ${final_selection} (for the base profile \"${mfa_parent_profile_ident}\")"

				# this is used to determine whether to print MFA questions/details
				mfaprofile="true"

				# this is used to determine whether to trigger a MFA request for a MFA profile
				active_mfa="true"

			elif [[ "$selprofile_mfa_check" != "" &&
				"${mfa_profile_status[$actual_selprofile]}" == "" ]]; then
				# mfa ('m') profile was selected for a profile that no mfa profile exists
				echo -e "${BIRed}There is no profile '${selprofile}'.${Color_Off}"
				echo
				exit 1

			else
				# a base profile was selected
				if [[ $selprofile =~ ^[[:digit:]]+$ ]]; then 
					echo "SELECTED PROFILE: ${cred_profiles[$actual_selprofile]}"
					final_selection="${cred_profiles[$actual_selprofile]}"
				else
					# non-acceptable characters were present in the selection
					echo -e "${BIRed}There is no profile '${selprofile}'.${Color_Off}"
					echo
					exit 1
				fi
			fi

		else
			# no numeric part in selection
			echo -e "${BIRed}There is no profile '${selprofile}'.${Color_Off}"
			echo
			exit 1
		fi
	else
		# empty selection
		echo -e "${BIRed}There is no profile '${selprofile}'.${Color_Off}"
		echo
		exit 1
	fi

	# this is an MFA request (an MFA ARN exists but the MFA is not active)
	if ( [[ "${mfa_arns[$actual_selprofile]}" != "" &&
		"$active_mfa" == "false" ]] ) ||
		[[ "$mfa_req" == "true" ]]; then  # mfa_req is a single profile MFA request

		# prompt for the MFA code
		echo
		echo -e "${BIWhite}Enter the current MFA one time pass code for the profile '${cred_profiles[$actual_selprofile]}'${Color_Off} to start/renew an MFA session,"
		echo "or leave empty (just press [ENTER]) to use the selected profile without the MFA."
		echo
		while :
		do
			echo -en "${BIWhite}"
			read -p ">>> " -r mfacode
			echo -en "${Color_Off}"
			if ! [[ "$mfacode" =~ ^$ || "$mfacode" =~ [0-9]{6} ]]; then
				echo -e "${BIRed}The MFA pass code must be exactly six digits, or blank to bypass (to use the profile without an MFA session).${Color_Off}"
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
		echo
		echo -e "A vMFAd has not been set up for this profile (run 'enable-disable-vmfa-device.sh' script to configure the vMFAd)."
	fi

	if [[ "$mfacode" != "" ]]; then
		# init an MFA session (request an MFA session token)
		AWS_USER_PROFILE="${cred_profiles[$actual_selprofile]}"
		AWS_2AUTH_PROFILE="${AWS_USER_PROFILE}-mfasession"
		ARN_OF_MFA=${mfa_arns[$actual_selprofile]}

		# make sure an entry exists for the MFA profile in ~/.aws/config
		profile_lookup="$(grep "$CONFFILE" -e '^[[:space:]]*\[[[:space:]]*profile '"${AWS_2AUTH_PROFILE}"'[[:space:]]*\][[:space:]]*$')"
		if [[ "$profile_lookup" == "" ]]; then
			echo >> "$CONFFILE"
			echo "[profile ${AWS_2AUTH_PROFILE}]" >> "$CONFFILE"
		fi

		echo
		echo -e "Acquiring MFA session token for the profile: ${BIWhite}${AWS_USER_PROFILE}${Color_Off}..."

		getDuration AWS_SESSION_DURATION "$AWS_USER_PROFILE"

		read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< \
		$(aws --profile "$AWS_USER_PROFILE" sts get-session-token \
		  --duration "$AWS_SESSION_DURATION" \
		  --serial-number "$ARN_OF_MFA" \
		  --token-code $mfacode \
		  --output text | awk '{ print $2, $4, $5 }')

		if [ -z "$AWS_ACCESS_KEY_ID" ]; then
			echo
			echo -e "${BIRed}Could not initialize the requested MFA session.${Color_Off}"
			echo
			exit 1
		else
			# this is used to determine whether to print MFA questions/details
			mfaprofile="true"
			echo -e "${Green}MFA session token acquired.${Color_Off}"
			echo

			# export the selection to the remaining subshell commands in this script
			export AWS_PROFILE=${AWS_2AUTH_PROFILE}
			# Make sure the final selection profile name has '-mfasession' suffix
			# (before this assignment it's not present when going from a base profile to an MFA profile)
			final_selection="$AWS_2AUTH_PROFILE"

			# optionally set the persistent (~/.aws/credentials or custom cred file entries):
			# aws_access_key_id, aws_secret_access_key, and aws_session_token 
			# for the MFA profile
			getPrintableTimeRemaining _ret "$AWS_SESSION_DURATION"
			validity_period=${_ret}
			echo -e "${BIWhite}Make this MFA session persistent?${Color_Off} (Saves the session in $CREDFILE\\nso that you can return to it during its validity period, ${validity_period}.)"
			read -s -p "$(echo -e "${BIWhite}Yes (default) - make peristent${Color_Off}; No - only the envvars will be used ${BIWhite}[Y]${Color_Off}/N ")" -n 1 -r
			echo		
			if [[ $REPLY =~ ^[Yy]$ ]] ||
				[[ $REPLY == "" ]]; then

				persistent_MFA="true"
				aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
				aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
				aws configure set aws_session_token "$AWS_SESSION_TOKEN"
				# set init time in the static MFA profile (a custom key in ~/.aws/credentials)
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
	AWS_DEFAULT_REGION=$(aws configure get region --profile "${final_selection}")
	AWS_DEFAULT_OUTPUT=$(aws configure get output --profile "${final_selection}")

	# If the region and output format have not been set for this profile, set them.
	# For the parent/base profiles, use defaults; for MFA profiles use first
	# the base/parent settings if present, then the defaults
	if [[ "${AWS_DEFAULT_REGION}" == "" ]]; then
		# retrieve parent profile region if an MFA profie
		if [[ "${profile_region[$actual_selprofile]}" != "" &&
			  "${mfaprofile}" == "true" ]]; then
			set_new_region=${profile_region[$actual_selprofile]}
			echo -e "\\nNOTE: Region had not been configured for the selected MFA profile;\\n      it has been set to same as the parent profile ('$set_new_region')."
		fi
		if [[ "${set_new_region}" == "" ]]; then
			set_new_region=${default_region}
			echo -e "\\nNOTE: Region had not been configured for the selected profile;\\n      it has been set to the default region ('${default_region}')."
		fi

		AWS_DEFAULT_REGION="${set_new_region}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			aws configure --profile "${final_selection}" set region "${set_new_region}"
		fi
	fi

	if [[ "${AWS_DEFAULT_OUTPUT}" == "" ]]; then
		# retrieve parent profile output format if an MFA profile
		if [[ "${profile_output[$actual_selprofile]}" != "" &&
			"${mfaprofile}" == "true" ]]; then
			set_new_output=${profile_output[$actual_selprofile]}
			echo -e "NOTE: Output format had not been configured for the selected MFA profile;\\n      it has been set to same as the parent profile ('$set_new_output')."
		fi
		if [[ "${set_new_output}" == "" ]]; then
			set_new_output=${default_output}
			echo -e "Output format had not been configured for the selected profile;\\n      it has been set to the default output format ('${default_output}')."
		fi

		AWS_DEFAULT_OUTPUT="${set_new_output}"
		if [[ "$mfacode" == "" ]] ||
			( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
			
			aws configure --profile "${final_selection}" set output "${set_new_output}"
		fi
	fi

	if [[ "$mfacode" == "" ]]; then  # this is _not_ a new MFA session, so read in selected persistent values;
									 # for new MFA sessions they are already present
		AWS_ACCESS_KEY_ID=$(aws configure --profile "${final_selection}" get aws_access_key_id)
		AWS_SECRET_ACCESS_KEY=$(aws configure --profile "${final_selection}" get aws_secret_access_key)
		
		if [[ "$mfaprofile" == "true" ]]; then  # this is a persistent MFA profile (a subset of [[ "$mfacode" == "" ]])
			AWS_SESSION_TOKEN=$(aws configure --profile "${final_selection}" get aws_session_token)
			getInitTime _ret "${final_selection}"
			AWS_SESSION_INIT_TIME=${_ret}
			getDuration _ret "${final_selection}"
			AWS_SESSION_DURATION=${_ret}
		fi
	fi

	echo
	echo
	echo -e "${BIWhite}${On_DGreen}                            * * * PROFILE DETAILS * * *                            ${Color_Off}"
	echo
	if [[ "$mfaprofile" == "true" ]]; then
		echo -e "${BIWhite}MFA profile name: '${final_selection}'${Color_Off}"
		echo
	else
		echo -e "${BIWhite}Profile name '${final_selection}'${Color_Off}"
		echo -e "\\n${BIWhite}NOTE: This is not an MFA session!${Color_Off}"
		echo 
	fi
	echo -e "Region is set to: ${BIWhite}${AWS_DEFAULT_REGION}${Color_Off}"
	echo -e "Output format is set to: ${BIWhite}${AWS_DEFAULT_OUTPUT}${Color_Off}"
	echo

	if [[ "$mfacode" == "" ]] || # re-entering a persistent profile, MFA or not
		( [[ "$mfacode" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then # a new persistent MFA session was initialized; 
		# Display the persistent profile's envvar details for export?
		read -s -p "$(echo -e "${BIWhite}Do you want to export the selected profile's secrets to the environment${Color_Off} (for s3cmd, etc)? - Y/${BIWhite}[N]${Color_Off} ")" -n 1 -r
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
		echo -e "${BIWhite}*** THIS IS A NON-PERSISTENT MFA SESSION${Color_Off}! THE MFA SESSION ACCESS KEY ID,\\n    SECRET ACCESS KEY, AND THE SESSION TOKEN ARE *ONLY* SHOWN BELOW!"
		echo
	fi

	if [[ "$OS" == "macOS" ]] ||
		[[ "$OS" == "Linux" ]] ; then

		echo -e "${BIGreen}*** It is imperative that the following environment variables are exported/unset\\n    as specified below in order to activate your selection! The required\\n    export/unset commands have already been copied on your clipboard!\\n${BIWhite}    Just paste on the command line with Command-v, then press [ENTER]\\n    to complete the process!${Color_Off}"
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
				fi
			fi
		fi
		echo
		if [[ "$OS" == "Linux" ]]; then
			if exists xclip; then
				echo "${BIGreen}*** NOTE: xclip found; the envvar configuration command is now on your X PRIMARY clipboard -- just paste on the command line, and press [ENTER])${Color_Off}"
			else
				echo
				echo "*** NOTE: If you're using an X GUI on Linux, install 'xclip' to have the activation command copied to the clipboard automatically!"
			fi
		fi
		echo
		echo -e "${Green}*** Make sure to export/unset all the new values as instructed above to\\n    make sure no conflicting profile/secrets remain in the envrionment!"
		echo
		echo -e "*** You can temporarily override the profile set/selected in the environment\\n    using the \"--profile AWS_PROFILE_NAME\" switch with awscli. For example:${Color_Off}\\n    ${BIGreen}aws sts get-caller-identity --profile default${Color_Off}"
		echo
		echo -e "${Green}*** To easily remove any all AWS profile settings and secrets information\\n    from the environment, simply source the included script, like so:${Color_Off}\\n    ${BIGreen}source ./source-to-clear-AWS-envvars.sh"
		echo
		echo -e "${BIWhite}PASTE THE PROFILE ACTIVATION COMMAND FROM THE CLIPBOARD\\nON THE COMMAND LINE NOW, AND PRESS ENTER! THEN YOU'RE DONE!${Color_Off}"
		echo

	else  # not macOS, not Linux, so some other weird OS like Windows..

		echo "It is imperative that the following environment variables are exported/unset to activate the selected profile!"
		echo 
 		echo "Execute the following on the command line to activate this profile for the 'aws', 's3cmd', etc. commands."
 		echo
		echo "NOTE: Even if you only use a named profile ('AWS_PROFILE'), it's important to execute all of the export/unset"
		echo "      commands to make sure previously set environment variables won't override the selected configuration."
		echo

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
		echo
		echo "*** Make sure to export/unset all the new values as instructed above to"
		echo "    make sure no conflicting profile/secrets remain in the envrionment!"
		echo
		echo "*** You can temporarily override the profile set/selected in the environment"
		echo "    using the \"--profile AWS_PROFILE_NAME\" switch with awscli. For example:"
		echo "    aws sts get-caller-identity --profile default"
		echo
		echo "*** To easily remove any all AWS profile settings and secrets information"
		echo "    from the environment, simply source the included script, like so:"
		echo "    source ./source-to-clear-AWS-envvars.sh"
		echo

	fi
	echo
fi
