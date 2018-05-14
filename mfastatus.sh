#!/usr/bin/env bash

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
# 
# **NOTE: THIS SHOULD MATCH THE SETTING IN THE 
#         awscli-mfa.sh SCRIPT!
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
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White


# FUNCTIONS ==================================================================

# workaround function for lack of 
# macOS bash's assoc arrays
idxLookup() {
	# $1 is _ret (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	declare -a arr=("${!2}")
	local key=$3
 	local result=""
 	local i
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

getDuration() {
	# $1 is _ret
	# $2 is the profile ident

	local this_profile_ident=$2
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
# (must be pre-incremented with duration,
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

sessionData() {
	idxLookup idx profiles_key_id[@] "$AWS_ACCESS_KEY_ID"
	in_env_only="false"
	if [[ "$idx" == "" ]]; then

		if [[ "${AWS_PROFILE}" != "" ]]; then
			idxLookup name_idx profiles_ident[@] "${AWS_PROFILE}"
			if [[ "$name_idx" != "" ]]; then
				matched="not same as the similarly named persistent session"
			else
				matched="an in-env session [only]"
				in_env_only="true"
			fi
		else
			matched="an in-env session [only]"
			in_env_only="true"
		fi
	else
		if [[ "${AWS_PROFILE}" != "" ]]; then
			matched="same as the similarly named persistent session below"
		else
			matched="same as the persistent session '${profiles_ident[$idx]}'"
		fi
	fi

	for_iam=""
	bad_profile="false"
	if [[ "$in_env_only" == "true" ]]; then
		env_iam_check="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"

		if [[ "$env_iam_check" =~ ^arn:aws:iam::([[:digit:]]+):user.*/([^/]+)$ ]]; then 
			aws_account_id="${BASH_REMATCH[1]}" # this AWS account
			aws_iam_user="${BASH_REMATCH[2]}" # IAM user of the (hopefully :-) active MFA session
			for_iam=" for IAM user '$aws_iam_user'"
		else
			bad_profile="true"
		fi
	fi

	[[ "${AWS_PROFILE}" == "" ]] && AWS_PROFILE="[unnamed]"

	if [[ "$bad_profile" == "false" ]]; then
		echo -e "${Green}AWS PROFILE IN THE ENVIRONMENT: ${BIGreen}${AWS_PROFILE} ${Green}\\n  (${matched}${for_iam})${Color_Off}"
	else
		echo -e "${Red}AWS PROFILE IN THE ENVIRONMENT: ${BIRed}${AWS_PROFILE} -- a bad profile?${Color_Off}"
	fi

	if [[ "$AWS_SESSION_INIT_TIME" != "" ]]; then
	
		# use the global default if the duration is not set for the env session
		[[ "${AWS_SESSION_DURATION}" == "" ]] &&
			AWS_SESSION_DURATION=$MFA_SESSION_LENGTH_IN_SECONDS

		getRemaining _ret_remaining "$AWS_SESSION_INIT_TIME" "$AWS_SESSION_DURATION"
		getPrintableTimeRemaining _ret ${_ret_remaining}
		if [ "${_ret}" = "EXPIRED" ]; then
			echo -e "  ${Red}THE MFA SESSION EXPIRED; ${BIRed}YOU SHOULD PURGE THE ENV BY EXECUTING 'source ./source-this-to-clear-AWS-envvars.sh'${Color_Off}"
		else
			echo -e "  ${Green}MFA SESSION REMAINING TO EXPIRATION: ${BIGreen}${_ret}${Color_Off}"
		fi
	fi
}

repeatr() { 
	# $1 is the repeat_char
	# $2 is the base_length
	# $3 is the variable_repeat_length
 
	local repeat_char=$1
	local base_length=$2
	local variable_repeat_length=$3

	((repeat_length=base_length+variable_repeat_length))

	printf "$repeat_char"'%.s' $(eval "echo {1.."$((repeat_length))"}");
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

# -- end functions --

## PREREQUISITES CHECK

filexit="false"
# check for ~/.aws directory, and ~/.aws/{config|credentials} files
# if the custom config defs aren't in effect
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
	echo -e "${BIRed}${On_Black}AWSCLI credentials file '${CREDFILE}' was not found.${Color_Off}\\nMake sure it and '${CONFFILE}' files exist.\\nSee http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	filexit="true"
fi

if [[ "$filexit" == "true" ]]; then 
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"


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

AWS_SESSION_DURATION=$(env | grep AWS_SESSION_DURATION)
[[ "$AWS_SESSION_DURATION" =~ ^AWS_SESSION_DURATION[[:space:]]*=[[:space:]]*(.*)$ ]] &&
	AWS_SESSION_DURATION="${BASH_REMATCH[1]}"

IN_ENV_SESSION_TIME=0
if [[ "$AWS_SESSION_INIT_TIME" != "" ]]; then

	[[ "${AWS_SESSION_DURATION}" == "" ]] &&
		AWS_SESSION_DURATION=$MFA_SESSION_LENGTH_IN_SECONDS

	((IN_ENV_SESSION_TIME=AWS_SESSION_INIT_TIME+AWS_SESSION_DURATION))
fi

# COLLECT AWS CONFIG DATA FROM $CONFFILE

# init arrays to hold ident<->mfasec detail
declare -a confs_ident
declare -a confs_mfasec
confs_iterator=0

# read the config file for the optional MFA length param (mfasec)
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

done < "$CONFFILE"


# COLLECT AWS_SESSION DATA FROM $CREDFILE

# define profiles arrays
declare -a profiles_ident
declare -a profiles_type
declare -a profiles_key_id
declare -a profiles_session_token
declare -a profiles_session_init_time
declare -a profiles_mfa_mfasec
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
			profiles_ident[$profiles_iterator]="$_ret"
		fi

		# transfer possible MFA mfasec from config array
		idxLookup idx confs_ident[@] "${_ret}"
		if [[ $idx != "" ]]; then
			profiles_mfa_mfasec[$profiles_iterator]=${confs_mfasec[$idx]}
		fi

		if [[ "$_ret" != "" ]] &&
			[[ ! "$_ret" =~ -mfasession$ ]]; then

			profiles_type[$profiles_iterator]="profile"
		else
			profiles_type[$profiles_iterator]="session"
		fi
	fi

	[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_key_id[$profiles_iterator]="${BASH_REMATCH[1]}"

	[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_session_token[$profiles_iterator]="${BASH_REMATCH[1]}"

	[[ "$line" =~ ^aws_session_init_time[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		profiles_session_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

done < "$CREDFILE"

## PRESENTATION

echo
echo -e "${BIWhite}${On_Black}ENVIRONMENT${Color_Off}"
echo -e "==========="
echo

if [[ "$AWS_PROFILE" != "" ]]; then
	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		sessionData
	else
		idxLookup name_idx profiles_ident[@] "${AWS_PROFILE}"
		if [[ "$name_idx" != "" ]]; then
			profile_type=${profiles_type[$name_idx]}
		else
			profile_type=""
		fi

		if [[ "${profile_type}" == "profile" ]]; then
			echo -e "${Green}${On_Black}ENVVAR 'AWS_PROFILE' SELECTING A BASE PROFILE (not an MFA session): ${BIGreen}${AWS_PROFILE}${Color_Off}"
		elif [[ "${profile_type}" == "session" ]]; then
			echo -e "${Green}${On_Black}ENVVAR 'AWS_PROFILE' SELECTING A PERSISTENT MFA SESSION (as below): ${BIGreen}${AWS_PROFILE}${Color_Off}"
		else
			echo -e "${BIRed}${On_Black}INVALID ENVIRONMENT CONFIGURATION!\\nExecute ${Red}source ./source-this-to-clear-AWS-envvars.sh${BIRed} to clear the environment.\\n${Color_Off}"
		fi
	fi
else
	if [[ "$AWS_ACCESS_KEY_ID" != "" ]]; then
		sessionData

	else
		echo -e "No AWS profile variables present in the environment;\\nusing the default base profile."
	fi
fi

echo
echo
echo -e "${BIWhite}${On_Black}PERSISTENT MFA SESSIONS (in $CREDFILE)${Color_Off}"
repeatr "=" 29 ${#CREDFILE}
echo -e "${Color_Off}"
echo

maxIndex=${#profiles_ident[@]}
((maxIndex--))

live_session_counter=0
bad_profile="false"
for_iam=""
for (( z=0; z<=maxIndex; z++ ))
do 
	if [[ "${profiles_type[$z]}" == "session" ]]; then

		profile_iam_check="$(aws --profile "${profiles_ident[$z]}" sts get-caller-identity --output text --query 'Arn' 2>&1)"

		if [[ "$profile_iam_check" =~ ^arn:aws:iam::([[:digit:]]+):user.*/([^/]+)$ ]]; then 
			aws_account_id="${BASH_REMATCH[1]}" # this AWS account
			aws_iam_user="${BASH_REMATCH[2]}" # IAM user of the (hopefully :-) active MFA session
			for_iam="$aws_iam_user"

			getAccountAlias _ret
			if [[ "${_ret}" != "" ]]; then
				account_alias_if_any=" @ ${_ret}"
			else 
				account_alias_if_any=" @ ${aws_acount_id}"
			fi

		else
			for_iam="unknown -- a bad profile?"
			bad_profile="true"
		fi

		if [[ "$bad_profile" == "false" ]]; then
			echo -e "${Green}MFA SESSION IDENT: ${BIGreen}${profiles_ident[$z]} ${Green}(IAM user: '${for_iam}${account_alias_if_any}')${Color_Off}"
		else
			echo -e "${Green}MFA SESSION IDENT: ${BIGreen}${profiles_ident[$z]} ${Red}(IAM user: '${for_iam}${account_alias_if_any}')${Color_Off}"
		fi

		if [[ "${profiles_session_init_time[$z]}" != "" ]]; then
			getDuration _ret_duration "${profiles_ident[$z]}"
			getRemaining _ret_remaining "${profiles_session_init_time[$z]}" "${_ret_duration}"
			getPrintableTimeRemaining _ret "${_ret_remaining}"
			if [ "${_ret}" = "EXPIRED" ]; then
				echo -e "  ${Red}**MFA SESSION EXPIRED**${Color_Off}"
			else
				((live_session_counter++))
				echo -e "  ${Green}MFA SESSION REMAINING TO EXPIRATION: ${BIGreen}${_ret}${Color_Off}"
			fi
		else
			echo -e "  ${Yellow}No recorded init time (legacy or external init?)${Color_Off}"
		fi
		echo
	fi

	bad_profile="false"
	_ret=""
	_ret_duration=""
	_ret_remaining=""
done

if [[ $live_session_counter -eq 0 ]]; then
	echo -e "No current active persistent MFA sessions.\\n\\n"
fi

echo -e "\\nNOTE: Execute 'awscli-mfa.sh' to renew/start a new MFA session,\\n      or to select (switch to) an existing active MFA session.\\n\\n"
