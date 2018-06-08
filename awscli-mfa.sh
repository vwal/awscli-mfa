#!/usr/bin/env bash

# todo: handle roles with MFA
# todo: handle root account max session time @3600 & warn if present
# todo: handle secondary role max session time @3600 & warn
# todo: arg parsing, help
# todo: "--quick" switch which forgoes the aws queries before
#       the presentation

# NOTE: Debugging mode prints the secrets on the screen!
DEBUG="false"

# enable debugging with '-d' or '--debug' command line argument..
[[ "$1" == "-d" || "$1" == "--debug" ]] && DEBUG="true"
# .. or by uncommenting the line below:
#DEBUG="true"

# Set the global MFA session length in seconds below; note that 
# this only sets the client-side duration for the MFA session 
# token! The maximum length of a valid session is enforced by 
# the IAM policy, and is unaffected by this value (if this
# duration is set to a longer value than the enforcing value
# in the IAM policy, the token will stop working before it 
# expires on the client side). Matching this value with the 
# enforcing IAM policy provides you with accurate detail 
# about how long a token will continue to be valid.
# 
# THIS VALUE CAN BE OPTIONALLY OVERRIDDEN PER EACH BASE PROFILE
# BY ADDING A "sessmax" ENTRY FOR A BASE PROFILE IN ~/.aws/config
#
# The AWS-side IAM policy may be set to session lengths 
# between 900 seconds (15 minutes) and 129600 seconds (36 hours);
# the example value below is set (below) to 32400 seconds, or 9 hours.
MFA_SESSION_LENGTH_IN_SECONDS=32400

# Set the global ROLE session length in seconds below; this value
# is used when the enforcing IAM policy disallows retrieval of 
# the maximum role session length. The attached example MFA 
# enforcement policy (example-MFA-enforcement-policy.txt) allows
# this, and in such cases this value should not need to be altered.
# Wit the correctly configured enforcement policy this value is
# dynamically overridden when specific session maxtime is defined
# for a particular role.
# 
# The default role session length set by AWS for CLI access is 
# 3600 seconds, or 1 hour. This length can be altered by an IAM
# policy to range from 900 seconds (15 minutes) to 129600 seconds
# (36 hours).
#  
# Note that just like the maximum session length for the MFA
# sessions set above, this value only sets the client-side
# maximum duration for the role session token! Changing this
# value does not affect the session length enforced by the
# policy, and in fact, if this duration is set to a longer
# value than the enforcing value in the IAM policy (or the
# default 3600 seconds if no maxtime has been explicitly set
# in the policy), the role session token request WILL FAIL.
# 
# Furthermore, this value can also be optionally overridden
# per each role profile by adding a "sessmax" entry for a role
# in ~/.aws/config (this can be useful in situations where
# session maximum isn't available from AWS, such as for
# accesing a third party AWS role).
ROLE_SESSION_LENGTH_IN_SECONDS=3600

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

# 'exists' for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

yesno() {
	# $1 is _ret

	old_stty_cfg=$(stty -g)
	stty raw -echo
	answer=$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )
	stty "$old_stty_cfg"

	if echo "$answer" | grep -iq "^n" ; then
		_ret="no"
	else
		_ret="yes"
	fi

	eval "$1=${_ret}"
}

# precheck envvars for existing/stale session definitions
checkEnvSession() {
	# $1 is the check type

	local this_time
	this_time=$(date "+%s")

#todo: make sure all role params are in env (if applicable), and that a in-env only MFA session is taken into account when assuming a role

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

	PRECHECK_AWS_MFASESSION_INIT_TIME=$(env | grep AWS_MFASESSION_INIT_TIME)
	[[ "$PRECHECK_AWS_MFASESSION_INIT_TIME" =~ ^AWS_MFASESSION_INIT_TIME[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_MFASESSION_INIT_TIME="${BASH_REMATCH[1]}"

	PRECHECK_AWS_SESSION_DURATION=$(env | grep AWS_SESSION_DURATION)
	[[ "$PRECHECK_AWS_SESSION_DURATION" =~ ^AWS_SESSION_DURATION[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_DURATION="${BASH_REMATCH[1]}"

#todo: this is not yet set anywhere
	PRECHECK_AWS_ROLESESSION_EXPIRY=$(env | grep AWS_ROLESESSION_EXPIRY)
	[[ "$PRECHECK_AWS_ROLESESSION_EXPIRY" =~ ^AWS_ROLESESSION_EXPIRY[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_ROLESESSION_EXPIRY="${BASH_REMATCH[1]}"

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
	# AWS_PROFILE is set to point to a non-existent persistent profile!)
	if [[ "$PRECHECK_AWS_PROFILE" != "" ]]; then

		idxLookup profiles_idx merged_ident[@] "$PRECHECK_AWS_PROFILE"

		if [[ "$profiles_idx" == "" ]]; then

			# AWS_PROFILE ident is not recognized;
			# awscli commands without specific profile
			# switch will fail
			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS PROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}\\n\
      Purge the invalid AWS envvars with:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      (or else you must include '--profile someprofilename' to every aws command)"
		fi			
	fi

	# makes sure that the MFA session has not expired (whether it's 
	# defined in the environment or in ~/.aws/credentials).
	# 
	# First checking the envvars
	if [[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
		[[ "$PRECHECK_AWS_MFASESSION_INIT_TIME" != "" ]] &&
		[[ "$PRECHECK_AWS_SESSION_DURATION" != "" ]]; then
		# this is an MFA session profile in the environment;
		# AWS_PROFILE is either empty or valid

		getRemaining _ret "mfasession" "$PRECHECK_AWS_MFASESSION_INIT_TIME" "$PRECHECK_AWS_SESSION_DURATION"
		if [[ "${_ret}" -eq 0 ]]; then 
			echo -e "\\n${BIRed}${On_Black}NOTE: THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
		fi

	elif [[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
		[[ "$PRECHECK_AWS_ROLESESSION_EXPIRY" != "" ]]; then
		# this is an role session profile in the environment;
		# AWS_PROFILE is either empty or valid

		getRemaining _ret "rolesession" "$PRECHECK_AWS_ROLESESSION_EXPIRY"
		if [[ "${_ret}" -eq 0 ]]; then 
			echo -e "\\n${BIRed}${On_Black}NOTE: THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
		fi

	elif [[ "$PRECHECK_AWS_PROFILE" =~ -mfasession$ ]] &&
			[[ "$profiles_idx" != "" ]]; then
		# AWS_PROFILE is set, is valid, and refers to a persistent mfasession,
		# but TOKEN, INIT_TIME, and/or DURATION are not set (known by exclusion),
		# so this is likely a select of a named profile

		# find the selected persistent MFA profile's init time if one exists
		session_time=${merged_aws_mfasession_init_time[$profiles_idx]}
		
		# if the duration for the current profile is not set
		# (as is usually the case with the mfaprofiles), use
		# the parent/base profile's duration
		if [[ "$session_time" != "" ]]; then
			getMaxSessionDuration parent_duration "$PRECHECK_AWS_PROFILE"
			getRemaining _ret "mfasession" "$session_time" "$parent_duration"
			if [[ "${_ret}" -eq 0 ]]; then 
				echo -e "\\n${BIRed}${On_Black}NOTE: THE MFA SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
			fi
		fi

	elif [[ "$PRECHECK_AWS_PROFILE" =~ -rolesession$ ]] &&
			[[ "$profiles_idx" != "" ]]; then
		# AWS_PROFILE is set (and valid, and refers to a persistent rolesession)
		# but TOKEN, and/or EXPIRY_TIME are not set (known by exclusion), so 
		# this is likely a select of a named profile

		# find the selected persistent role profile's expiry time if one exists
		session_expiry=${merged_aws_rolesession_expiry[$profiles_idx]}
		
		# if this is a role session and it has been configured
		# with this script, the expiration time is available;
		# if the expiry time has not been provided, this value
		# cannot be determined
		if [[ "$session_expiry" != "" ]]; then
			getRemaining _ret "rolesession" "$session_expiry"
			if [[ "${_ret}" -eq 0 ]]; then 
				echo -e "\\n${BIRed}${On_Black}NOTE: THE ROLE SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
			fi
		fi
	fi
	# empty AWS_PROFILE + no in-env MFA session should flow through

	# detect and print informative notice of 
	# effective AWS envvars
	if [[ "${AWS_PROFILE}" != "" ]] ||
		[[ "${AWS_ACCESS_KEY_ID}" != "" ]] ||
		[[ "${AWS_SECRET_ACCESS_KEY}" != "" ]] ||
		[[ "${AWS_SESSION_TOKEN}" != "" ]] ||
		[[ "${AWS_MFASESSION_INIT_TIME}" != "" ]] ||
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
			[[ "$PRECHECK_AWS_MFASESSION_INIT_TIME" != "" ]] && echo "   AWS_MFASESSION_INIT_TIME: $PRECHECK_AWS_MFASESSION_INIT_TIME"
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

# save the MFA/role session initialization/expiry
# timestamp in the MFA/role session profile in
# the credfile (usually ~/.aws/credentials)
writeSessionTime() {
	# $1 is the profile (ident)
	# $2 is time type ("mfa" or "role")
	# $3 is role session length (blank for mfa sessions)

	local this_ident="$1"
	local this_timetype="$2"

	# only available for rolesessions
	local role_session_length="$3"

	local this_time=$(date "+%s")
	local replace_me
	local DATA

	[[ "$this_timetype" == "role" ]] && (( this_time=this_time+role_session_length ))

	# find the selected profile's existing
	# init/expiry time entry if one exists
	getSessionTime _ret "$this_ident" "$this_timetype"
	local session_time="${_ret}"

	# update/add session init/expiry time
	if [[ "$session_time" != "" ]]; then
		# time entry exists for the profile, update
		
		if [[ "$OS" == "macOS" ]]; then 
			sed -i '' -e "s/${session_time}/${this_time}/g" "$CREDFILE"
		else 
			sed -i -e "s/${session_time}/${this_time}/g" "$CREDFILE"
		fi
	else
		# no time entry exists for the profile; 
		# add on a new line after the header "[${this_ident}]"
		replace_me="\\[${this_ident}\\]"

		if [[ "$this_timetype" == "mfa" ]]; then
			DATA="[${this_ident}]\\naws_mfasession_init_time = ${this_time}"
		else
			# this is a role session
			DATA="[${this_ident}]\\naws_rolesession_expiry = ${this_time}"
		fi
		echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${CREDFILE}")" > "${CREDFILE}"
	fi

	# update the selected profile's existing
	# init/expiry time entry in this script
	idxLookup idx merged_ident[@] "$this_ident"
	if [[ "$this_timetype" == "mfa" ]]; then
		merged_aws_mfasession_init_time[$idx]=$this_time
	else
		# this is a role session
		merged_aws_rolesession_expiry[$idx]=$this_time
	fi
}

#todo: write the 'sessmax' prop to role profile's config if it's not there;
#      this is used by the dynamic update when a custom maximum role session
#      lifetime is defined in the IAM role policy (and is different from the
#      default 3600)
writeSessmax() {

	echo
}

writeRoleSourceProfile() {

	# $1 is the target profile ident to add source_profile to
	# $2 is the source profile ident 

	local target_ident="$1"
	local source_profile_ident="$2"
	local replace_me
	local data
	local idx
	local existing_source_profile

	# confirm that the target profile indeed
	# doesn't have a source profile entry
	existing_source_profile="$(aws --profile "$target_ident" configure get source_profile)"

	# double-check that this is a role, and that this has no
	# source profile as of yet; then add on a new line after
	# the existing header "[${target_ident}]"
	idxLookup idx merged_ident[@] "$target_ident"
	if [[ "$existing_source_profile" == "" ]] &&
		[[ "${merged_role_source_profile[$idx]}" == "" ]] &&
		[[ "${merged_type[$idx]}" == "role" ]]; then

		replace_me="\\[${target_ident}\\]"

		DATA="[${target_ident}]\\nsource_profile = ${source_profile_ident}"

		echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${CONFFILE}")" > "${CONFFILE}"
	fi
}

writeRoleMFASerialNumber() {
#todo: add MFA serial numbe writing..
	echo
}

#todo: add region (for roles, baseprofiles, based on user input)
#      (if '--use-default' is present, look for region in the default profile first (does_valid_default_exist), but don't do it otherwise automatically)
addProfileRegion() {
	echo

	# for roles, lookup source_profile's [if exist] role first [if exist]
	# if no source profile, prompt; if no source profile region, prompt (and write to both!)

	# to write, simply use 
	# aws configure --profile $profile_name set region "${set_new_region}"
	# .. because it automagically uses the appropriate profile, even if custom
	# is set
}

# return the MFA session init/expiry time for the given profile
getSessionTime() {
	# $1 is _ret
	# $2 is the profile ident
	# $3 is the time type ("mfa" or "role")

	local this_ident=$2
	local this_timetype=$3

	local session_time

	# find the profile's init/expiry time entry if one exists
	idxLookup idx merged_ident[@] "$this_ident"
	if [[ "$this_timetype" == "mfa" ]]; then
		session_time=${merged_aws_mfasession_init_time[$idx]}
	else
		# this is a role session
		session_time=${merged_aws_rolesession_expiry[$idx]}
	fi

	eval "$1=${session_time}"
}

#todo: $3 must be added into calling locations
getMaxSessionDuration() {
	# $1 is _ret
	# $2 is the profile ident
	# $3 is "baseprofile", "role", "mfasession", or "rolesession";
	#    required for the baseprofiles and roles (but optional for
	#    the sessions since they can be derived from the profile_ident)

	local this_profile_ident="$2"
	local this_profiletype="$3"

	local this_duration

	# use parent profile ident if this is a role or MFA session
	if [[ "$this_profile_ident" =~ ^(.*)-mfasession$ ]]; then
		this_profile_ident="${BASH_REMATCH[1]}"
	elif [[ "$this_profile_ident" =~ ^(.*)-rolesession$ ]]; then
		this_profile_ident="${BASH_REMATCH[1]}"
#todo: add dynamic lookup for the role length here?
#      using, perhaps, the source_profile creds?
#      .. but what if the source profile requires
#      active MFA to do anything?
	fi

	# look up a possible custom duration for the parent profile/role
	idxLookup idx merged_ident[@] "$this_profile_ident"

	if [[ "$this_profiletype" == "baseprofile" ]]; then

		[[ $idx != "" && "${merged_sessmax[$idx]}" != "" ]] && 
			this_duration=${merged_sessmax[$idx]}  ||
			this_duration=$MFA_SESSION_LENGTH_IN_SECONDS

	elif [[ "$this_profiletype" == "role" ]]; then

		[[ $idx != "" && "${merged_aws_rolesession_expiry[$idx]}" != "" ]] && 
			this_duration=${merged_aws_rolesession_expiry[$idx]}  ||
			this_duration=$ROLE_SESSION_LENGTH_IN_SECONDS
	fi		

	eval "$1=${this_duration}"
}

# Returns remaining seconds for the given timestamp;
# if the custom duration is not provided, the global
# duration setting is used). In the result
# 0 indicates expired, -1 indicates NaN input
getRemaining() {
	# $1 is _ret
	# $2 is the session type, "mfasession" or "rolesession"
	# $3 is the timestamp
	# $4 is the duration (not needed for rolesessions)

#todo: has the API change been reflected everywhere?

	local sessiontype=$2
	local timestamp=$3
	local duration=$4

	local this_time
	this_time=$(date "+%s")
	local remaining=0
	local session_time_slack=300

	[[ "${sessiontype}" == "mfasession" && "${duration}" == "" ]] &&
		duration=$MFA_SESSION_LENGTH_IN_SECONDS

	if [[ "${sessiontype}" == "mfasession" ]]; then
		# this is an mfa session (timestamp = init time)

		if [ ! -z "${timestamp##*[!0-9]*}" ]; then
			((session_end=timestamp+duration))
			if [[ $session_end -gt $this_time ]]; then
				(( remaining=session_end-this_time ))
			else
				remaining=0
			fi
		else
			remaining=-1
		fi
	else
		# this is a role session (timestamp = expiry time)

		if [ ! -z "${timestamp##*[!0-9]*}" ]; then
			
			(( session_time_slack=this_time+session_time_slack ))
			if [[ $session_time_slack -lt $timestamp ]]; then
				((remaining=this_time-timestamp))
			else
				remaining=0
			fi
		else
			remaining=-1
		fi

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

does_valid_default_exist() {
	# $1 is _ret

	default_profile_arn="$(aws --profile default sts get-caller-identity \
		--query 'Arn' \
		--output text 2>&1)"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile default sts get-caller-identity  --query 'Arn' --output text':\\n${ICyan}${default_profile_arn}${Color_Off}"

	if [[ "$default_profile_arn" =~ ^arn:aws:iam:: ]] &&
		[[ ! "$default_profile_arn" =~ 'error occurred' ]]; then

		response="true"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The default profile exists and is valid.${Color_Off}"
	else
		response="false"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The default profile not present or invalid.${Color_Off}"
	fi

	eval "$1=${response}"
}

checkAWSErrors() {
	# $1 is exit_on_error (true/false)
	# $2 is the AWS return (may be good or bad)
	# $3 is the 'default' keyword (if present)
	# $4 is the custom message (if present);
	#    only used when $3 is positively present
	#    (such as at MFA token request)

	local exit_on_error="$1"
	local aws_raw_return="$2"
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

	# do not exit on the profile ingest loop
	[[ "$is_error" == "true" && "$exit_on_error" == "true" ]] && exit 1
}

declare -a account_alias_cache_table_ident
declare -a account_alias_cache_table_result
getAccountAlias() {
	# $1 is _ret (returns the account alias if found)
	# $2 is the profile_ident

	local local_profile_ident="$2"
	local account_alias_result
	local cache_hit="false"
	local cache_idx
	local itr

	if [[ "$local_profile_ident" == "" ]]; then
		# no input, return blank result
		result=""
	else

		for ((itr=0; itr<${#account_alias_cache_table_ident[@]}; ++itr))
		do
			if [[ "${account_alias_cache_table_ident[$itr]}" == "$local_profile_ident" ]]; then
				result="${account_alias_cache_table_result[$itr]}"
				cache_hit="true"
				[[ "$DEBUG" == "true" ]] && echo -e "\\n\
${Cyan}${On_Black}Account alias found from cache for profile ident: '$local_profile_ident'\\n\
${ICyan}${account_alias_result}${Color_Off}\\n\\n"
			fi
		done

		if  [[ "$cache_hit" == "false" ]]; then
			# get the account alias (if any) for the profile
			account_alias_result="$(aws --profile "$local_profile_ident" iam list-account-aliases \
				--output text \
				--query 'AccountAliases' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n\
${Cyan}${On_Black}result for: 'aws --profile \"$local_profile_ident\" iam list-account-aliases --query 'AccountAliases' --output text':\\n\
${ICyan}${account_alias_result}${Color_Off}\\n\\n"

			if [[ "$account_alias_result" =~ 'error occurred' ]]; then
				# no access to list account aliases
				# for this profile or other error
				result=""
			else
				result="$account_alias_result"
				cache_idx=${#account_alias_cache_table_ident[@]}
				account_alias_cache_table_ident[$cache_idx]="$local_profile_ident"
				account_alias_cache_table_result[$cache_idx]="$account_alias_result"
			fi
		fi
	fi

	eval "$1=$result"
}

dynamicAugment() {

	local profile_check
	local user_arn
	local mfa_arn
	local idx

	echo -ne "${BIWhite}${On_Black}Please wait"

	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then  # BASEPROFILE AUGMENT ---------------------------------

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws --profile "$profile_ident" sts get-caller-identity \
				--output text \
				--query 'Arn' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${user_arn}${Color_Off}\\n\\n"

			if [[ "$user_arn" =~ ^arn:aws ]]; then
				merged_baseprofile_arn[$idx]="$user_arn"

				# get the actual username (may be different
				# from the arbitrary profile ident)
				if [[ "$user_arn" =~ ([[:digit:]]+):user.*/([^/]+)$ ]]; then
					merged_account_id[$idx]="${BASH_REMATCH[1]}"
					merged_username[$idx]="${BASH_REMATCH[2]}"
				fi

				# check to see if this profile has access currently (this is 
				# not 100% accurate as it depends on the effective IAM policy;
				# however if the MFA enforcement is set following the example
				# policy, this should produce a reasonably reliable result);
				# since sts get-caller-identity above verified that the creds
				# are valid, this checks for possible requirement for a valid
				# MFA session
				profile_check="$(aws --profile "$profile_ident" iam get-user \
					--query 'User.Arn' \
					--output text 2>&1)"
					
				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" iam get-user --query 'User.Arn' --output text':\\n${ICyan}${profile_check}${Color_Off}\\n\\n"

				if [[ "$profile_check" =~ ^arn:aws ]]; then
					merged_profile_status[$idx]="OK"
				elif [[ "$profile_check" =~ 'AccessDenied' ]]; then  # may require an MFA session
					merged_profile_status[$idx]="LIMITED"
				elif [[ "$profile_check" =~ 'could not be found' ]]; then
					merged_profile_status[$idx]="NONE"  
				else
					merged_profile_status[$idx]="UNKNOWN"
				fi

				# get the account alias (if any)
				# for the user/profile
				getAccountAlias _ret "$profile_ident"
				merged_account_alias[$idx]="${_ret}"

				# get MFA ARN if available (obviously
				# not available if a vMFA device hasn't
				# been configured for the profile)
				mfa_arn="$(aws --profile "$profile_ident" iam list-mfa-devices \
					--user-name "${merged_username[$idx]}" \
					--output text \
					--query 'MFADevices[].SerialNumber' 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" iam list-mfa-devices --user-name \"${merged_username[$idx]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${mfa_arn}${Color_Off}\\n\\n"

				if [[ "$mfa_arn" =~ ^arn:aws ]]; then
					merged_mfa_arn[$idx]="$mfa_arn"
				else
					merged_mfa_arn[$idx]=""
				fi

			else
				# must be a bad profile (or the unlikely case where 
				# 'sts get-caller-identity' has been blocked)
				merged_baseprofile_arn[$idx]=""
			fi

		elif [[ "${merged_type[$idx]}" == "role" ]]; then  # ROLE AUGMENT ---------------------------------------------

			if [[ "${merged_role_source_profile[$idx]}" == "" ]] &&
				[[ "${merged_role_mfa_serial[$idx]}" == "" ]]; then

				echo -e "\\n${BIRed}${On_Black}\
The role profile '${merged_type[$idx]}' has neither a source profile nor an vMFA device serial defined.${Color_Off}\\n\
A role must have the means to authenticate, so select below the associated source profile,\\n\
or enter the serial number ('Arn', of the format 'arn:aws:iam::AWSaccountNumber:mfa/AWSIAMUserName')\\n\
for the vMFA device that is allowed to authenticate for this role.\\n"

				# acquire source_profile or MFA arn for the role
				while :
				do
					echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS BASE PROFILES: ${Color_Off}\\n"

					for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
					do

						if [[ "${merged_type[$int_idx]}" == "baseprofile" ]]; then

							# create a more-human-friendly selector 
							# digit (starts from 1 rather than 0)
							(( selval=$int_idx+1 ))
							echo -e "${BIWhite}${On_Black}${selval}: ${merged_ident[$int_idx]}${Color_Off}\\n"
						fi
					done

					# prompt for a base profile selection
					echo -e "\\n\
Select a source profile for the above role by entering a profile ID, or enter\\n\
the Arn (serial) for an authorized vMFA device. If you enter an Arn, it must be of the format:\\n\
arn:aws:iam::AwsAccountNumber:mfa/AwsIAMUserName, e.g. arn:aws:iam::123456789123:mfa/bbaggins\\n"
					echo -en  "\\n${BIWhite}${On_Black}ENTER A PROFILE ID OR A vMFAd ARN, AND PRESS ENTER:${Color_Off}\\n"
					read -r role_auth
					echo -en  "\\n"

					(( max_sel_val=selval+1 ))
					if [[ "$role_auth" =~ ^[[:space:]]*arn:aws:iam::[[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]]:mfa/.+ ]]; then
						# this is an authorized MFA Arn
						
						merged_role_mfa_serial[$idx]="$role_auth"
						writeRoleMFASerialNumber "$idx" "$role_auth"
						break

					elif [ "$role_auth" -gt 0 -a "$role_auth" -lt $max_sel_val ]; then
						# this is a base profile selector for
						# a valid role source_profile

						(( actual_index=role_auth-1 ))
						get_this_role="$(aws --profile "${merged_ident[$actual_index]}" iam get-role \
							--role-name "${merged_ident[$idx]}" \
							--query 'Role.Arn' \
							--output text 2>&1)"

						if [[ "$get_this_role" =~ ^[[:space:]]*arn:aws:iam::[[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]]:role/.+ ]]; then
							merged_role_source_profile[$idx]="${merged_ident[$actual_index]}"
							writeRoleSourceProfile "$idx" "${merged_ident[$actual_index]}"
							break
						elif [[ "$get_this_role" =~ NoSuchEntity ]]; then
							echo -e "\\n${BIRed}${On_Black}\
The selected source profile '${merged_ident[$actual_index]}' is not associated with\\n\
with the role '${merged_ident[$idx]}'. Select another profile.${Color_Off}\\n"
						else
							echo -e "\\n${BIWhite}${On_Black}\
The selected profile '${merged_ident[$actual_index]}' could not be verified as\\n\
the source profile for the role '${merged_ident[$idx]}'. However, this could be\\n\
because of the selected profile's permissions.${Color_Off}\\n\\n
Do you want to keep the selection? ${BIWhite}${On_Black}Y/N${Color_Off}"

							yesno _ret
							if [[ "${_ret}" == "yes" ]]; then
								echo -e "\\n${BIWhite}${On_Black}\
Using the profile '${merged_ident[$actual_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n"
								merged_role_source_profile[$idx]="${merged_ident[$actual_index]}"
								writeRoleSourceProfile "$idx" "${merged_ident[$actual_index]}"
								break
							fi

					elif [[ "$role_auth" =~ ^[[:digit:]]*$ ]]; then
						# skip setting source_profile/mfa arn
						break

					else
						# an invalid entry

						echo -e "\\n${BIRed}${On_Black}\
Invalid selection.${Color_Off}\\n\
Try again, or just press Enter to skip setting source_profile\\n\
or vMFAd serial number for this role profile at this time.\\n"
					fi
					
				done

			fi

			# a role must have either a source_profile or
			# mfa_serial defined to be functional
			merged_role_source_username[$idx]=""
			if [[ "${merged_role_source_profile[$idx]}" != "" ]] &&
				[[ "${merged_role_mfa_serial[$idx]}" == "" ]]; then

				# the "username" for this role is that of the source_profile
				# if it's defined; the 'source_profile' is not available if
				# vMFA serial is used for role authentication
				if [[ "${merged_username[${merged_role_source_profile[$idx]}]}" != "" ]]; then
					merged_role_source_username[$idx]="${merged_username[${merged_role_source_profile[$idx]}]}"
				fi

			fi

# then do: 
#  aws --profile [profile from source_profile] iam get-role --role-name ville-assumable --output text --query 'Role.MaxSessionDuration'
#  .. to get the MaxSessionDuration (if present), set to merged_sessmax[@] if different from the existing setting, then save it into the profile config 'sessmax' w/writeSessmax
#  if different from the default 3600.
#  
#  might get:
#  Partial credentials found in assume-role, missing: source_profile or credential_source
#  if no profile, source_profile, or credential_source is set
#  or this:
#  aws iam get-role --role-name ville-assumable --output text --query 'Role.MaxSessionDuration' --profile ville-assumable
#
# Enter MFA code for arn:aws:iam::248783370565:mfa/ville:
#
# An error occurred (AccessDenied) when calling the GetRole operation: User: arn:aws:sts::248783370565:assumed-role/ville-assumable/botocore-session-1528064916 is not authorized to perform: iam:GetRole on resource: role ville-assumable

# pattern match for digits only, if not available, assume default 1h (and do not write anything)

		elif [[ "${merged_type[$idx]}" == "mfasession" ]] ||
			[[ "${merged_type[$idx]}" == "rolesession" ]]; then  # MFA OR ROLE SESSION AUGMENT ------------------------

# should first rely on the recorded time, because there's no point to augment further if the
# timestamps say the session has expired

# 'sts get-caller-identity' to see if the session is still valid (beyond the remaining time)

# how is this related to the time-based earlier check? different array variable?

## old isSessionValid() "requires work" :-]

			getSessionTime _ret_timestamp "$mfa_profile_ident"
			getMaxSessionDuration _ret_duration "$mfa_profile_ident"
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

		echo -n "."

	done

	echo
}

acquireSession() {
	# $1 is "mfa" or "role"

	# the session request stuff will be here
	echo

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

		# aws_mfasession_init_time
		[[ "$line" =~ ^[[:space:]]*aws_mfasession_init_time[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_mfasession_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

		# aws_rolesession_expiry
		[[ "$line" =~ ^[[:space:]]*aws_rolesession_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			creds_aws_rolesession_expiry[$profiles_iterator]=${BASH_REMATCH[1]}

		# role_arn (not stored; only for warning)
		if [[ "$line" =~ ^[[:space:]]*role_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			this_role="${BASH_REMATCH[1]}"

			echo -e "\\n${BIRed}${On_Black}\
NOTE: The role '${this_role}' is defined in the credentials\\n\
      file ($CREDFILE) and will be ignored.${Color_Off}\\n\\n\
      The credentials file may only contain profile/session credentials;\\n\
      you should define roles in the config file ($CONFFILE).\\n"

		fi

	done < "$CREDFILE"

	# init arrays to hold profile configuration detail
	# (may also include credentials)
	declare -a confs_ident
	declare -a confs_aws_access_key_id
	declare -a confs_aws_secret_access_key
	declare -a confs_aws_mfasession_init_time
	declare -a confs_aws_rolesession_expiry
	declare -a confs_aws_session_token
	declare -a confs_ca_bundle
	declare -a confs_cli_timestamp_format
	declare -a confs_sessmax
	declare -a confs_output
	declare -a confs_parameter_validation
	declare -a confs_region
	declare -a confs_role_arn
	declare -a confs_role_credential_source
	declare -a confs_role_external_id
	declare -a confs_role_mfa_serial
	declare -a confs_role_session_name
	declare -a confs_role_source_profile
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

		# aws_mfasession_init_time (should always be blank in the config, but just in case)
		[[ "$line" =~ ^[[:space:]]*aws_mfasession_init_time[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_mfasession_init_time[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_rolesession_expiry (should always be blank in the config, but just in case)
		[[ "$line" =~ ^[[:space:]]*aws_rolesession_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_expiry[$confs_iterator]=${BASH_REMATCH[1]}

		# aws_session_token
		[[ "$line" =~ ^[[:space:]]*aws_session_token[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_session_token[$confs_iterator]="${BASH_REMATCH[1]}"

		# ca_bundle
		[[ "$line" =~ ^[[:space:]]*ca_bundle[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_ca_bundle[$confs_iterator]=${BASH_REMATCH[1]}

		# cli_timestamp_format
		[[ "$line" =~ ^[[:space:]]*cli_timestamp_format[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_cli_timestamp_format[$confs_iterator]=${BASH_REMATCH[1]}

		# sessmax
		[[ "$line" =~ ^[[:space:]]*sessmax[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_sessmax[$confs_iterator]=${BASH_REMATCH[1]}

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

		# (role) credential_source
		[[ "$line" =~ ^[[:space:]]*credential_source[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_credential_source[$confs_iterator]=${BASH_REMATCH[1]}

		# (role) source_profile
		[[ "$line" =~ ^[[:space:]]*source_profile[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_source_profile[$confs_iterator]=${BASH_REMATCH[1]}

		# (role) external_id
		[[ "$line" =~ ^[[:space:]]*external_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_external_id[$confs_iterator]=${BASH_REMATCH[1]}

		# (role) mfa_serial
		[[ "$line" =~ ^[[:space:]]*mfa_serial[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_mfa_serial[$confs_iterator]=${BASH_REMATCH[1]}

		# role_session_name 
		[[ "$line" =~ ^[[:space:]]*role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_name[$confs_iterator]=${BASH_REMATCH[1]}

		# aws_rolesession_expiry (should always be blank in the config, but just in case)
		[[ "$line" =~ ^[[:space:]]*aws_rolesession_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_expiry[$confs_iterator]=${BASH_REMATCH[1]}

	done < "$CONFFILE"

	# UNIFIED (config+credentials) ARRAYS
	declare -a merged_ident # baseprofile name, *-mfasession, or *-rolesession
	declare -a merged_type # baseprofile, role, mfasession, rolesession
	declare -a merged_has_session # true/false (baseprofiles and roles only; not session profiles)
	declare -a merged_session_idx # reference to the related session profile index in this array (added after the fact)
	declare -a merged_session_status # current/expired (session profiles only; based on time as this is offline augmentation)
	declare -a merged_aws_access_key_id
	declare -a merged_aws_secret_access_key
	declare -a merged_aws_mfasession_init_time
	declare -a merged_aws_rolesession_expiry
	declare -a merged_aws_session_token
	declare -a merged_ca_bundle
	declare -a merged_cli_timestamp_format
	declare -a merged_mfa_serial # same as merged_mfa_arn, but based on the config
	declare -a merged_sessmax
	declare -a merged_output
	declare -a merged_parameter_validation
#todo: should use source_profile's region for the roles that don't have it defined, then *write it to the config for the role*
	declare -a merged_region # precedence: environment, baseprofile (for mfasessions, roles [via source_profile])

	# ROLE ARRAYS
	declare -a merged_role_arn
	declare -a merged_role_credential_source
	declare -a merged_role_external_id
	declare -a merged_role_mfa_serial
	declare -a merged_role_session_name
	declare -a merged_role_source_profile
	declare -a merged_role_source_profile_idx

	# DYNAMIC AUGMENT ARRAYS
	declare -a merged_baseprofile_arn
	declare -a merged_account_id
	declare -a merged_account_alias
	declare -a merged_user_arn
	declare -a merged_username
	declare -a merged_mfa_arn # same as merged_mfa_serial, but acquired dynamically
	declare -a merged_valid # true/false based on 'sts get-caller-identity' work for the profile?
	declare -a merged_profile_status # OK/LIMITED/NONE/UNKNOWN based on 'iam get-user'

	for ((itr=0; itr<${#confs_ident[@]}; ++itr))
	do
		# import content from confs_ arrays
		merged_ident[$itr]="${confs_ident[$itr]}"
		merged_ca_bundle[$itr]="${confs_ca_bundle[$itr]}"
		merged_cli_timestamp_format[$itr]="${confs_cli_timestamp_format[$itr]}"
		merged_has_session[$itr]="false" # the default value; may be overridden below
		merged_sessmax[$itr]="${confs_sessmax[$itr]}"
		merged_output[$itr]="${confs_output[$itr]}"
		merged_parameter_validation[$itr]="${confs_parameter_validation[$itr]}"
		merged_region[$itr]="${confs_region[$itr]}"
		merged_role_arn[$itr]="${confs_role_arn[$itr]}"
		merged_role_credential_source[$itr]="${confs_role_credential_source[$itr]}"
		merged_role_external_id[$itr]="${confs_role_external_id[$itr]}"
		merged_role_mfa_serial[$itr]="${confs_role_mfa_serial[$itr]}"
		merged_role_session_name[$itr]="${confs_role_session_name[$itr]}"
		merged_role_source_profile[$itr]="${confs_role_source_profile[$itr]}"

		# find possible matching (and thus, overriding) profile
		# index in the credentials file (creds_ident)
		idxLookup creds_idx creds_ident[@] "${confs_ident[$itr]}"

		# use the data from credentials (creds_ arrays) if available,
		# otherwise from config (confs_ arrays)
		[[ "${creds_aws_access_key_id[$creds_idx]}" != "" ]] &&
			merged_aws_access_key_id[$itr]="${creds_aws_access_key_id[$creds_idx]}" ||
			merged_aws_access_key_id[$itr]="${confs_aws_access_key_id[$itr]}"

		[[ "${creds_aws_secret_access_key[$creds_idx]}" != "" ]] &&
			merged_aws_secret_access_key[$itr]="${creds_aws_secret_access_key[$creds_idx]}" ||
			merged_aws_secret_access_key[$itr]="${confs_aws_secret_access_key[$itr]}"

		[[ "${creds_aws_session_token[$creds_idx]}" != "" ]] &&
			merged_aws_session_token[$itr]="${creds_aws_session_token[$creds_idx]}" ||
			merged_aws_session_token[$itr]="${confs_aws_session_token[$itr]}"

		[[ "${creds_aws_mfasession_init_time[$creds_idx]}" != "" ]] &&
			merged_aws_mfasession_init_time[$itr]="${creds_aws_mfasession_init_time[$creds_idx]}" ||
			merged_aws_mfasession_init_time[$itr]="${confs_aws_mfasession_init_time[$itr]}"

		[[ "${creds_aws_rolesession_expiry[$creds_idx]}" != "" ]] &&
			merged_aws_rolesession_expiry[$itr]="${creds_aws_rolesession_expiry[$creds_idx]}" ||
			merged_aws_rolesession_expiry[$itr]="${confs_aws_rolesession_expiry[$itr]}"

		[[ "${creds_type[$itr]}" != "" ]] &&
			merged_type[$itr]="${creds_type[$creds_idx]}" ||
			merged_type[$itr]="${confs_type[$itr]}"

		# set merged_session_status ("expired/valid") based on the 
		# remaining time for mfa & role sessions:
		if [[ "${merged_type[$itr]}" == "mfasession" ]]; then
			
			getMaxSessionDuration this_session_duration "${merged_ident[$itr]}" "mfasession"
			getRemaining _ret "mfasession" "${merged_aws_mfasession_init_time[$itr]}" "$this_session_duration"

			[[ ${_ret} -gt 0 ]] &&
				merged_session_status[$itr]="valid" ||
				merged_session_status[$itr]="expired"

		elif [[ "${merged_type[$itr]}" == "rolesession" ]]; then

			getRemaining _ret "rolesession" "${merged_aws_rolesession_expiry[$itr]}"

			[[ ${_ret} -gt 0 ]] &&
				merged_session_status[$itr]="valid" ||
				merged_session_status[$itr]="expired"
		else
			merged_session_status[$itr]=""
		fi

		# since this index in creds_ident has now been merged, remove it from
		# the array so that it won't be duplicated in the leftover merge pass below
		[[ "$creds_idx" != "" ]] && creds_ident[$creds_idx]=""

	done

	# merge in possible credentials-only profiles as they
	# would not have been merged by the above process
	for ((itr=0; itr<${#creds_ident[@]}; ++itr))
	do
		if [[ "${creds_ident[$itr]}" != "" ]]; then
			# get the next available index to store the data in 
			merge_idx=${#merged_ident[@]}

			merged_ident[$merge_idx]="${creds_ident[$itr]}"
			merged_type[$merge_idx]="${creds_type[$itr]}"
			merged_aws_access_key_id[$merge_idx]="${creds_aws_access_key_id[$itr]}"
			merged_aws_secret_access_key[$merge_idx]="${creds_aws_secret_access_key[$itr]}"
			merged_aws_session_token[$merge_idx]="${creds_aws_session_token[$itr]}"
			merged_aws_mfasession_init_time[$merge_idx]="${creds_aws_mfasession_init_time[$itr]}"
			merged_aws_rolesession_expiry[$merge_idx]="${creds_aws_rolesession_expiry[$itr]}"
		fi			
	done

	# add merged_has_session and merged_session_idx properties
	# to make it easier to generate the selection arrays
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
		do

			if [[ "${merged_ident[$int_idx]}" =~ "${merged_ident[$idx]}-mfasession" ]] ||
				[[ "${merged_ident[$int_idx]}" =~ "${merged_ident[$idx]}-rolesession" ]]; then

				merged_has_session[$idx]="true"
				merged_session_idx[$idx]="$int_idx"
				break
			fi

		done
	done

	# add merged_role_source_profile_idx property
	# to easily access a role's source_profile data
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
		do
			if [[ "${merged_role_source_profile[$int_idx]}" == "${merged_ident[$idx]}" ]]; then
				merged_role_source_profile_idx[$idx]="$int_idx"
				break
			fi
		done
	done

#todo: remove the variable def here; must be an arg
quick_mode="false"

	if [[ "$quick_mode" == "false" ]]; then
		dynamicAugment
	else
#todo: add color
#todo: set session status for sessions w/o timestamps to "UNKNOWN"
		echo "Quick mode selected; skipping dynamic status checks."
	fi

	# make sure environment has either no config
	# or a functional config before we proceed
	checkEnvSession

	# get default region and output format
	# (in case default has been defined;
	# otherwise warn)
	default_region=$(aws --profile default configure get region)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get region':\\n${ICyan}'${default_region}'${Color_Off}\\n\\n"

	if [[ "$default_region" == "" ]]; then
		echo -e "${BIWhite}${On_Black}\
NOTE: The default region has not been configured.${Color_Off}\\n\
      Some operations may fail if each parent profile doesn't\\n\
      have the region set. You can set the default region in\\n\
      '$CONFFILE', for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set region \"us-east-1\"${Color_Off}\\n
      (do not use '--profile default' switch when configuring the defaults!)"
	fi

	default_output=$(aws --profile default configure get output)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get output':\\n${ICyan}'${default_output}'${Color_Off}\\n\\n"

	if [[ "$default_output" == "" ]]; then
		# default output is not set in the config;
		# set the default to the AWS default internally 
		# (so that it's available for the MFA sessions)
		default_output="json"

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}default output for this script was set to: ${ICyan}json${Color_Off}\\n\\n"
		echo -e "\\n${BIWhite}${On_Black}\
The default output format has not been configured; 'json' format is used.\\n\
You can modify it, for example, like so:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
aws configure set output \"table\"${Color_Off}\\n"
	fi

	echo

#todo: Switch 'm' ("mfa") -> 's' ("session"), so that it's generic for
#      both the role sessions and mfa session
#
#todo: warn when a role doesn't have role_source_profile set (bail when it's 
#      not set, there's no default, and the role is requested) .. or present a list of which one to use?
#      
#todo: bail if the only configured profile is a role AND the role doesn't have mfa_serial set

	declare -a select_ident
	declare -a select_type  # baseprofile, role, mfasession, rolesession
	declare -a select_merged_idx  # idx in the merged array (key to other info)
	declare -a select_has_session
	declare -a select_merged_session_idx

# loop through the merged array twice:
#  first iteration: mfa baseprofiles
#  second iteration: role profiles
#  .. this is because the items in the select array must be
#     in the presentation order
#  
#  On each iteration the merge arrays are looped through for
#  an associated session; sessions are related even when they're
#  expired (but session's status indicates whether it's active or not)

	# create the select arrays; first add the baseprofiles, then the roles

	select_idx=0
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then

			select_ident[$select_idx]=${merged_ident[$idx]}
			select_type[$select_idx]="baseprofile"
			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"

			(( select_idx++ ))
		fi
	done

	# NOTE: select_idx is intentionally not reset
	#       before continuing below
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "role" ]]; then

			select_ident[$select_idx]=${merged_ident[$idx]}
			select_type[$select_idx]="role"
			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"

			(( select_idx++ ))
		fi
	done

	# PROFILE SELECT MENU
	# displays single profile + a possible associated persistent MFA session
	mfa_req="false"
	if [[ ${#baseprofile_ident[@]} == 1 ]]; then
		echo
		[[ "${merged_username[0]}" != "" ]] && pr_user="${merged_username[0]}" || pr_user="unknown — a bad profile?"

		if [[ "${merged_account_alias[0]}" != "" ]]; then
			pr_accn=" @${merged_account_alias[0]}"
		elif [[ "${merged_account_id[0]}" != "" ]]; then
			# use the AWS account number if no alias has been defined
			pr_accn=" @${merged_account_id[0]}"
		else
			# or nothing for a bad profile
			pr_accn=""
		fi

		echo -e "${Green}${On_Black}You have one configured profile: ${BIGreen}${baseprofile_ident[0]} ${Green}(IAM: ${pr_user}${pr_accn})${Color_Off}"

		mfa_session_status="false"	
		if [[ "${merged_mfa_arn[0]}" != "" ]]; then
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
#todo: add role-only.. it is possible if the vMFAd has been defined externally or the profile
#      that created it has been since dropped, and it is named in the role config with mfa_serial
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
						selprofile="1s"
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

		# create the base profile selections
		echo
		echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS PROFILES: ${Color_Off}"
		echo

		for ((idx=0; idx<${#select_ident[@]}; ++idx))
		do

			if [[ "${select_type[$idx]}" == "baseprofile" ]]; then

				if [[ "${merged_username[$idx]}" != "" ]]; then 
					pr_user="${merged_username[$idx]}"
				else
					pr_user="unknown — a bad profile?"
				fi

				if [[ "${merged_account_alias[$idx]}" != "" ]]; then
					pr_accn=" @${merged_account_alias[$idx]}"
				elif [[ "${merged_account_id[$idx]}" != "" ]]; then
					# use the AWS account number if no alias has been defined
					pr_accn=" @${merged_account_id[$idx]}"
				else
					# or nothing for a bad profile
					pr_accn=""
				fi

				if [[ "${merged_mfa_arn[$idx]}" != "" ]]; then
					mfa_notify="; ${Green}${On_Black}vMFAd enabled${Color_Off}"
				else
					mfa_notify="; vMFAd not configured" 
				fi

				# make a more-human-friendly selector digit (starts from 1)
				(( selval=$idx+1 ))
				echo -en "${BIWhite}${On_Black}${selval}: ${merged_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify})\\n"

				if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" == "valid" ]]; then
#todo: add remaining time
					echo -e "${BIWhite}${On_Black}${selval}s: ${merged_ident[$idx]} MFA profile${Color_Off} (REMAINING TIME SHOULD GO HERE)"
				fi

				echo
			fi
		done

#todo: add "no base profiles" (unlikely as it is)

		# create the role profile selections
		echo
		echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS ROLES: ${Color_Off}"
		echo

		for ((idx=0; idx<${#select_ident[@]}; ++idx))
		do

			if [[ "${select_type[$idx]}" == "role" ]]; then

				if [[ "${merged_username[$idx]}" != "" ]]; then 
					pr_user="${merged_username[$idx]}"
				else
					pr_user="unknown — a bad role?"
				fi

				if [[ "${merged_account_alias[$idx]}" != "" ]]; then
					pr_accn=" @${merged_account_alias[$idx]}"
				elif [[ "${merged_account_id[$idx]}" != "" ]]; then
					# use the AWS account number if no alias has been defined
					pr_accn=" @${merged_account_id[$idx]}"
				else
					# or nothing for a bad profile
					pr_accn=""
				fi

				if [[ "${merged_mfa_arn[$idx]}" != "" ]]; then
					mfa_notify="; ${Green}${On_Black}vMFAd enabled${Color_Off}"
				else
					mfa_notify="; vMFAd not configured" 
				fi

				# make a more-human-friendly selector digit (starts from 1)
				(( selval=$idx+1 ))
				echo -en "${BIWhite}${On_Black}${selval}: ${merged_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify})\\n"

				if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" == "valid" ]]; then
#todo: add remaining time
					echo -e "${BIWhite}${On_Black}${selval}s: ${merged_ident[$idx]} MFA profile${Color_Off} (REMAINING TIME SHOULD GO HERE)"
				fi

				echo
			fi
		done
#todo: add "no roles"

# select_ident[$select_idx]=${merged_ident[$idx]}
# select_type[$select_idx]="role"
# select_merged_idx[$select_idx]="$idx"
# select_has_session[$select_idx]="${merged_has_session[$idx]}"
# select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"

		# this is used to determine whether to trigger a MFA request for a MFA profile
		active_mfa="false"

		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		# prompt for profile selection
		echo -e "\
You can switch to a base profile to use it as-is, start an MFA session\\n\
for a profile if it is marked as \"vMFAd enabled\", or switch to an existing\\n\
active MFA or role session if any are available (indicated by the letter 's'\\n\
after the profile ID, e.g. '1s'; NOTE: the expired MFA or role sessions are not shown).\\n"
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE ID:${Color_Off} "
		read -r selprofile
		echo -en  "\\n"

	fi  # end multi-profile selection

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
	if ( [[ "${merged_mfa_arn[$actual_selprofile]}" != "" &&
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
		ARN_OF_MFA=${merged_mfa_arn[$actual_selprofile]}

		# make sure an entry exists for the MFA profile in ~/.aws/config
		profile_lookup="$(grep "$CONFFILE" -e '^[[:space:]]*\[[[:space:]]*profile '"${AWS_2AUTH_PROFILE}"'[[:space:]]*\][[:space:]]*$')"
		if [[ "$profile_lookup" == "" ]]; then
			echo -en "\\n\\n">> "$CONFFILE"
			echo "[profile ${AWS_2AUTH_PROFILE}]" >> "$CONFFILE"
		fi

		echo -e "\\nAcquiring MFA session token for the profile: ${BIWhite}${On_Black}${AWS_USER_PROFILE}${Color_Off}..."

		getMaxSessionDuration AWS_SESSION_DURATION "$AWS_USER_PROFILE"

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

#todo: this is mfa only at this point.. must add role support

				writeSessionTime "${AWS_2AUTH_PROFILE}" "mfa"
			fi
			# init time for envvar exports (if selected)
			AWS_MFASESSION_INIT_TIME=$(date +%s)

			## DEBUG
			if [[ "$DEBUG" == "true" ]]; then
				echo
				echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
				echo "AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
				echo "AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN"
				echo "AWS_MFASESSION_INIT_TIME: $AWS_MFASESSION_INIT_TIME"
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

			getSessionTime _ret "${final_selection}"
			AWS_MFASESSION_INIT_TIME=${_ret}
			getMaxSessionDuration _ret "${final_selection}"
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
** It is imperative that the following environment variables are exported/unset\\n\
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
			envvar_config="unset AWS_PROFILE; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_MFASESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}" 
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
			envvar_config="export AWS_PROFILE=\"${final_selection}\"; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_MFASESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}"
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
			echo "unset AWS_MFASESSION_INIT_TIME"
			echo "unset AWS_SESSION_DURATION"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\""
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\""
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_MFASESSION_INIT_TIME=${AWS_MFASESSION_INIT_TIME}"
				echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; export AWS_MFASESSION_INIT_TIME=${AWS_MFASESSION_INIT_TIME}; export AWS_SESSION_DURATION=${AWS_SESSION_DURATION}; export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"${envvar_config_clear_custom_config}"

				if [[ "$OS" == "macOS" ]]; then
					echo -n "$envvar_config" | pbcopy
				elif [[ "$OS" == "Linux" ]] &&
					exists xclip; then

					echo -n "$envvar_config" | xclip -i
					xclip -o | xclip -sel clip
				fi
			else
				echo "unset AWS_MFASESSION_INIT_TIME"
				echo "unset AWS_SESSION_DURATION"
				echo "unset AWS_SESSION_TOKEN"

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; unset AWS_MFASESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_SESSION_TOKEN${envvar_config_clear_custom_config}"

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
			echo "unset AWS_MFASESSION_INIT_TIME \\"
			echo "unset AWS_SESSION_DURATION \\"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_PROFILE=\"${final_selection}\" \\"
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\" \\"
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\" \\"
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \\"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT} \\"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_MFASESSION_INIT_TIME=${AWS_MFASESSION_INIT_TIME} \\"
				echo "export AWS_SESSION_DURATION=${AWS_SESSION_DURATION} \\"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""
			else
				echo "unset AWS_MFASESSION_INIT_TIME \\"
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
