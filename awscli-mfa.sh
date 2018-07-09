#!/usr/bin/env bash

# todo: handle root account max session time @3600 & warn if present
# todo: handle secondary role max session time @3600 & warn
# todo: arg parsing, help
# todo: "--quick" switch which forgoes the aws queries before
#       the presentation

# NOTE: Debugging mode prints the secrets on the screen!
DEBUG="false"

# enable debugging with '-d' or '--debug' command line argument..
[[ "$1" == "-d" || "$1" == "--debug" ]] && DEB UG="true"
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

# minimum time required (in seconds) remaining in a MFA 
# or a role session for it to be considered valid
valid_session_time_slack=300

# COLOR DEFINITIONS ===================================================================================================

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

# DEBUG MODE WARNING & BASH VERSION ===================================================================================

if [[ "$DEBUG" == "true" ]]; then
	echo -e "\\n${BIWhite}${On_Red} DEBUG MODE ACTIVE ${Color_Off}\\n\\n${BIRed}${On_Black}NOTE: Debug output may include secrets!!!${Color_Off}\\n\\n"
	echo -e "Using bash version $BASH_VERSION\\n\\n"
fi

# FUNCTIONS ===========================================================================================================

# 'exists' for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

yesNo() {
	# $1 is _ret
	
	local old_stty_cfg
	local answer
	local _ret

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

OneOrTwo() {
	# $1 is _ret
	
	local old_stty_cfg
	local answer
	local _ret

	old_stty_cfg=$(stty -g)
	stty raw -echo
	answer=$( while ! head -c 1 | grep -i '[12]' ;do true ;done )
	stty "$old_stty_cfg"

	if echo "$answer" | grep -iq "^1" ; then
		_ret="1"
	else
		_ret="2"
	fi

	eval "$1=${_ret}"
}

# precheck envvars for existing/stale session definitions
checkEnvSession() {

	local this_time=$(date "+%s")
	local profiles_idx
	local _ret
	local parent_duration
	local this_session_type
	local profile_pass

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

	PRECHECK_AWS_SESSION_TYPE=$(env | grep AWS_SESSION_TYPE)
	[[ "$PRECHECK_AWS_SESSION_TYPE" =~ ^AWS_SESSION_TYPE[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_TYPE="${BASH_REMATCH[1]}"

	PRECHECK_AWS_SESSION_EXPIRY=$(env | grep AWS_ROLESESSION_EXPIRY)
	[[ "$PRECHECK_AWS_SESSION_EXPIRY" =~ ^AWS_ROLESESSION_EXPIRY[[:space:]]*=[[:space:]]*(.*)$ ]] &&
		PRECHECK_AWS_SESSION_EXPIRY="${BASH_REMATCH[1]}"

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
	profile_pass="false"
	if [[ "$PRECHECK_AWS_PROFILE" != "" ]]; then

		idxLookup profiles_idx merged_ident[@] "$PRECHECK_AWS_PROFILE"

		if [[ "$profiles_idx" == "" ]]; then

			# AWS_PROFILE ident is not recognized;
			# awscli commands without an explicit
			# profile switch will fail
			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS PROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}\\n\
      Purge the invalid AWS envvars with:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      (or else you must include '--profile someprofilename' to every aws command)"

		else
			# AWS_PROFILE is defined but valid
			profile_pass="true"
		fi

	else
		# AWS_PROFILE is empty
		profile_pass="true"
	fi

	# AWS_PROFILE must either be valid or empty,
	# otherwise there is no point for the below checks
	if [[ "$profile_pass" == "true" ]]; then

		# makes sure that the selected MFA session has not expired (whether 
		# it's defined in the environment or in ~/.aws/{config|credentials}).
		# 
		# First check the envvars
		if [[ "$PRECHECK_AWS_SESSION_TOKEN" != "" ]] &&
			[[ "$PRECHECK_AWS_SESSION_EXPIRY" != "" ]]; then
			# this is an in-env-only session profile (a role or an MFA session)

#todo: this should also include dynamic check, observing --quick.
#      at least `sts get-caller-identity` perhaps?

			getRemaining _ret "$PRECHECK_AWS_SESSION_EXPIRY"
			if [[ "${_ret}" -lt 1 ]]; then 

				[[ "$PRECHECK_AWS_SESSION_TYPE" != "" ]] &&
					this_session_type="$(echo $PRECHECK_AWS_SESSION_TYPE | awk '{print toupper($0)}') "

				echo -e "\\n${BIRed}${On_Black}NOTE: THE ${this_session_type}SESSION CONFIGURED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
			fi

		elif [[ "$PRECHECK_AWS_PROFILE" =~ -rolesession|-mfasession$ ]] &&
				[[ "$profiles_idx" != "" ]]; then
			# AWS_PROFILE is set, is valid, and refers to a persistent mfasession,
			# but TOKEN and EXPIRY are not set (known by exclusion from above),
			# so this should be select of a named mfasession profile

			# find the selected persistent session profile's expiry time if one exists
			session_expiry="${merged_aws_session_expiry[$profiles_idx]}"
			
			# if this session has been configured with this script,
			# the expiration time is available; if the expiry time
			# has not been provided, this value cannot be determined
			if [[ "$session_expiry" != "" ]]; then
				getRemaining _ret "$session_expiry"
				if [[ "${_ret}" -lt 1 ]]; then

					[[ "$PRECHECK_AWS_SESSION_TYPE" != "" ]] &&
						this_session_type="$(echo $PRECHECK_AWS_SESSION_TYPE | awk '{print toupper($0)}') "

					echo -e "\\n${BIRed}${On_Black}NOTE: THE ${this_session_type}SESSION SELECTED IN THE ENVIRONMENT HAS EXPIRED.${Color_Off}"
				fi
			fi

		elif [[ "$PRECHECK_AWS_PROFILE" == "" ]] &&
			[[ "$PRECHECK_AWS_ACCESS_KEY_ID" != "" ]] &&
			[[ "$PRECHECK_AWS_SECRET_ACCESS_KEY" != "" ]] &&
			[[ "$PRECHECK_AWS_SESSION_TOKEN" == "" ]]; then

			# this is an in-env baseprofile

#todo: this should also include dynamic check, observing --quick.
#      at least `sts get-caller-identity` perhaps?


		fi
	fi

	# detect and print informative notice of 
	# effective AWS envvars
	if [[ "${AWS_PROFILE}" != "" ]] ||
		[[ "${AWS_ACCESS_KEY_ID}" != "" ]] ||
		[[ "${AWS_SECRET_ACCESS_KEY}" != "" ]] ||
		[[ "${AWS_SESSION_TOKEN}" != "" ]] ||
		[[ "${AWS_ROLESESSION_EXPIRY}" != "" ]] ||
		[[ "${AWS_SESSION_TYPE}" != "" ]] ||
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
			[[ "$PRECHECK_AWS_SESSION_EXPIRY" != "" ]] && echo "   AWS_SESSION_EXPIRY: $PRECHECK_AWS_SESSION_EXPIRY"
			[[ "$PRECHECK_AWS_SESSION_TYPE" != "" ]] && echo "   AWS_SESSION_TYPE: $PRECHECK_AWS_SESSION_TYPE"
			[[ "$PRECHECK_AWS_DEFAULT_REGION" != "" ]] && echo "   AWS_DEFAULT_REGION: $PRECHECK_AWS_DEFAULT_REGION"
			[[ "$PRECHECK_AWS_DEFAULT_OUTPUT" != "" ]] && echo "   AWS_DEFAULT_OUTPUT: $PRECHECK_AWS_DEFAULT_OUTPUT"
			[[ "$PRECHECK_AWS_CA_BUNDLE" != "" ]] && echo "   AWS_CA_BUNDLE: $PRECHECK_AWS_CA_BUNDLE"
			[[ "$PRECHECK_AWS_SHARED_CREDENTIALS_FILE" != "" ]] && echo "   AWS_SHARED_CREDENTIALS_FILE: $PRECHECK_AWS_SHARED_CREDENTIALS_FILE"
			[[ "$PRECHECK_AWS_CONFIG_FILE" != "" ]] && echo "   AWS_CONFIG_FILE: $PRECHECK_AWS_CONFIG_FILE"
			echo
	fi
}

# workaround function for lack of macOS bash's assoc arrays
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

# adds a new property+value to the defined config file
addConfigProp() {
	# $1 is the target file
	# $2 is the target profile (the anchor)
	# $3 is the property
	# $4 is the value
	
	local target_file="$1"
	local target_profile="$2"
	local new_property="$3"
	local new_value="$4"
	local replace_me
	local DATA

	replace_me="\\[${target_profile}\\]"

	DATA="[${target_profile}]\\n${new_property} = ${new_value}"
	echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${target_file}")" > "${target_file}"
}

# updates an existing property value in the defined config file
updateUniqueConfigPropValue() {
	# $1 is target file
	# $2 is old property value
	# $3 is new property value
	
	local target_file="$1"
	local old_value="$2"
	local new_value="$3"

	if [[ "$OS" == "macOS" ]]; then 
		sed -i '' -e "s/${old_value}/${new_value}/g" "$target_file"
	else 
		sed -i -e "s/${old_value}/${new_value}/g" "$target_file"
	fi
}

# deletes an existing property value in the defined config file
deleteConfigProp() {
	# $1 is target file
	# $2 is the target profile
	# $3 is the prop name to be deleted
	
	local target_file="$1"
	local target_profile="$2"
	local prop_to_delete="$3"
	local TMPFILE
	local delete_active="false"
	local profile_ident

	if [[ $target_file != "" ]] &&
		[ ! -f "$target_file" ]; then
		
		echo -e "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n"
		exit 1
	fi

	TMPFILE=$(mktemp "$HOME/tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[[[:space:]]*(.*)[[:space:]]*\].* ]]; then
			profile_ident="${BASH_REMATCH[1]}"

			if [[ "$profile_ident" == "$target_profile" ]]; then
				# activate deletion for the matching profile
				delete_active="true"

			elif [[ "$profile_ident" != "" ]] &&
				[[ "$profile_ident" != "$target_profile" ]]; then
				# disable deletion when we're looking at
				# a non-matching profile label

				delete_active="false"

			fi
		fi

		if [[ "$delete_active" == "false" ]] || 
			[[ ! "$line" =~ ^$prop_to_delete ]]; then

			echo "$line" >> "$TMPFILE"

		else 
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}Deleting property '$prop_to_delete' in profile '$profile_ident'.${Color_Off}"

		fi

	done < "$target_file"

	mv -f "$TMPFILE" "$target_file"

}

# save the MFA/role session expiration
# timestamp in the MFA/role session profile in
# the credfile (usually ~/.aws/credentials)
writeSessionExpTime() {
	# $1 is the profile (ident)
	# $2 is the session expiration timestamp

	local this_ident="$1"
	local new_session_expiration_timestamp="$2"

	local idx
	local old_session_exp

	# get idx for the current ident
	idxLookup idx merged_ident[@] "$this_ident"

	# must have profile index to proceed
	if [[ "$idx" != "" ]]; then

		merged_aws_session_expiry[$idx]="$new_session_expiration_timestamp"
		
		# find the selected profile's existing
		# expiry time if one exists
		getSessionExpiry old_session_exp "$this_ident"

		if [[ "$session_exp" != "" ]]; then
			# time entry exists for the profile, update it
			updateUniqueConfigPropValue "$CREDFILE" "$old_session_exp" "$new_session_expiration_timestamp"
		else
			# no time entry exists for the profile; 
			# add a new property line after the header "$this_ident"
			addConfigProp "$CREDFILE" "$this_ident" "aws_session_expiry" "$new_session_expiration_timestamp"
		fi

	fi
}

writeSessmax() {
	# $1 is the target ident (role)
	# $2 is the sessmax value

	local this_target_ident="$1"
	local this_sessmax="$2"
	local local_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	if [[ "${merged_sessmax[$local_idx]}" == "" ]]; then
		# add the sessmax property
		addConfigProp "$CONFFILE" "$this_target_ident" "sessmax" "$this_sessmax"

	elif [[ "${this_sessmax}" == "erase" ]]; then
		# delete the existing sessmax property
		deleteConfigProp "$CONFFILE" "$this_target_ident" "sessmax"

	else
		# update the existing sessmax value (delete+add)
		deleteConfigProp "$CONFFILE" "$this_target_ident" "sessmax"
		addConfigProp "$CONFFILE" "$this_target_ident" "sessmax" "$this_sessmax"
	fi

}

#todo: get-role provides principals, get-user/get-caller-identity provides Arn...
#      it should be possible to make a good guess of the correct profile in 
#      most cases by picking the first match of a principal + account ID,
#      perhaps even the vMFAd (if role requires MFA, then look for principal's
#      match, and thus maybe that profile has configured vMFAd). Unless 100% 
#      match, ask the user

writeRoleSourceProfile() {
	# $1 is the target profile ident to add source_profile to
	# $2 is the source profile ident 

	local target_ident="$1"
	local source_profile_ident="$2"
	local local_idx
	local existing_source_profile

	# confirm that the target profile indeed
	# doesn't have a source profile entry
	existing_source_profile="$(aws --profile "$target_ident" configure get source_profile)"

	# double-check that this is a role, and that this has no
	# source profile as of yet; then add on a new line after
	# the existing header "[${target_ident}]"
	idxLookup local_idx merged_ident[@] "$target_ident"
	if [[ "$existing_source_profile" == "" ]] &&
		[[ "${merged_role_source_profile_ident[$local_idx]}" == "" ]] &&
		[[ "${merged_type[$local_idx]}" == "role" ]]; then

		addConfigProp "$CONFFILE" "$target_ident" "source_profile" "$source_profile_ident"
	fi
}

#todo: $HOME/.aws/cli/cache/* role session sync to the $CREDFILE
# IF EXISTS JQ (if there are cached roles in the cache dir and JQ is not installed, notify)
#  iterate $merged_ident for roles, look for ${merged_role_session_name[$idx]};
#   grep files in ~/.aws/cli/cache/ for the role_session_name; 
#    if found, read the cache file in in with JQ, get:
#     - role_session_name either from AssumedRoleId or Arn
#     - aws_access_key_id from AccessKeyId
#     - aws_secret_access_key from SecretAccessKey
#     - aws_session_token from SessionToken
#     - aws_session_expiry from Expiration
#    if the session is current (and newer than in $CREDFILE?)
#    write the data to $CREDFILE as ${merged_ident[$idx]}-rolesession

# persist the baseprofile's vMFAd Arn
# in the conffile (usually ~/.aws/config)
# if a vMFAd has been configured/attached
writeBaseprofileMfaArn() {
	# $1 is the profile (ident)
	# $2 is the vMFAd Arn (can be set to 'erase')

	local this_ident="$1"
	local baseprofile_vmfad_arn="$2"

	local idx

	# get idx for the current ident
	idxLookup idx merged_ident[@] "$this_ident"

	# must have a profile index to proceed
	if [[ "$idx" != "" ]]; then

		if [[ "$baseprofile_vmfad_arn" == "erase" ]]; then
			# vmfad has gone away; delete the existing mfad_arn entry
			deleteConfigProp "$CONFFILE" "${merged_ident[$idx]}" "mfa_arn"
		elif [[ "$baseprofile_vmfad_arn" != "" ]]; then
			# add a vmfad entry (none exists previously)
			addConfigProp "$CONFFILE" "${merged_ident[$idx]}" "mfa_arn" "$baseprofile_vmfad_arn"
		fi
	fi
}

writeRoleMFASerialNumber() {
	# $1 is the target profile ident to add mfa_serial to
	# $2 is the mfa_serial

	local this_target_ident="$1"
	local this_mfa_serial="$2"
	local local_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	if [[ "${merged_type[$local_idx]}" == "role" ]]; then

		if [[ "${merged_role_mfa_serial[$local_idx]}" == "" ]]; then
			# add the mfa_serial property
			addConfigProp "$CONFFILE" "$this_target_ident" "mfa_serial" "$this_mfa_serial"

		elif [[ "${this_mfa_serial}" == "erase" ]]; then  # "mfa_serial" is set to "erase" when the MFA requirement for a role has gone away
			# delete the existing mfa_serial property
			deleteConfigProp "$CONFFILE" "$this_target_ident" "mfa_serial"

		else
			# update the existing mfa_serial value (delete+add)
			deleteConfigProp "$CONFFILE" "$this_target_ident" "mfa_serial"
			addConfigProp "$CONFFILE" "$this_target_ident" "mfa_serial" "$this_mfa_serial"
		fi
	fi
}

# return the session expiry time for
# the given role/mfa session profile
getSessionExpiry() {
	# $1 is _ret
	# $2 is the profile ident

	local this_ident="$2"

	local idx
	local session_time
 
	# find the profile's init/expiry time entry if one exists
	idxLookup idx merged_ident[@] "$this_ident"

	session_time=${merged_aws_session_expiry[$idx]}

	eval "$1=${session_time}"
}

#todo: $3 must be added into calling locations
getMaxSessionDuration() {
	# $1 is _ret
	# $2 is the profile ident
	# $3 is "baseprofile" or "role";
	#    required for the baseprofiles and roles (but optional for the sessions
	#    since the session type can be derived from the profile_ident)

	local this_profile_ident="$2"
	local this_sessiontype="$3"

	local idx
	local this_duration

	# use parent profile ident if this is a role or MFA session
	if [[ "$this_profile_ident" =~ ^(.*)-mfasession$ ]]; then
		this_profile_ident="${BASH_REMATCH[1]}"
		this_sessiontype="baseprofile"

	elif [[ "$this_profile_ident" =~ ^(.*)-rolesession$ ]]; then
		this_profile_ident="${BASH_REMATCH[1]}"
		this_sessiontype="role"

	fi

	# look up a possible custom duration for the parent profile/role
	idxLookup idx merged_ident[@] "$this_profile_ident"

	if [[ $idx != "" && "${merged_sessmax[$idx]}" != "" ]]; then
		this_duration=${merged_sessmax[$idx]}

	else
		# sessmax is not being used; using the defaults

		if [[ "$this_sessiontype" == "baseprofile" ]]; then
			this_duration=$MFA_SESSION_LENGTH_IN_SECONDS 

		elif [[ "$this_sessiontype" == "role" ]]; then
			this_duration=3600  # the default AWS role session length is 3600 seconds if not otherwise defined

		fi
	fi

	eval "$1=${this_duration}"
}

# Returns remaining seconds for the given expiry timestamp
# In the result 0 indicates expired, -1 indicates NaN input
getRemaining() {
	# $1 is _ret
	# $2 is the expiration timestamp

#todo: has the API change been reflected everywhere?
	
	local expiration_timestamp="$3"
	local this_time=$(date "+%s")
	local remaining=0
	local this_session_time_slack

	if [ ! -z "${timestamp##*[!0-9]*}" ]; then
		
		(( this_session_time_slack=this_time+valid_session_time_slack ))
		if [[ $this_session_time_slack -lt $expiration_timestamp ]]; then
			((remaining=this_time-expiration_timestamp))
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
	# $2 is the time_in_seconds

	local time_in_seconds="$2"

	case $time_in_seconds in
		-1)
			response=""
			;;
		0)
			response="00h:00m:00s"
			;;
		*)
			response=$(printf '%02dh:%02dm:%02ds' $((timestamp/3600)) $((timestamp%3600/60)) $((timestamp%60)))
			;;
	esac
	eval "$1=${response}"
}

DoesValidDefaultExist() {
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
	# $1 is _ret: exit_on_error (true/false)
	# $2 is the AWS return (may be good or bad)
	# $3 is the profile name (if present) AWS command was run against
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
				[[ "$DEBUG" == "true" ]] && echo -e "\\n\${Cyan}${On_Black}Account alias found from cache for profile ident: '$local_profile_ident'\\n\${ICyan}${account_alias_result}${Color_Off}\\n\\n"
			fi
		done

		if  [[ "$cache_hit" == "false" ]]; then
			# get the account alias (if any) for the profile
			account_alias_result="$(aws --profile "$local_profile_ident" iam list-account-aliases \
				--output text \
				--query 'AccountAliases' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n\${Cyan}${On_Black}result for: 'aws --profile \"$local_profile_ident\" iam list-account-aliases --query 'AccountAliases' --output text':\\n\${ICyan}${account_alias_result}${Color_Off}\\n\\n"

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

	local user_arn
	local profile_check
	local cached_get_role
	local get_this_mfa_arn
	local get_this_role_arn
	local get_this_role_sessmax
	local get_this_role_mfa_req
	local get_this_session_status
	local idx
	local notice_reprint="true"

	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do

		if [[ "$notice_reprint" == "true" ]]; then
			echo -ne "\\n${BIWhite}${On_Black}Please wait"
			notice_reprint="false"
		fi
		
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then  # BASEPROFILE AUGMENT ---------------------------------

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws --profile "${merged_ident[$idx]}" sts get-caller-identity \
				--output text \
				--query 'Arn' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$idx]}\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${user_arn}${Color_Off}\\n\\n"

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
				# since 'sts get-caller-identity' above verified that the creds
				# are valid, this checks for possible requirement for a valid
				# MFA session
				profile_check="$(aws --profile "${merged_ident[$idx]}" iam get-user \
					--query 'User.Arn' \
					--output text 2>&1)"
					
				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$idx]}\" iam get-user --query 'User.Arn' --output text':\\n${ICyan}${profile_check}${Color_Off}\\n\\n"

				if [[ "$profile_check" =~ ^arn:aws ]]; then
					merged_baseprofile_operational_status[$idx]="ok"

				elif [[ "$profile_check" =~ 'AccessDenied' ]]; then  # may require an MFA session
					merged_baseprofile_operational_status[$idx]="limited"

				elif [[ "$profile_check" =~ 'could not be found' ]]; then
					merged_baseprofile_operational_status[$idx]="none"

				else
					merged_baseprofile_operational_status[$idx]="unknown"

				fi

				# get the account alias (if any)
				# for the user/profile
				getAccountAlias _ret "${merged_ident[$idx]}"
				merged_account_alias[$idx]="${_ret}"

				# get vMFA device ARN if available (obviously not available
				# if a vMFAd hasn't been configured for the profile)
				get_this_mfa_arn="$(aws --profile "${merged_ident[$idx]}" iam list-mfa-devices \
					--user-name "${merged_username[$idx]}" \
					--output text \
					--query 'MFADevices[].SerialNumber' 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$profile_ident\" iam list-mfa-devices --user-name \"${merged_username[$idx]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${get_this_mfa_arn}${Color_Off}\\n\\n"

				if [[ "$get_this_mfa_arn" =~ ^arn:aws ]]; then
					if [[ "$get_this_mfa_arn" != "${merged_mfa_arn[$idx]}" ]]; then
						# persist MFA Arn in the config..
						writeBaseprofileMfaArn "${merged_ident[$idx]}" "$get_this_mfa_arn"

						# ..and update in this script state
						merged_mfa_arn[$idx]="$get_this_mfa_arn"
					fi

				elif [[ "$get_this_mfa_arn" == "" ]]; then
					# empty result, no error: no vMFAd confgured currently

					merged_mfa_arn[$idx]=""

					if [[ "${merged_mfa_arn[$idx]}" != "" ]]; then
						# erase the existing persisted vMFAd Arn
						# from the profile since one exists currently
						writeBaseprofileMfaArn "${merged_ident[$idx]}" "erase"
					fi

				else  # (error conditions such as NoSuchEntity or Access Denied)

					# we do not delete the persisted Arn in case a policy
					# is blocking 'iam list-mfa-devices'; user has the option
					# to add a "mfa_serial" manually to the baseprofile config
					# to facilitate associated role session requests that
					# require MFA, even when 'iam list-mfa-devices' isn't 
					# allowed.

					merged_mfa_arn[$idx]=""

				fi

			else
				# must be a bad profile
				merged_baseprofile_arn[$idx]=""

			fi

		elif [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]]; then  # ROLE AUGMENT (no point augmenting invalid roles) -----------

			if [[ "$jq_available" == "false" ]]; then
				echo -e "\\n${BIWhite}${On_Black}\
Since you are using roles, consider installing 'jq'.${Color_Off}\\n
It will speed up some role-related operations and\\n\
automatically import roles that are initialized\\n\
outside of this script.\\n"

				if [[ "$OS" == "macOS" && "$has_brew" == "true" ]]; then 
					echo -e "Install with: 'brew install jq'\\n"

				elif  [[ "$OS" == "Linux" ]]; then 
					echo -e "Install with: 'apt-get install jq'\\n"

				fi

			elif [[ "$jq_minimum_version" == "false" ]]; then
				echo -e "\\n${BIWhite}${On_Black}\
Please upgrade your 'jq' installation.${Color_Off}\\n"

				if [[ "$OS" == "macOS" && "$has_brew" == "true" ]]; then 
					echo -e "Upgrade with: 'brew upgrade jq'\\n"
				elif  [[ "$OS" == "Linux" ]]; then 
					echo -e "Upgrade with: 'apt-get update && apt-get upgrade jq'\\n"
				fi

			fi

			# a role must have a source_profile defined 
			if [[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then

				notice_reprint="true"

				echo -e "\\n\\n${BIRed}${On_Black}\
The role profile '${merged_type[$idx]}' does not have a source_profile defined.${Color_Off}\\n\
A role must have the means to authenticate, so select below the associated source profile,\\n"

				# prompt for source_profile selection for this role
				while :
				do
					echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS BASE PROFILES: ${Color_Off}\\n"

					for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
					do

						if [[ "${merged_type[$int_idx]}" == "baseprofile" ]]; then

							# create a more-human-friendly selector 
							# digit (starts from 1 rather than 0)
							(( selval=int_idx+1 ))
							echo -e "${BIWhite}${On_Black}${selval}: ${merged_ident[$int_idx]}${Color_Off}\\n"
						fi
					done

					# prompt for a base profile selection
					echo -en  "\\n${BIWhite}${On_Black}ENTER A SOURCE PROFILE ID AND PRESS ENTER (or Enter by itself to skip):${Color_Off} "
					read -r role_auth
					echo -en  "\\n"

					(( max_sel_val=selval+1 ))
					if [[ "$role_auth" -gt 0 && "$role_auth" -lt $max_sel_val ]]; then
						# this is a base profile selector for
						# a valid role source_profile

						(( actual_source_index=role_auth-1 ))
						# everybody within the ForceMFA policy is allowed 
						# to query roles without active MFA session;
						# attempt to use the selected profile to query
						# the role (we already know the role's Arn, so 
						# this is just a reverse lookup to validate).
						# If jq is available, this will cache the result.
						if [[ "$jq_minimum_version_available" ]]; then
#todo: should any query be preceded with
# [[ merged_baseprofile_arn[$idx] != "" ]] ..?
							cached_get_role="$(aws --profile "${merged_ident[$actual_source_index]}" iam get-role \
							--role-name "${merged_role_name[$idx]}" \
							--output json 2>&1)"

							[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$actual_source_index]}\" iam get-role --role-name \"${merged_ident[$idx]}\" --output json':\\n${ICyan}${cached_get_role}${Color_Off}"				

							get_this_role_arn="$(printf '\n%s\n' "$cached_get_role" | jq -r '.Role.Arn')"

						else

							get_this_role_arn="$(aws --profile "${merged_ident[$actual_source_index]}" iam get-role \
								--role-name "${merged_role_name[$idx]}" \
								--query 'Role.Arn' \
								--output text 2>&1)"

							[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$actual_source_index]}\" iam get-role --role-name \"${merged_ident[$idx]}\" --query 'Role.Arn' --output text':\\n${ICyan}${get_this_role_arn}${Color_Off}"				

						fi

						if [[ "$get_this_role_arn" == "${merged_role_arn[$idx]}" ]]; then
							# the source_profile is confirmed working

							merged_role_source_profile_ident[$idx]="${merged_ident[$actual_source_index]}"
							merged_role_source_profile_idx[$idx]="$actual_source_index"
							writeRoleSourceProfile "$idx" "${merged_ident[$actual_source_index]}"
							break

						elif [[ "$get_this_role_arn" =~ NoSuchEntity ]]; then
							# the source_profile does not recognize the role; invalid

							echo -e "\\n${BIRed}${On_Black}\
The selected source profile '${merged_ident[$actual_source_index]}' is not associated with\\n\
with the role '${merged_ident[$idx]}'. Select another profile.${Color_Off}\\n\\n\\n"

							# this flows through, and thus reprints the base
							# profile list for re-selection
						else
							echo -e "\\n${BIWhite}${On_Black}\
The selected profile '${merged_ident[$actual_source_index]}' could not be verified as\\n\
the source profile for the role '${merged_ident[$idx]}'. However, this could be\\n\
because of the selected profile's permissions.${Color_Off}\\n\\n
Do you want to keep the selection? ${BIWhite}${On_Black}Y/N${Color_Off}"

							yesNo _ret
							if [[ "${_ret}" == "yes" ]]; then
								echo -e "\\n${BIWhite}${On_Black}\
Using the profile '${merged_ident[$actual_source_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n"
								merged_role_source_profile_ident[$idx]="${merged_ident[$actual_source_index]}"
								writeRoleSourceProfile "$idx" "${merged_ident[$actual_source_index]}"
								break
							fi

						fi

					elif [[ "$role_auth" =~ ^[[:space:]]*$ ]]; then
						# skip setting source_profile
						break

					else
						# an invalid entry

						echo -e "\\n${BIRed}${On_Black}\
Invalid selection.${Color_Off}\\n\
Try again, or just press Enter to skip setting source_profile\\n\
or vMFAd serial number for this role profile at this time.\\n"
					fi

				done

			else
				# source_profile exists already, so just do 
				# a lookup for cache here if jq is enabled
				if [[ "$jq_minimum_version_available" ]]; then
					cached_get_role="$(aws --profile "${merged_ident[$actual_source_index]}" iam get-role \
					--role-name "${merged_role_name[$idx]}" \
					--output json 2>&1)"
				fi
			fi

			# retry setting region now in case it wasn't
			# available earlier (in the offline config) 
			# in the absence of a defined source_profile
			if [[ "${merged_region[$idx]}" == "" ]] &&   # a region is not set for this role
				[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&  # the source_profile is [now] defined
				[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # and the source_profile has a region set

				merged_region[$idx]="${merged_region[${merged_role_source_profile_idx[$idx]}]}"

				# make the role region persistent
				aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}"
			fi

			# execute the following only when a source profile
			# has been defined; since we give the option to 
			# skip setting a missing source profile, this is
			# conditionalized
			if [[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then

				# role sessmax dynamic augment; get MaxSessionDuration from role 
				# if queriable, and write to the profile if 1) not blank, and 
				# 2) different from the default 3600
				if [[ "$jq_minimum_version_available" ]]; then
					# use the cached get-role to avoid
					# an extra lookup if jq is available
					get_this_role_sessmax="$(printf '\n%s\n' "$cached_get_role" | jq -r '.Role.MaxSessionDuration')"

				else

					get_this_role_sessmax="$(aws --profile "${merged_role_source_profile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--query 'Role.MaxSessionDuration' \
						--output text 2>&1)"

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_profile_ident[$idx]}\" iam get-role --role-name \"${merged_ident[$idx]}\" --query 'Role.MaxSessionDuration' --output text':\\n${ICyan}${get_this_role_sessmax}${Color_Off}"				

				fi

				# minimum acceptable sessmax value is 900 seconds,
				# hence at least three digits in the pattern below
				if [[ "$get_this_role_sessmax" =~ ^[[:space:]]*[[:digit:]][[:digit:]][[:digit:]]+[[:space:]]*$ ]]; then

					# set and persist get get_this_role_sessmax if it differs
					# from the existing value (do not set/persist the default 
					# 3600 if the value has not been previously set)
					if [[ "$get_this_role_sessmax" != "${merged_sessmax[$idx]}" ]] &&
						[[ $get_this_role_sessmax -ge 900 ]] &&
						! [[ "${merged_sessmax[$idx]}" == "" && 
							"$get_this_role_sessmax" == "3600" ]]; then

						merged_sessmax[$idx]="$get_this_role_sessmax"
						writeSessmax "${this_ident[$idx]}" "$get_this_role_sessmax"
					elif ( [[ "$get_this_role_sessmax" == "" ]] ||
						[[ "$get_this_role_sessmax" == "3600" ]] ) &&
						[[ "${merged_sessmax[$idx]}" != "" ]]; then

						merged_sessmax[$idx]="3600"
						writeSessmax "${this_ident[$idx]}" "erase"
					fi

				fi

			fi

		elif [[ "${merged_type[$idx]}" =~ "mfasession|rolesession" ]]; then  # MFA OR ROLE SESSION AUGMENT ------------

			# no point to augment this session if the timestamps indicate
			# the session has expired. Note: this also checks the session
			# validity for the sessions whose init+sessmax or expiry
			# weren't set for some reason. After this process
			# merged_session_status will be populated for all sessions
			# with one of the following values:
			# valid, expired, invalid (i.e. not expired but not functional)
			if [[ "${merged_session_status[$idx]}" != "expired" ]]; then

				get_this_session_status="$(aws --profile "${merged_ident[$idx]}" sts get-caller-identity \
					--query 'Arn' \
					--output text 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$idx]}\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${get_this_session_status}${Color_Off}"				

				if [[ "$default_profile_arn" =~ ^arn:aws:iam:: ]] &&
					[[ ! "$default_profile_arn" =~ 'error occurred' ]]; then

					merged_session_status[$idx]="valid"
				else
					merged_session_status[$idx]="invalid"
				fi

			fi

## BEGIN TO BE DELETED (waiting output rework before deleting) -----------------
## old isSessionValid()
			getSessionExpiry _ret_timestamp "$mfa_profile_ident"
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
## END TO BE DELETED -----------------------------------------------------------

		fi

		[[ "$DEBUG" != "true" ]] &&
			echo -n "."

	done

	# phase II for things that had deps
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do

		if [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]] &&
			[[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then  # ROLE AUGMENT, PHASE II -------------------

			# add source_profile username to the merged_role_source_username array
			merged_role_source_username[$idx]=""
			if [[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&
				[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&
				[[ "${merged_username[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # the source profile username is available

				# merged_username is now available for all base profiles
				# (since this comes after the first dynamic augment loop)
				merged_role_source_username[$idx]="${merged_username[${merged_role_source_profile_idx[$idx]}]}"
			fi			

			# role_mfa requirement check (persist the associated 
			# source profile mfa_serial if avialable/changed)
			if [[ "$jq_minimum_version_available" ]]; then
				# use the cached get-role to avoid
				# an extra lookup if jq is available
				get_this_role_mfa_req="$(printf '\n%s\n' "$cached_get_role" | jq -r '.Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"')"

			else
# todo: again, check for
# [[ merged_baseprofile_arn[$idx] != "" ]] 
# since it is known..?
				get_this_role_mfa_req="$(aws --profile "${merged_role_source_profile_ident[$idx]}" iam get-role \
					--role-name "${merged_ident[$idx]}" \
					--query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' \
					--output text 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_profile_ident[$idx]}\" iam get-role --role-name \"${merged_ident[$idx]}\" --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' --output text':\\n${ICyan}${get_this_role_mfa_req}${Color_Off}"				

			fi

			if [[ "$get_this_role_mfa_req" == "true" ]]; then

				merged_role_mfa_required[$idx]="true"

				this_source_mfa_arn="${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}"

				if [[ "$this_source_mfa_arn" == "" ]] &&
					[[ "${merged_role_mfa_serial[$idx]}" != "" ]]; then

					# A non-functional role: the role requires an MFA,
					# the role profile has a vMFAd configured, but the
					# source profile [no longer] has one configured
					writeRoleMFASerialNumber "${this_ident[$idx]}" "erase"

				elif [[ "$this_source_mfa_arn" != "" ]] &&
					[[ "${merged_role_mfa_serial[$idx]}" != "$this_source_mfa_arn" ]]; then

					# the role requires an MFA, the source profile
					# has vMFAd available, and it differs from what
					# is currently configured (including blank)
					# 
					# Note: "blank to configured" is the most likely scenario
					# here since unless the role's source_profile changes
					# the vMFAd Arn doesn't change even if it gets reissued
					writeRoleMFASerialNumber "${this_ident[$idx]}" "$this_source_mfa_arn"
				fi

			else

				merged_role_mfa_required[$idx]="false"

				# the role [no longer] requires an MFA
				# and one is currently configured, so remove it
				if [[ "${merged_role_mfa_serial[$idx]}" != "" ]]; then
					writeRoleMFASerialNumber "${this_ident[$idx]}" "erase"
				fi
			fi

		fi

		[[ "$DEBUG" != "true" ]] &&
			echo -n "."
	done

	echo
}

getMfaToken() {
	# $1 is _ret
	# $2 is token_target ('mfa' or 'role')
	
	local mfatoken=""
	local token_target="$2"

	while :
	do
		echo -en "${BIWhite}${On_Black}"
		read -p ">>> " -r mfatoken
		echo -en "${Color_Off}"
		if [[ "$token_target" == "mfa" ]]; then

			if ! [[ "$mfatoken" =~ ^$ || "$mfatoken" =~ [0-9]{6} ]]; then
				echo -e "${BIRed}${On_Black}The MFA token must be exactly six digits, or blank to bypass (to use the profile without an MFA session).${Color_Off}"
				continue
			else
				break
			fi

		elif [[ "$token_target" == "role" ]]; then

			if ! [[ "$mfatoken" =~ [0-9]{6} ]]; then
				echo -e "${BIRed}${On_Black}The MFA token must be exactly six digits.${Color_Off}"
				continue
			else
				break
			fi

		fi
	done

	eval "$1=$mfatoken"	
}

persistSession() {
 
# there should be question/no question option for persisting, because persistSession could be
# "persistSessionMaybe", and thus include the option to prompt the user for whether the session
# should be persisted (or not.. maybe that should be on the calling side?) Anyway, session init
# request should be forcable so that there's no prompt (if there'd otherwise be a prompt), because
# the session init *requires* the persisted MFA session to be there!

 	# $1 is the baseprofile ident
	# $2 is the target (session) ident
	# $3 is session result dataset

#todo: should we use 3 to get the dataset and then AGAIN re-unpack it, or should we rely on acquireSession's global transits?
# Inbound data either as a segmented, standardized string, or as JSON
# if jq is available and the first character is "{", treat as JSON,
# otherwise as a standardized string

	echo -e "${BIWhite}${On_Black}\
Make this MFA session persistent?${Color_Off} (Saves the session in $CREDFILE\\n\
so that you can return to it during its validity period, ${validity_period}.)"

	read -s -p "$(echo -e "${BIWhite}${On_Black}Yes (default) - make peristent${Color_Off}; No - only the envvars will be used ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
	echo		
	if [[ $REPLY =~ ^[Yy]$ ]] ||
		[[ $REPLY == "" ]]; then

		# get the resulting session profile idx (if one exists in the merge arrays)
		idxLookup session_profile_idx merged_ident[@] "$AWS_SESSION_PROFILE_IDENT"

		if [[ "$session_profile_idx" == "" ]]; then		

			# no existing profile was found; make sure there's
			# a stub entry for the session profile in $CONFFILE
			echo -en "\\n\\n">> "$CONFFILE"
			echo "[profile ${AWS_SESSION_PROFILE_IDENT}]" >> "$CONFFILE"
		fi

		# persist the session expiration time
		writeSessionExpTime "$AWS_SESSION_PROFILE_IDENT" "$AWS_SESSION_EXPIRY"
		
#todo: what is this??
		persistent_MFA="true"

		# export the selection to the remaining subshell commands in this script
		# so that "--profile" selection is not required, and in fact should not
		# be used for setting the credentials (or else they go to the conffile)
		export AWS_PROFILE="$AWS_SESSION_PROFILE_IDENT"

		# NOTE: These do not require the "--profile" switch because AWS_PROFILE
		#       has been exported above. If you set --profile, the details
		#       go to the CONFFILE instead of CREDFILE (so don't set it! :-)
		aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
		aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
		aws configure set aws_session_token "$AWS_SESSION_TOKEN"
		
	fi

}

acquireSession() {
	# $1 is _ret
	# $2 is the base profile or the role profile ident

	local session_base_profile_ident="$2"
	local mfa_token=""
	local this_role_arn
	local this_role_session_name
	local source_profile_has_session
	local source_profile_mfa_session_status
	local role_init_profile
	local mfa_session_detail
	local mfa_session_duration
	local profile_idx
	local output_type
	local get_session
	local profile_check
	local result=""
	local result_check
	local session_init="false"
	local _ret

	[[ "$jq_minimum_version_available" ]] &&
		output_type="json" ||
		output_type="text"

	# get the requesting profile idx
	idxLookup profile_idx merged_ident[@] "$session_base_profile_ident"

	# get the type of session being requested ("baseprofile" for mfasession, or "role" for rolesession)
	session_request_type="${merged_type[$profile_idx]}"

	if [[ "$session_request_type" == "baseprofile" ]]; then  # INIT MFASESSION ----------------------------------------

		getMaxSessionDuration mfa_session_duration "${merged_ident[$profile_idx]}" "baseprofile"

		echo -e "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${merged_ident[$profile_idx]}'${Color_Off} to start/renew an MFA session,\\n\
or leave empty (just press [ENTER]) to use the selected profile without the MFA.\\n"

		getMfaToken mfa_token "mfa"

		result=$(aws --profile "${merged_ident[$profile_idx]}" sts get-session-token \
			--serial-number "${merged_mfa_arn[$profile_idx]}" \
			--duration "$mfa_session_duration" \
			--token-code "$mfa_token" \
			--output "$output_type")

		if [[ "$DEBUG" == "true" ]]; then
			echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$profile_idx]}\" sts get-session-token --serial-number \"${merged_mfa_arn[$profile_idx]}\" --duration \"$mfa_session_duration\" --token-code \"$mfa_token\" --output \"$output_type\"':\\n${ICyan}${result}${Color_Off}\\n\\n"
		fi

		checkAWSErrors "true" "$result" "${merged_ident[$profile_idx]}" "An error occurred while attempting to acquire the MFA session credentials; cannot continue!"

	elif [[ "$session_request_type" == "role" ]]; then  # INIT ROLESESSION --------------------------------------------
		# get the role's source_profile
		role_init_profile="${merged_role_source_profile_ident[$profile_idx]}"

		# does the source_profile have a session?
		source_profile_has_session="${merged_has_session[${merged_role_source_profile_idx[$profile_idx]}]}"

		# is the session valid?
		# (role profile IDX -> role source_profile IDX -> source profile's session IDX -> source profile's session status)
		source_profile_mfa_session_status="${merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$profile_idx]}]}]}"

		if [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&
			[[ "$source_profile_has_session" == "true" ]] &&
			[[ "$source_profile_mfa_session_status" == "valid" ]]; then
			# ROLE: MFA required, source profile has an active MFA

			# use the source profile's active MFA session
			role_init_profile="${merged_role_source_profile_ident[$profile_idx]}-mfasession"

		elif [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&

			( [[ "$source_profile_has_session" == "false" ]] ||
			[[ "$source_profile_mfa_session_status" != "valid" ]] ) &&  # includes expired, invalid, and unknown session statuses

			[[ "${merged_role_mfa_serial[$profile_idx]}" != "" ]]; then  # since the source_profile's merged_mfa_arn is acquired dynamically, the persistent merged_role_mfa_serial has a higher chance of being there (from run-to-run)

			# ROLE: MFA required, source profile does not have an active MFA session, but it does have an attached vMFAd

			echo -en "\\n${BIWhite}${On_Black}\
The role session requires MFA authentication and the role's source profile\\n\
doesn't have an active MFA session.${Color_Off} You can either:\\n\\n\
 ${BIWhite}1${Color_Off} - Start a new persistent MFA session for the source profile\\n\
     (it will be automatically used to authenticate for the role session).\\n\\n\
 ${BIWhite}2${Color_Off} - Use the role's source profile virtual MFA device\\n\
      for a one-off authentication for this role session.\\n\\n\
Either selection will prompt for a MFA token. ${BIWhite}${On_Black}SELECT 1 or 2 >>>${Color_Off} "

			oneOrTwo _ret

			if [[ "${_ret}" == "1" ]]; then  # start a new MFA session for the parent..

				acquireSession mfa_session_detail "${merged_role_source_profile_ident[$profile_idx]}" "true"
				role_init_profile="${merged_role_source_profile_ident[$profile_idx]}-mfasession"

			elif [[ "${_ret}" == "2" ]]; then  # one-off MFA auth

				# .. or use a one-off token to init the session;
				# use --profile 'init_with_profile' (baseprofile), req token

				echo -e "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${role_init_profile}'${Color_Off} to for a one-off\\n\
authentication for a role session initialization.\\n"

				getMfaToken mfa_token "role"
			fi

			if [[ "$mfa_token" != "" ]]; then 
				token_switch=" --token-code ${mfa_token} "
				serial_switch=" --serial-number ${merged_mfa_serial[$profile_idx]} "
			else
				token_switch=""
				serial_switch=""
			fi

		else [[ "${merged_role_mfa_required[$profile_idx]}" == "false" ]]; then
			# no MFA required, do not include MFA Arn in the request,
			# just init the role session

			token_switch=""
			serial_switch=""
		fi

		# generate '--external-id' switch if an exeternal ID has been defined in config
		if [[ "$merged_role_external_id" != "" ]]; then
			external_id_switch="--external-id ${merged_role_external_id[$profile_idx]}"
		else
			external_id_switch=""
		fi

		getMaxSessionDuration role_session_duration "${merged_ident[$profile_idx]}" "role"

#todo: should an in-env only MFA session be taken into account when assuming a role? probably not...

		result=$(aws --profile $role_init_profile sts assume-role \
			$token_switch $serial_switch $external_id_switch \
			--role-arn "${merged_role_arn[$profile_idx]}" \
			--role-session-name "${merged_role_session_name[$profile_idx]}" \
			--duration-seconds $role_session_duration \
			--output $output_type)

		checkAWSErrors "true" "$result" "$role_init_profile" "An error occurred while attempting to acquire the role session credentials; cannot continue!"

	else  # NO SESSION INIT (should never happen; no session request type, or request type is mfasession/rolesession)

		echo -e "${BIRed}${On_Black}\
A $session_request_type cannot request a session (program error).\\n\
Cannot continue.${Color_Off}"

		exit 1
	fi

	# VALIDATE AND FINALIZE SESSION INIT ------------------------------------------------------------------------------
	if [[ "$output_type" == "json" ]]; then

		result_check="$(printf '\n%s\n' "$result" | jq -r .Credentials.AccessKeyId)"

	elif [[ "$output_type" == "text" ]]; then

		# strip extra spaces
		result="$(echo "$result" | xargs echo -n)"

		result_check="$(printf '%s' "$result" | awk '{ print $2 }')"

	fi

	if [[ "$result_check" =~ ^arn:aws:iam:: ]]; then

		if [[ "$output_type" == "json" ]]; then
			AWS_ACCESS_KEY_ID="$(printf '\n%s\n' "$result" | jq -r .Credentials.AccessKeyId)"
			AWS_SECRET_ACCESS_KEY="$(printf '\n%s\n' "$result" | jq -r .Credentials.SecretAccessKey)"
			AWS_SESSION_TOKEN="$(printf '\n%s\n' "$result" | jq -r .Credentials.SessionToken)"
			AWS_SESSION_EXPIRY="$(printf '\n%s\n' "$result" | jq -r .Credentials.Expiration)"

		elif [[ "$output_type" == "text" ]]; then
			read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SESSION_EXPIRY <<< $(printf '%s' "$result" | awk '{ print $2, $4, $5, $3 }')

		fi

		if [[ "$session_request_type" == "baseprofile" ]]; then
			echo -e "${Green}${On_Black}MFA session token acquired.${Color_Off}\\n"
			# passing a global
			AWS_SESSION_PROFILE_IDENT="${merged_ident[$profile_idx]}-mfasession"
	
		elif [[ "$session_request_type" == "role" ]]; then
			echo -e "${Green}${On_Black}Role session token acquired.${Color_Off}\\n"
			# passing a global
			AWS_SESSION_PROFILE_IDENT="${merged_ident[$profile_idx]}-rolesession"

		fi

		AWS_SESSION_TYPE="$session_request_type"

		## DEBUG
		if [[ "$DEBUG" == "true" ]]; then
			echo
			echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
			echo "AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
			echo "AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN"
			echo "AWS_SESSION_EXPIRY: $AWS_SESSION_EXPIRY"
			echo "AWS_SESSION_TYPE: $AWS_SESSION_TYPE"
			echo "AWS_SESSION_PROFILE_IDENT: $AWS_SESSION_PROFILE_IDENT"
		fi
		## END DEBUG

		# update script state
		#   merged_has_session[${merged_role_source_profile_idx[$profile_idx]}] = "true"
		#   merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$profile_idx]}]}] = "valid"
		#   
		#   getMaxSessionDuration this_session_duration "${merged_ident[$idx]}" "mfasession"
		#   getRemaining _ret "mfasession" "${merged_aws_mfasession_init_time[$idx]}" "$this_session_duration"
		#   merged_session_remaining=${_ret}
		#
		#   merged_aws_session_expiry=[data from mfa session init]
		#   merged_aws_access_key_id=[data from mfa session init]
		#   merged_aws_secret_access_key=[data from mfa session init]
		#   merged_aws_session_token=[data from mfa session init]

		eval "$1=$result"

	else

		if [[ "$session_request_type" == "baseprofile" ]]; then
			session_word="An MFA"
		else
			session_word="A role"
		fi

		echo -e "${BIRed}${On_Black}\
$session_word session could not be initialized for the profile '${merged_ident[$profile_idx]}'.\\n\
Cannot continue.${Color_Off}\\n\\n"

		exit 1

	fi

#BEGIN TO BE DELETED-------------------
#EXAMPLES for the calling side: ROLES 
	if [[ "$jq_minimum_version_available" == "true" ]] &&
		[[ "$session_request_type" == "role" ]]; then

		# return json get_session, the below extracts would be done on the calling side

		AWS_ASSUMED_ROLE_ARN="$(printf '\n%s\n' "$result" | jq -r .AssumedRoleUser.Arn)"
		AWS_ACCESS_KEY_ID="$(printf '\n%s\n' "$result" | jq -r .Credentials.AccessKeyId)"
		AWS_SECRET_ACCESS_KEY="$(printf '\n%s\n' "$result" | jq -r .Credentials.SecretAccessKey)"
		AWS_SESSION_TOKEN="$(printf '\n%s\n' "$result" | jq -r .Credentials.SessionToken)"
		AWS_ROLESESSION_EXPIRY="$(printf '\n%s\n' "$result" | jq -r .Credentials.Expiration)"

		echo -e "\\n\
		AWS_ASSUMED_ROLE_ARN: $AWS_ASSUMED_ROLE_ARN\\n\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\n\
		AWS_ROLESESSION_EXPIRY: $AWS_ROLESESSION_EXPIRY\\n\\n"

	elif [[ "$jq_minimum_version_available" == "false" ]] &&
		[[ "$session_request_type" == "role" ]]; then

		read -r AWS_ASSUMED_ROLE_ARN AWS_ACCESS_KEY_ID AWS_ROLESESSION_EXPIRY AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< $(printf '%s' "$result" | awk '{ print $2, $5, $6, $7, $8 }')

		echo -e "\\n\
		AWS_ASSUMED_ROLE_ARN: $AWS_ASSUMED_ROLE_ARN\\n\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\n\
		AWS_ROLESESSION_EXPIRY: $AWS_ROLESESSION_EXPIRY\\n\\n"

	fi

	#example for the calling side: ROLES
	if [[ "$session_request_type" == "role" ]] &&
		[[ "$jq_minimum_version_available" == "true" ]]; then

		# return json get_session, the below extracts would be done on the calling side

		AWS_ASSUMED_ROLE_ARN="$(printf '\n%s\n' "$result" | jq -r .AssumedRoleUser.Arn)"
		AWS_ACCESS_KEY_ID="$(printf '\n%s\n' "$result" | jq -r .Credentials.AccessKeyId)"
		AWS_SECRET_ACCESS_KEY="$(printf '\n%s\n' "$result" | jq -r .Credentials.SecretAccessKey)"
		AWS_SESSION_TOKEN="$(printf '\n%s\n' "$result" | jq -r .Credentials.SessionToken)"
		AWS_ROLESESSION_EXPIRY="$(printf '\n%s\n' "$result" | jq -r .Credentials.Expiration)"

		echo -e "\\n\
		AWS_ASSUMED_ROLE_ARN: $AWS_ASSUMED_ROLE_ARN\\n\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\n\
		AWS_ROLESESSION_EXPIRY: $AWS_ROLESESSION_EXPIRY\\n\\n"

	elif [[ "$session_request_type" == "role" ]] &&
		[[ "$jq_minimum_version_available" == "false" ]]; then
		
		read -r AWS_ASSUMED_ROLE_ARN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_ROLESESSION_EXPIRY <<< $(printf '%s' "$result" | awk '{ print $2, $5, $7, $8, $6 }')

		echo -e "\\n\
		AWS_ASSUMED_ROLE_ARN: $AWS_ASSUMED_ROLE_ARN\\n\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\n\
		AWS_ROLESESSION_EXPIRY: $AWS_ROLESESSION_EXPIRY\\n\\n"

	fi

	#example for the calling side: MFASESSION
	if [[ "$session_request_type" == "mfa" ]] &&
		[[ "$jq_minimum_version_available" == "true" ]]; then

		# return json get_session, the below extracts would be done on the calling side

		AWS_ACCESS_KEY_ID="$(printf '\n%s\n' "$result" | jq -r .Credentials.AccessKeyId)"
		AWS_SECRET_ACCESS_KEY="$(printf '\n%s\n' "$result" | jq -r .Credentials.SecretAccessKey)"
		AWS_SESSION_TOKEN="$(printf '\n%s\n' "$result" | jq -r .Credentials.SessionToken)"
		AWS_SESSION_EXPIRY="$(printf '\n%s\n' "$result" | jq -r .Credentials.Expiration)"

		echo -e "\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\\n\
		AWS_SESSION_EXPIRY: $AWS_SESSION_EXPIRY\\n"

	elif [[ "$session_request_type" == "mfa" ]] &&
		[[ "$jq_minimum_version_available" == "false" ]]; then
		
		read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SESSION_EXPIRY <<< $(printf '%s' "$result" | awk '{ print $2, $4, $5, $3 }')

		echo -e "\\n\
		AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID\\n\\n\
		AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY\\n\\n\
		AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN\\n\\n\
		AWS_SESSION_EXPIRY: $AWS_SESSION_EXPIRY\\n"

	fi
#END TO BE DELETED--------------------


}

## END FUNCTIONS ======================================================================================================

## MAIN ROUTINE START =================================================================================================
## PREREQUISITES CHECK

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

# is AWS CLI installed?
if ! exists aws ; then

	if [[ "$OS" == "macOS" ]]; then

		printf "\\n\
*******************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html\\n\
*******************************************************************************************************************************\\n\\n"

	elif [[ "$OS" == "Linux" ]]; then

		printf "\\n\
**********************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-linux.html\\n\
**********************************************************************************************************************************\\n\\n"

	else

		printf "\\n\
************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/installing.html\\n\
************************************************************************************************************************\\n\\n"

	fi

	exit 1
fi 

# check for the minimum awscli version
aws_version_raw=$(aws --version)
aws_version_string=$(printf '%s' "$aws_version_raw" | awk '{ print $1 }')

[[ "$aws_version_string" =~ ^aws-cli/([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)$ ]] &&
	aws_version_major="${BASH_REMATCH[1]}"
	aws_version_minor="${BASH_REMATCH[2]}"
	aws_version_patch="${BASH_REMATCH[3]}"

if [ "${aws_version_major}" -lt 1 ] ||
	[ "${aws_version_minor}" -lt 15 ] ||
	[ "${aws_version_patch}" -lt 36 ]; then

	echo -e "\\n${BIRed}${On_Black}\
Please upgrade your awscli to the latest version, then try again.${Color_Off}\\n\\n\
To upgrade, run:\\n\
${BIWhite}${On_Black}pip3 install --upgrade awscli${Color_Off}\\n"

	exit 1

else
	echo -e "\\n\
The current awscli version is ${aws_version_major}.${aws_version_minor}.${aws_version_patch} ${BIGreen}${On_Black}✓${Color_Off}\\n"

fi

# check for brew
brew_string="$(brew --version 2>&1 | sed -n 1p)"
[[ "${brew_string}" =~ ^Homebrew ]] &&
	has_brew="true" ||
	has_brew="false"

# check for jq, version
jq_version_string=$(jq --version)
jq_available="false"
jq_minimum_version_available="false"

if [[ "$jq_version_string" =~ ^jq-.*$ ]]; then
	jq_available="true"

	[[ "$jq_version_string" =~ ^jq-([[:digit:]]+)\.([[:digit:]]+)$ ]] &&
		jq_version_major="${BASH_REMATCH[1]}"
		jq_version_minor="${BASH_REMATCH[2]}"

	if [ "${jq_version_major}" -ge 1 ] &&
		[ "${aws_version_minor}" -ge 5 ]; then

		jq_minimum_version_available="true"
	fi
fi

filexit="false"
# check for ~/.aws directory
# if the custom config defs aren't in effect
if [[ "$AWS_CONFIG_FILE" == "" ]] ||
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

	active_config_file="$AWS_CONFIG_FILE"
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

# todo: make sure credfile exists, even if it's blank as long as conffile exists, too
#       the credfile is used to save the session credentials!


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
conffile_props_in_credfile="false"

profile_header_check="false"
access_key_id_check="false"
secret_access_key_check="false"
creds_unsupported_props=""
profile_count=0
session_profile_count=0

if [[ $CREDFILE != "" ]]; then
	while IFS='' read -r line || [[ -n "$line" ]]; do
		[[ "$line" =~ ^\[(.*)\].* ]] &&
			profile_ident="${BASH_REMATCH[1]}"

		if [[ "$profile_ident" != "" ]]; then
			profile_header_check="true"
			(( profile_count++ ))
		fi 

		if [[ "$profile_ident" =~ -mfasession|-rolesession$ ]]; then
			(( session_profile_count++ ))
		fi 

		if [[ "$line" =~ ^[[:space:]]*aws_access_key_id.* ]]; then 
			access_key_id_check="true"
		fi

		if [[ "$line" =~ ^[[:space:]]*aws_secret_access_key.* ]]; then
			secret_access_key_check="true"
		fi

		if	[[ "$line" =~ ^[[:space:]]*(cli_timestamp_format).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(credential_source).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(external_id).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(mfa_serial).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(mfa_arn).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(output).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(sessmax).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(region).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(role_arn).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(ca_bundle).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(source_profile).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(role_session_name).* ]] ||
			[[ "$line" =~ ^[[:space:]]*(parameter_validation).* ]]; then 
	
			this_line_match="${BASH_REMATCH[1]}"			
			creds_unsupported_props="${creds_unsupported_props}      - ${this_line_match}\\n"
			conffile_props_in_credfile="true"
		fi

	done < "$CREDFILE"
fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	ONEPROFILE="true"
fi

if [[ "$conffile_props_in_credfile" == "true" ]]; then
	echo -e "\\n${BIWhite}${On_Black}\
NOTE: The credentials file ($CREDFILE) contains the following properties\\n\
      only supported in the config file ($CONFFILE):\\n\\n\
${creds_unsupported_props}${Color_Off}\\n\
      The credentials file may only contain credentials and session expiration timestamps;\\n\
      please see https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
      and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
      for the details on how to correctly set up the config and shared credentials files."
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
		(( profile_count++ ))
	fi 

	if [[ "$profile_ident" =~ -mfasession|-rolesession$ ]]; then
		(( session_profile_count++ ))
	fi 

	if [[ "$line" =~ ^[[:space:]]*aws_access_key_id.* ]]; then 
		access_key_id_check="true"
	fi

	if [[ "$line" =~ ^[[:space:]]*aws_secret_access_key.* ]]; then
		secret_access_key_check="true"
	fi

done < "$CONFFILE"

if [[ "$profile_count" -eq 0 ]] &&
	[[ "$session_profile_count" -gt 0 ]]; then

	echo
	echo -e "\\n${BIRed}${On_Black}\
THE ONLY CONFIGURED PROFILE WITH CREDENTIALS\\n\
MAY NOT BE A SESSION PROFILE.${Color_Off}\\n\\n\
Please add credentials for at least one base\\n\
profile, and try again.\\n"

	exit 1

fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	ONEPROFILE="true"
fi

if [[ "$ONEPROFILE" == "false" ]]; then
	echo
	echo -e "${BIRed}${On_Black}\
NO CONFIGURED AWS PROFILES WITH CREDENTIALS FOUND.${Color_Off}\\n\
Please make sure you have at least one configured profile\\n\
that has aws_access_key_id and aws_secret_access_key set.\\n\
For more info on how to set them up, see AWS CLI configuration\\n\
documentation at the following URLs:\\n\
https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n"

	exit 1

else

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

	## FUNCTIONAL PREREQS PASSED; PROCEED WITH CUSTOM CONFIGURATION/PROPERTY READ-IN

	DoesValidDefaultExist _ret
	if [[ "$_ret" == "false" ]]; then
		valid_default_exist="false"

		echo -e "${BIWhite}${On_Black}\
NOTE: The default profile is not present.${Color_Off}\\n\
      As a result the default parameters (region, output format)\\n\
      are not available and you need to also either define the\\n\
      profile in the environment (such as, with this script),\\n\
      or select the profile for each awscli command using\\n\
      the '--profile' switch.\\n"

	else
		valid_default_exists="true"
	fi

	# get default region and output format
	# (warn if not defined)
	default_region=$(aws --profile default configure get region)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get region':\\n${ICyan}'${default_region}'${Color_Off}\\n\\n"

	if [[ "$default_region" == "" ]]; then
		echo -e "${BIWhite}${On_Black}\
NOTE: The default region has not been configured.${Color_Off}\\n\
      You may need to use the '--region' switch for some commands\\n\
      if the base/role profile in use doesn't have the region set.\\n\
      You can set the default region in '$CONFFILE',\\n\
      for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set region \"us-east-1\"${Color_Off}\\n
      (NOTE: do NOT use '--profile default' switch when configuring the defaults!)\\n"

	fi

	default_output=$(aws --profile default configure get output)
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get output':\\n${ICyan}'${default_output}'${Color_Off}\\n\\n"

	if [[ "$default_output" == "" ]]; then
		# default output is not set in the config;
		# set the default to the AWS default internally 
		# (so that it's available for the MFA sessions)
		default_output="json"

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}default output for this script was set to: ${ICyan}json${Color_Off}\\n\\n"
		echo -e "\\n\
NOTE: The default output format has not been configured; 'json' format is used.\\n\
      You can modify it, for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set output \"table\"${Color_Off}\\n
      (NOTE: do NOT use '--profile default' switch when configuring the defaults!)\\n"

	fi

	echo

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
	declare -a confs_aws_session_token
	declare -a confs_aws_mfasession_init_time
	declare -a confs_aws_rolesession_expiry
	declare -a confs_sessmax
	declare -a confs_mfa_arn
	declare -a confs_ca_bundle
	declare -a confs_cli_timestamp_format
	declare -a confs_output
	declare -a confs_parameter_validation
	declare -a confs_region
	declare -a confs_role_arn
	declare -a confs_role_credential_source
	declare -a confs_role_external_id
	declare -a confs_role_mfa_serial
	declare -a confs_role_session_name
	declare -a confs_role_source_profile_ident
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

		# aws_session_expiry (should always be blank in the config, but just in case)
		[[ "$line" =~ ^[[:space:]]*aws_session_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_aws_session_expiry[$confs_iterator]=${BASH_REMATCH[1]}

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

		# mfa_arn
		[[ "$line" =~ ^[[:space:]]*mfa_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
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
			confs_role_source_profile_ident[$confs_iterator]=${BASH_REMATCH[1]}

		# (role) external_id
		[[ "$line" =~ ^[[:space:]]*external_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_external_id[$confs_iterator]=${BASH_REMATCH[1]}

		# (role) mfa_serial
		[[ "$line" =~ ^[[:space:]]*mfa_serial[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_mfa_serial[$confs_iterator]=${BASH_REMATCH[1]}

		# role_session_name 
		[[ "$line" =~ ^[[:space:]]*role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_name[$confs_iterator]=${BASH_REMATCH[1]}

	done < "$CONFFILE"

	# UNIFIED ARRAYS (config+credentials)
	declare -a merged_ident  # baseprofile name, *-mfasession, or *-rolesession
	declare -a merged_type  # baseprofile, role, mfasession, rolesession
	declare -a merged_has_session  # true/false (baseprofiles and roles only; not session profiles)
	declare -a merged_aws_access_key_id
	declare -a merged_aws_secret_access_key
	declare -a merged_aws_session_token
	declare -a merged_session_idx  # reference to the related session profile index in this array (from offline augment)
	declare -a merged_sessmax
	declare -a merged_mfa_arn  # baseprofile's configured vMFAd if one exists; like role's sessmax, this is written to config, and re-verified by dynamic augment
	declare -a merged_session_status  # valid/expired/unknown/invalid (session profiles only; valid/expired/unknown based on recorded time in offline, valid/unknown translated to valid/invalid in online augmentation)
	declare -a merged_aws_session_expiry  # both MFA and role session expiration timestamp 
	declare -a merged_session_remaining  # remaining seconds in session; automatically calculated for mfa and role profiles
	declare -a merged_ca_bundle
	declare -a merged_cli_timestamp_format
	declare -a merged_mfa_serial  # role's assigned mfa_serial (derived from its base profile, i.e. from merged_mfa_arn)
	declare -a merged_output
	declare -a merged_parameter_validation
	declare -a merged_region  # precedence: environment, baseprofile (for mfasessions, roles [via source_profile])

	# ROLE ARRAYS
	declare -a merged_role_arn  # this must be provided by the user for a valid role config
	declare -a merged_role_name  # this is discerned/set from the merged_role_arn
	declare -a merged_role_credential_source
	declare -a merged_role_external_id
	declare -a merged_role_mfa_serial  # role's mfa_serial if set, triggers MFA request when the profile is referenced; acquired from the source_profile
	declare -a merged_role_session_name
	declare -a merged_role_source_profile_ident
	declare -a merged_role_source_profile_idx

	# DYNAMIC AUGMENT ARRAYS
	declare -a merged_baseprofile_arn  # based on sts-caller-identity, this can be used as the validity indicator for the baseprofiles (combined with merged_session_status for the select_status)
	declare -a merged_baseprofile_operational_status  # OK/LIMITED/NONE/UNKNOWN based on 'iam get-user' (a 'valid' profile can still be 'limited' or 'none', depending on policy)
	declare -a merged_account_alias
	declare -a merged_account_id
	declare -a merged_username  # username derived from a baseprofile, or role name from a role profile
	declare -a merged_user_arn
	declare -a merged_role_source_username  # username for a role's source profile, derived from the source_profile (if avl)
	declare -a merged_role_mfa_required  # if a role profile has a functional source_profile, this is derived from get-role and query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"'

	# BEGIN CONF/CRED ARRAY MERGING PROCESS
	for ((itr=0; itr<${#confs_ident[@]}; ++itr))
	do
		# import content from confs_ arrays
		merged_ident[$itr]="${confs_ident[$itr]}"
		merged_ca_bundle[$itr]="${confs_ca_bundle[$itr]}"
		merged_cli_timestamp_format[$itr]="${confs_cli_timestamp_format[$itr]}"
		merged_has_session[$itr]="false" # the default value; may be overridden below
		merged_sessmax[$itr]="${confs_sessmax[$itr]}"
		merged_mfa_arn[$itr]="${confs_mfa_arn[$itr]}"
		merged_output[$itr]="${confs_output[$itr]}"
		merged_parameter_validation[$itr]="${confs_parameter_validation[$itr]}"
		merged_region[$itr]="${confs_region[$itr]}"
		merged_role_arn[$itr]="${confs_role_arn[$itr]}"
		merged_role_credential_source[$itr]="${confs_role_credential_source[$itr]}"
		merged_role_external_id[$itr]="${confs_role_external_id[$itr]}"
		merged_role_mfa_serial[$itr]="${confs_role_mfa_serial[$itr]}"
		merged_role_session_name[$itr]="${confs_role_session_name[$itr]}"
		merged_role_source_profile_ident[$itr]="${confs_role_source_profile_ident[$itr]}"

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

		[[ "${creds_aws_session_expiry[$creds_idx]}" != "" ]] &&
			merged_aws_session_expiry[$itr]="${creds_aws_session_expiry[$creds_idx]}" ||
			merged_aws_session_expiry[$itr]="${confs_aws_session_expiry[$itr]}"

		[[ "${creds_type[$itr]}" != "" ]] &&
			merged_type[$itr]="${creds_type[$creds_idx]}" ||
			merged_type[$itr]="${confs_type[$itr]}"

		# since this index in creds_ident has now been merged, remove it from
		# the array so that it won't be duplicated in the leftover merge pass below
		[[ "$creds_idx" != "" ]] && creds_ident[$creds_idx]=""

	done

	# merge in possible credentials-only profiles as they
	# would not have been merged by the above process
	for ((itr=0; itr<${#creds_ident[@]}; ++itr))
	do
		# select creds_ident entries that weren't purged
		if [[ "${creds_ident[$itr]}" != "" ]]; then
			# get the next available index to store the data in 
			merge_idx="${#merged_ident[@]}"

			merged_ident[$merge_idx]="${creds_ident[$itr]}"
			merged_type[$merge_idx]="${creds_type[$itr]}"
			merged_aws_access_key_id[$merge_idx]="${creds_aws_access_key_id[$itr]}"
			merged_aws_secret_access_key[$merge_idx]="${creds_aws_secret_access_key[$itr]}"
			merged_aws_session_token[$merge_idx]="${creds_aws_session_token[$itr]}"
			merged_aws_session_expiry[$merge_idx]="${creds_aws_session_expiry[$itr]}"
		fi			
	done

	# SESSION PROFILES offline augmentation: discern and set merged_has_session,
	# merged_session_idx, and merged_role_source_profile_idx
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
		do

			# add merged_has_session and merged_session_idx properties
			# to make it easier to generate the selection arrays
			if [[ "${merged_ident[$int_idx]}" =~ "${merged_ident[$idx]}-(mfasession|rolesession)$" ]]; then
				merged_has_session[$idx]="true"
				merged_session_idx[$idx]="$int_idx"
			fi

			# add merged_role_source_profile_idx property
			# to easily access a role's source_profile data
			# (this assumes that the role has source_profile
			# set in config; dynamic augment will happen
			# later unless '--quick' is used, and this will
			# be repeated then)
			if [[ "${merged_role_source_profile_ident[$int_idx]}" == "${merged_ident[$idx]}" ]]; then
				merged_role_source_profile_idx[$idx]="$int_idx"
			fi

		done
	done

	# further offline augmentation: persistent profile
	# standardization (relies on merged_role_source_profile_idx
	# assignment, above, having been completed) including
	# region, role_name, and role_session name. 
	# 
	# Also determines/sets merged_session_status
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do

		# BASE PROFILES: Warn if neither the region is set
		# nor is the default region configured
		if [[ "${merged_type[$idx]}" == "baseprofile" ]] &&	# this is a base profile
			[[ "${merged_region[$idx]}" == "" ]] &&			# a region has not been set for this profile
			[[ "$default_region" == "" ]]; then				# and the default is not available

			echo -e "${BIYellow}${On_Black}\
The profile '${merged_ident[$idx]}' does not have a region set,\\n\
and the default region is not available (hence the region is also.\\n\
not available for roles or MFA sessions based off of this profile).${Color_Off}\\n"
		fi

		# ROLE PROFILES: Check if a role has a region set; if not, attempt to 
		# determine it from the source profile. If not possible, and if the 
		# default region has not been set, warn (this is based on the source_profile
		# from config; dynamic augment will happen later unless '--quick' is used, 
		# and if a region becomes available then, it is written into the configuration)
		if [[ "${merged_type[$idx]}" == "role" ]] &&  # this is a role
			[[ "${merged_region[$idx]}" == "" ]] &&   # a region is not set for this role
			[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&  # the source_profile is defined
			[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # and the source_profile has a region set

			merged_region[$idx]="${merged_region[${merged_role_source_profile_idx[$idx]}]}"

			# make the role region persistent
			aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}"

		elif [[ "${merged_type[$idx]}" == "role" ]] &&  # this is a role
			[[ "${merged_region[$idx]}" == "" ]] &&     # a region has not been set for this role

			( ( [[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&				  # (the source_profile has been defined
			[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" == "" ]] ) ||  # .. but it doesn't have a region set
																						  #  OR
			[[ "${merged_role_source_profile_idx[$idx]}" == "" ]] )	&&					  # the source_profile has not been defined)

			[[ "$default_region" == "" ]]; then 		# .. and the default region is not available

			echo -e "${BIYellow}${On_Black}\
The role '${merged_ident[$idx]}' does not have the region set\\n\
and it cannot be determined from its source (it doesn't have one\\n\
set either), and the default doesn't exist.${Color_Off}\\n"
		fi

		# ROLE PROFILES: add an explicit role_session_name to a role to
		# facilitate synchronization of cached role sessions; the same pattern
		# is used as what this script uses to issue for role sessions, 
		# i.e. '{ident}-rolesession'
		if [[ "${merged_type[$idx]}" == "role" ]] &&  				# this is a role
			[[ "${merged_role_session_name[$idx]}" == "" ]]; then	# role_session_name has not been set

			merged_role_session_name[$idx]="${merged_ident[$idx]}-rolesession"

			addConfigProp "$CONFFILE" "${merged_ident[$idx]}" "role_session_name" "${merged_role_session_name[$idx]}" 
		fi

		# ROLE PROFILES: add role_name for easier get-role use
		if [[ "${merged_type[$idx]}" == "role" ]] && 		# this is a role
			[[ "${merged_role_arn[$idx]}" != "" ]]; then 	# and it has an arn (if it doesn't, it's not a valid role profile)

			[[ "${merged_role_arn[$idx]}" =~ ^arn:aws:iam::[[:digit:]]+:role.*/([^/]+)$ ]] &&
				merged_role_name[$idx]="${BASH_REMATCH[1]}"
		fi

		# SESSION PROFILES: set merged_session_status ("expired/valid/unknown")
		# based on the remaining time for the MFA & role sessions
		# (dynamic augment will translate valid/unknown to valid/invalid):
		if [[ "${merged_type[$idx]}" =~ ^mfasession|rolesession$ ]]; then
			
			getRemaining _ret "${merged_aws_session_expiry[$idx]}"
			merged_session_remaining[$idx]="${_ret}"

			case ${_ret} in
				-1)
					merged_session_status[$idx]="unknown"  # timestamp not available, time-based validity status cannot be determined
					;;
				0)
					merged_session_status[$idx]="expired"  # note: this includes the time slack
					;;
				*)
					merged_session_status[$idx]="valid"
					;;
			esac

		else
			# base & role profiles
			merged_session_status[$idx]=""
		fi

	done

#todo: remove the variable def here; must be an arg
quick_mode="false"

	if [[ "$quick_mode" == "false" ]]; then
		dynamicAugment
	else
		echo -e "${BIYellow}${On_Black}Quick mode selected; skipping the dynamic data augmentation.${Color_Off}\\n"
	fi

	# make sure environment has either no config
	# or a functional config before we proceed
	checkEnvSession

	declare -a select_ident  # imported merged_ident
	declare -a select_type  # baseprofile or role
	declare -a select_status  # merged profile status (baseprofiles: operational status if known; role profiles: has a defined, operational source profile if known)
	declare -a select_merged_idx  # idx in the merged array (the key to the other info)
	declare -a select_has_session  # baseprofile or role has a session profile (active/valid or not)
	declare -a select_merged_session_idx  # index of the associated session profile

	# Create the select arrays; first add the baseprofiles, then the roles;
	# on each iteration the merge arrays are looped through for
	# an associated session; sessions are related even when they're
	# expired (but session's status indicates whether the session
	# is active or not -- expired sessions are not displayed)
	select_idx=0
	baseprofile_count=0
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"
			select_type[$select_idx]="baseprofile"
			(( baseprofile_count++ ))
			
			if [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" != "" ]]; then

				# not quick mode; sts get-caller-identity had checked out ok for the base profile
				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" == "" ]]; then

				# not quick mode; sts get-caller-identity had not worked on the base profile
				select_status[$select_idx]="invalid"

			else
				# quick mode is active; base profile validity cannot be confirmed
				select_status[$select_idx]="unknown"

			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"
			(( select_idx++ ))
		fi
	done

	# NOTE: select_idx is intentionally not reset
	#       before continuing below
	role_count=0
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "role" ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"
			select_type[$select_idx]="role"
			(( role_count++ ))

			if [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&
				[[ "${merged_baseprofile_arn[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then
				
				# not quick mode, role's source_profile is defined and valid
				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&
				[[ "${merged_baseprofile_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="invalid_source"

			elif [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then

				# not quick mode, role's source_profile not defined
				select_status[$select_idx]="invalid_nosource"

			else
				# quick_mode is active (plus any unlikely catch-all cases)
				select_status[$select_idx]="unknown"

			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"

			(( select_idx++ ))
		fi
	done

	# DISPLAY THE PROFILE SELECT MENU, MAKE THE SELECTION -------------------------------------------------------------
	mfa_req="false"

	# displays a single profile + a possible associated persistent MFA session
	if [[ "${baseprofile_count}" -eq 0 ]]; then  # no baseprofiles found; bailing out									#1 - NO BASEPROFILES

		echo -e "${BIRed}${On_Black}No base profiles found. Cannot continue.${Color_Off}\\n\\n"

		exit 1

	elif [[ "${baseprofile_count}" -eq 1 ]] &&  # only one baseprofile is present (it may or may not have a session)..	#2 - ONE BASEPROFILE ONLY (W/WO SESSION)
		[[ "${role_count}" -eq 0 ]]; then  # .. and no roles; use the simplified menu
		
		echo

		# 'valid' is by definition 'not quick' (but it can still be 'limited' if MFA is required);
		# we know that index 0 must be the sole baseprofile because: 1) here there is only one baseprofile,
		# 2) the baseprofile was added to the selection arrays before any roles, and 3) MFA sessions
		# are not included in the selection arrays
		if [[ "${select_status[0]}" == "valid" ]]; then

			if [[ "${merged_account_alias[${select_merged_idx[0]}]}" != "" ]]; then  # AWS account alias available
				pr_accn=" @${merged_account_alias[${select_merged_idx[0]}]}"

			elif [[ "${merged_account_id[${select_merged_idx[0]}]}" != "" ]]; then   # AWS account alias does not exist/is not available; use the account number
				pr_accn=" @${merged_account_id[${select_merged_idx[0]}]}"

			else
				# something's wrong (should not happen with a valid account), but just in case..
				pr_accn="[unavailable]"

			fi

			echo -e "${Green}${On_Black}You have one configured profile: ${BIGreen}${select_ident[0]} (IAM: ${merged_username[${select_merged_idx[0]}]}${pr_accn})${Green}${Color_Off}"

			if [[ "${merged_mfa_arn[${select_merged_idx[0]}]}" != "" ]]; then
				echo ".. its vMFAd is enabled"

				if [[ "${select_has_session[0]}" != "true" ]] &&
					[[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]]; then

					getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[0]}]}"

					echo -e ".. and it ${BIWhite}${On_Black}has an active MFA session (with ${pr_remaining} of the validity period remaining)${Color_Off}"

				else
					echo -e ".. but no active persistent MFA sessions exist"

				fi

			else  # no vMFAd configured
				echo -e "\
.. but it doesn't have a virtual MFA device attached/enabled\\n\
(use the 'enable-disable-vmfa-device.sh' script to enable a vMFAd).\\n\\n\
Without a vMFAd the listed base profile can only be used as-is.\\n"

			fi

		elif [[ "${select_status[0]}" == "unknown" ]]; then  # status 'unknown' is by definition 'quick'

			echo -e "${BIWhite}${On_Black}** NOTE: Quick mode in effect; account/session status cannot be verified.${Color_Off}\\n\\n"

			echo -e "${Green}${On_Black}You have one configured profile: ${BIGreen}${select_ident[0]}${Green}${Color_Off}"

			if [[ "${select_has_session[0]}" != "true" ]] &&
				[[ "${merged_session_status[${select_merged_session_idx[0]}]}" != "expired" ]]; then  # since this is quick, the status can be 'valid' or 'unknown'

				if [[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]]; then 
					getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[0]}]}"

					echo -e ".. and it ${BIWhite}${On_Black}has an active MFA session (with ${pr_remaining} of the validity period remaining)${Color_Off}"

				else  # no expiry timestamp for some reason

					echo -e ".. and it ${BIWhite}${On_Black}has an MFA session (the validity status could not be determined)${Color_Off}"

				fi

			else

				echo -e ".. but no active persistent MFA sessions exist"

			fi

		else  # no base profiles in 'valid' (not quick) or 'unknown' (quick) status; bailing out

			echo -e "${BIRed}${On_Black}No valid base profiles found; please check your configuration files.\\nCannot continue.${Color_Off}\\n\\n"

			exit 1

		fi

		echo -e "\\nDo you want to:"
		echo -e "${BIWhite}${On_Black}U${Color_Off}: Use the above profile as-is (without an MFA session)?"

		single_select_start_mfa="disallow"
		if ( [[ "${select_status[0]}" == "valid" ]] &&  # not quick, profile validated..
			[[ "${merged_mfa_arn[${select_merged_idx[0]}]}" != "" ]] ) ||  # .. and it has a vMFAd configured
			[[ "${quick_mode}" == "true" ]]; then  # or the quick mode is on (in which case the status is unknown and we assume the user knows what they're doing)

			echo -e "${BIWhite}${On_Black}S${Color_Off}: Start/renew an MFA session for the profile mentioned above?"
			single_select_start_mfa="allow"
		fi

		single_select_resume="disallow"
		if ( [[ "${select_status[0]}" == "valid" ]] &&  # not quick, profile validated..
			[[ "${select_has_session[0]}" == "true" ]] &&  # .. and it has an MFA session..
			[[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]] ) ||  # .. which is valid

			( [[ "${quick_mode}" == "true" ]] &&  # or the quick mode is on (in which case the status is unknown and we assume the user knows what they're doing)
			[[ "${select_has_session[0]}" == "true" ]] &&  # .. an MFA session exists..
			[[ "${merged_session_status[${select_merged_session_idx[0]}]}" =~ ^valid|unknown$ ]] ); then  # and it's ok by timestamp or the timestamp doesn't exist

			echo -e "${BIWhite}${On_Black}R${Color_Off}: Resume the existing active MFA session (${baseprofile_mfa_status[0]})?"
			echo

			single_select_resume="allow"
		fi

		# single profile selector
		while :
		do	
			read -s -n 1 -r
			case $REPLY in
				U)
					echo "Using the base profile as-is (no MFA).."
					selprofile="1"
#todo: how does the bypass the mfa code req?
					break
					;;
				S)
					if [[ ${single_select_start_mfa} == "allow" ]]; then  
						echo "Starting an MFA session.."
						selprofile="1"
						mfa_req="true"
						break
					else
						echo -e "${BIRed}${On_Black}Please select one of the options above!${Color_Off}"
					fi
					;;
				R)
					if [[ "${single_select_resume}" == "allow" ]]; then
						echo "Resuming the existing MFA session.."
						selprofile="1s"
						break
					else 
						echo -e "${BIRed}${On_Black}Please select one of the options above!${Color_Off}"
					fi
					;;
				*)
					echo -e "${BIRed}${On_Black}Please select one of the options above!${Color_Off}"
					;;
			esac
		done

	# this is different from the above as roles are only allowed with at least one baseprofile
	elif [[ "${baseprofile_count}" -gt 1 ]] ||   # more than one baseprofile is present..								#3 - 1+ BASEPROFILES (W/WO SESSION), 1+ ROLES
												 # -or-
		( [[ "${baseprofile_count}" -ge 1 ]] &&  # one or more baseprofiles are present
		[[ "${role_count}" -ge 1 ]] ); then      # .. AND one or more session profiles are present

		if [[ "$quick_mode" == "false" ]]; then
			echo -e "${BIWhite}${On_Black}\\n** NOTE: Quick mode in effect; dynamic information is not available.${Color_Off}\\n\\n"
		fi

		# create the base profile selections
		echo
		echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS PROFILES: ${Color_Off}"
		echo

		for ((idx=0; idx<${#select_ident[@]}; ++idx))
		do

			if [[ "${select_type[$idx]}" == "baseprofile" ]] &&
				[[ "${select_status[$idx]}" =~ "valid|unknown" ]]; then

				# make a more-human-friendly selector digit (starts from 1)
				(( selval=idx+1 ))

				if [[ "$quick_mode" == "false" ]]; then

					# IAM username available (a dynamic augment data point)?
					if [[ "${merged_username[${select_merged_idx[$idx]}]}" != "" ]]; then 
						pr_user="${merged_username[${select_merged_idx[$idx]}]}"
					else
						pr_user="unknown — a bad profile?"
					fi

					# account alias available (a dynamic augment data point)?
					if [[ "${merged_account_alias[${select_merged_idx[$idx]}]}" != "" ]]; then
						pr_accn=" @${merged_account_alias[${select_merged_idx[$idx]}]}"
					elif [[ "${merged_account_id[${select_merged_idx[$idx]}]}" != "" ]]; then
						# use the AWS account number if no alias has been defined
						pr_accn=" @${merged_account_id[${select_merged_idx[$idx]}]}"
					else
						# or nothing (for a bad profile)
						pr_accn=""
					fi

					# vMFAd configured (a dynamic augment data point)?
					if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" != "" ]]; then
						mfa_notify="; ${Green}${On_Black}vMFAd configured/enabled${Color_Off}"
					else
						mfa_notify="; vMFAd not configured" 
					fi

					# print the baseprofile
					echo -en "${BIWhite}${On_Black}${selval}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify})\\n"

					# print an associated session if exist and is valid
					if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" == "valid" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_has_session_idx[$idx]}]}"

						echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} MFA session${Color_Off} (${pr_remaining} of the validity period remaining)"
					fi

					echo

				else  # quick_mode is active; print abbreviated data

					# print the baseprofile
					echo -en "${BIWhite}${On_Black}${selval}: ${select_ident[$idx]}${Color_Off}\\n"

					# print an associated session if exist and not expired (i.e. 'valid' or 'unknown')
					if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" != "expired" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_has_session_idx[$idx]}]}"

						echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} MFA session${Color_Off} (${pr_remaining} of the validity period remaining)"
					fi

					echo

				fi

			elif [[ "${select_type[$idx]}" == "baseprofile" ]] &&
				[[ "${select_status[$idx]}" =~ "invalid" ]]; then

				# print the invalid baseprofile for 'FYI'
				echo -e "INVALID: ${select_ident[$idx]}"

			fi
		done

		if [[ "${role_count}" -gt 0 ]]; then
			# create the role profile selections
			echo
			echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS ROLES: ${Color_Off}"
			echo

			for ((idx=0; idx<${#select_ident[@]}; ++idx))
			do

				if [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" =~ "valid|unknown" ]]; then

					# make a more-human-friendly selector digit (starts from 1)
					(( selval=idx+1 ))

					if [[ "$quick_mode" == "false" ]]; then

#todo: does this show the role's username or the baseprofile's username?
#      if the former, should the baseprofile's username be displayed also?

						if [[ "${merged_username[${select_merged_idx[$idx]}]}" != "" ]]; then 
							pr_user="${merged_username[${select_merged_idx[$idx]}]}"
						else
							pr_user="unknown — a bad role?"
						fi

						if [[ "${merged_account_alias[${select_merged_idx[$idx]}]}" != "" ]]; then
							pr_accn=" @${merged_account_alias[${select_merged_idx[$idx]}]}"
						elif [[ "${merged_account_id[${select_merged_idx[$idx]}]}" != "" ]]; then
							# use the AWS account number if no alias has been defined
							pr_accn=" @${merged_account_id[${select_merged_idx[$idx]}]}"
						else
							# or nothing for a bad profile
							pr_accn=""
						fi

						if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" != "" ]]; then
							mfa_notify="; ${Green}${On_Black}vMFAd configured/enabled${Color_Off}"
						else
							mfa_notify="; vMFAd not configured" 
						fi

						# print the role
						echo -en "${BIWhite}${On_Black}${selval}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify})\\n"

						# print the associated role session
						if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" == "valid" ]]; then
							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_has_session_idx[$idx]}]}"
		
							echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} role session${Color_Off} (${pr_remaining} of the validity period remaining)"
						fi

					else  # quick_mode is active; print abbreviated data

						# print the role
						echo -en "${BIWhite}${On_Black}${selval}: ${select_ident[$idx]}${Color_Off}\\n"

						# print the associated role session
						if [[ "${merged_session_status[${select_has_session_idx[$idx]}]}" != "expired" ]]; then
							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_has_session_idx[$idx]}]}"
		
							echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} role session${Color_Off} (${pr_remaining} of the validity period remaining)"
						fi

					fi

					echo

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" =~ "invalid_source" ]]; then

					# print the invalid role profile for 'FYI'
					echo -e "INVALID: ${select_ident[$idx]} (configured source profile is non-functional)"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" =~ "invalid_nosource" ]]; then

					# print the invalid role profile for 'FYI'
					echo -e "INVALID: ${select_ident[$idx]} (source profile not defined for the role)"

				fi

			done
		fi

#todo: remove these maybe (can be replaced with final_selection_idx lookups)
		# this is used to determine whether to trigger a MFA request for a MFA profile
#		active_mfa="false"

		# this is used to determine whether to print MFA questions/details
#		mfaprofile="false"

		if [[ "$quick_mode" == "false" ]]; then
			echo -e "\
You can switch to a base profile to use it as-is, start an MFA session for\\n\
a base profile if it is marked as \"vMFAd enabled\", or switch to an existing\\n\
active MFA or role session if any are available (indicated by the letter 's' after\\n\
the profile ID, e.g. '1s'; NOTE: the expired MFA and role sessions are not shown).\\n"

		else
			echo -e "\
You can switch to a base profile to use it as-is, start an MFA session for\\n\
a base profile if it has a vMFAd configured/enabled, or switch to an existing\\n\
active MFA or role session if any are available (indicated by the letter 's' after\\n\
the profile ID, e.g. '1s'; NOTE: the expired MFA and role sessions are not shown).\\n"

		fi

		# prompt for profile selection
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE ID:${Color_Off} "
		read -r selprofile
		echo -en  "\\n"

	fi  # end profile selections

	(( maxprofiles=baseprofile_count+role_count ))


	# PROCESS THE SELECTION -------------------------------------------------------------------------------------------

	if [[ "$selprofile" != "" ]]; then

		# check for a valid selection pattern
		if ! [[ "$selprofile" =~ ^[[:digit:]]+$ &&
			"$selprofile" =~ ^[[:digit:]]+s$ ]]; then 

			# non-acceptable characters were present in the selection -> exit
			echo -e "${BIRed}\
There is no profile '${selprofile}'.${Color_Off}\\n\
You may select the base and role profiles by the corresponding digit(s),\\n\
and the MFA or role session (if any exist) by the corresponding digit(s)\\n\
followed immediately by the letter 's'."

			exit 1
		fi

		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_selval="${BASH_REMATCH[1]}"
		
		if [[ "$selprofile_selval" != "" ]]; then
			# if the numeric selection was found, 
			# translate it to the array index and validate
			(( selprofile_idx=selprofile_selval-1 ))

			# does the selected profile exist? (this is baseprofile/roleprofile check);
			# the +1 selval is used instead of idx because maxprofiles is the sum of profile counts
			if [[ $selprofile_selval -gt $maxprofiles ||
				$selprofile_idx -lt 0 ]]; then

				# a selection outside of the existing range was specified -> exit
				echo -e "There is no profile '${selprofile_selval}'. Cannot continue.\\n"
				exit 1
			fi

			# was an existing and valid session profile selected?
			[[ $selprofile =~ ^[[:digit:]]+(s)$ ]] &&
				selprofile_session_check="${BASH_REMATCH[1]}"

			if [[ "$selprofile_session_check" != "" ]] &&
				[[ "${select_has_session[$selprofile_idx]}" == "true" ]] &&
				# For this to be a valid session profile, it must be
				# in 'valid' (not quick) or 'unknown' (quick) status
				[[ "${merged_session_status[${select_merged_session_idx[$selprofile_idx]}]}" =~ "valid|unknown" ]]; then
				
				# A SESSION PROFILE WAS SELECTED <<<<<<<========================

				# get the session profile's index and ident (the selection digit is that of the base/role profile
				# while 's' is just an indicator for the session but it has no intrinsic profile reference)
				final_selection_idx="${select_merged_session_idx[$selprofile_idx]}"
				final_selection_ident="${merged_ident[$final_selection_idx]}"

				if [[ "$select_type" == "baseprofile" ]]; then  # select_type is 'baseprofile' or 'role' because selection menus don't have session details internally

					final_selection_type="mfasession"
					echo -e "SELECTED MFA SESSION PROFILE: ${final_selection_ident} (for the base profile \"${select_ident[$selprofile_idx]}\")"

				elif [[ "$select_type" == "role" ]]; then

					final_selection_type="rolesession"
					echo -e "SELECTED ROLE SESSION PROFILE: ${final_selection_ident} (for the role profile \"${select_ident[$selprofile_idx]}\")"

				fi

## Delete these maybe? (can be replaced with final_selection_idx lookups)
				# this is used to determine whether to print MFA questions/details
#				mfaprofile="true"

				# this is used to determine whether to trigger a MFA request for a MFA profile
#				active_mfa="true"

			elif [[ "$selprofile_session_check" != "" ]] &&
				[[ "${select_has_session[$selprofile_idx]}" == "false" ]]; then
				# a session profile ('s') was selected for a base/role profile that has no session -> exit
				
				echo -e "${BIRed}${On_Black}
There is no profile '${selprofile}'.${Color_Off}\\n
(Profile '$selprofile_selval' has no session.)\\n"

				exit 1

			elif [[ "$selprofile_session_check" == "" ]] &&
				[[ "${select_type[$selprofile_idx]}" == "baseprofile" ]]; then
				
				# A BASE PROFILE WAS SELECTED <<<<<<<===========================

				final_selection_idx="${select_merged_idx[$selprofile_idx]}"
				final_selection_ident="${select_ident[$selprofile_idx]}"
				final_selection_type="baseprofile"

				echo "SELECTED BASE PROFILE: $final_selection_ident"

			elif [[ "$selprofile_session_check" == "" ]] &&
				[[ "${select_type[$selprofile_idx]}" == "role" ]]; then
				
				# A ROLE PROFILE WAS SELECTED <<<<<<<===========================

				final_selection_idx="${select_merged_idx[$selprofile_idx]}"
				final_selection_ident="${select_ident[$selprofile_idx]}"
				final_selection_type="roleprofile"
				echo "SELECTED ROLE PROFILE: $final_selection_ident"

			fi
		else
			# no numeric part in selection -> exit
			echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n"
			exit 1
		fi
	else
		# empty selection -> exit
		echo -e "${BIRed}${On_Black}You didn't select any profile.${Color_Off}\\n"
		exit 1
	fi

	# ACQUIRE SESSIONS ------------------------------------------------------------------------------------------------

	# this is an MFA request (an vMFAd ARN exists but the MFA is not active; 
	# all baseprofile selections from the multi-menu are considered MFA requests
	# (user has the option to hit enter at the MFA code prompt to opt to use the
	# baseprofile as-is), while from the simplified single-profile menu the MFA
	# session request is explicit.

#todo: WTF?! ROLE SUPPORT IS MISSING FROM HERE ALTOGETHER!!

#todo: NOTE: mfa_req=false may flow through here unless it's shortcut earlier to use the profile as-is

	if [[ "${merged_mfa_arn[$final_selection_idx]}" != "" ]] &&  # quick_mode off: merged_mfa_arn comes from dynamicAugment; quick_mode on: merged_mfa_arn comes from confs_mfa_arn (if avl)

		( [[ "$final_selection_type" == "baseprofile" ]] ||
			[[ "$mfa_req" == "true" ]] ); then  # 'mfa_req' is an explicit single base profile MFA request

		# BASEPROFILE MFA REQUEST

		AWS_BASE_PROFILE_IDENT="$final_selection_ident"
		echo -e "\\nAcquiring an MFA session token for the profile: ${BIWhite}${On_Black}${AWS_BASE_PROFILE_IDENT}${Color_Off}..."

#todo: if role side allows it, the requesting profile idx could be provided instead

		# acquire MFA session
		acquireSession mfaSessionData "$AWS_BASE_PROFILE_IDENT"

		# Add the '-mfasession' suffix to final_selection_ident,
		# as it's not there yet since the session was just created.
		# This is a global updated in acquireSession
		final_selection_ident="$AWS_SESSION_PROFILE_IDENT"

#todo: do we unpack mfaSessionData, or do we rely on the global transits?

	elif [[ "$quick_mode" == "true" ]] &&  # quick mode is active..
		[[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&  # .. and there was no vMFAd ARN in the conf -- could be new or not [yet] persisted; notify and exit
		
		( [[ "$final_selection_type" == "baseprofile" ]] ||
			[[ "$mfa_req" == "true" ]] ); then

		echo -e "\\n${BIRed}${On_Black}\
A vMFAd was not found for this profile in the quick mode!${Color_Off}\\n\
It is possible that the vMFAd has not been persisted yet; please run\\n\
this script first without the '--quick/-q' switch to confirm.\\n\
If a vMFAd is still unavailable, run 'enable-disable-vmfa-device.sh'\\n\
script to configure and enable the vMFAd for this profile, then try again.\\n"

		exit 1

	elif [[ "$quick_mode" == "false" ]] &&  # quick_mode is inactive..
		[[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&  # .. and no vMFAd is configured (no dynamically acquired vMFAd ARN); print a notice and exit

		( [[ "$final_selection_type" == "baseprofile" ]] ||
			[[ "$mfa_req" == "true" ]] ); then

#todo: is this needed ˅˅˅ ?
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		echo -e "\\n${BIRed}${On_Black}\
A vMFAd has not been configured/enabled for this profile!${Color_Off}\\n\
Run 'enable-disable-vmfa-device.sh' script to configure and\\n\
enable the vMFAd for this profile, then try again.\\n"

		exit 1

	elif [[ "$final_selection_type" == "role" ]]; then
#todo: additional checks are probably needed.. does quick affect this?

		AWS_ROLE_PROFILE_IDENT="$final_selection_ident"
		echo -e "\\nAcquiring a role session token for the profile: ${BIWhite}${On_Black}${AWS_ROLE_PROFILE_IDENT}${Color_Off}..."

		acquireSession roleSessionData "$AWS_ROLE_PROFILE_IDENT"

		# Add the '-rolesession' suffix to final_selection_ident,
		# as it's not there yet since the session was just created.
		# This is a global updated in acquireSession
		final_selection_ident="$AWS_SESSION_PROFILE_IDENT"

	fi

#----BEGIN DELETE

	# INITIALIZE A MFA SESSION (request an MFA session token) ---------------------------------------------------------
	if [[ "$mfacode" != "" ]]; then  # mfacode is only set for the baseprofile selections

# todo: this must be converted into "persistSession" function

			# export the selection to the remaining subshell commands in this script
			# so that "--profile" selection is not required, and in fact should not
			# be used for setting the credentials (or else they go to the conffile)
			export AWS_PROFILE=${AWS_MFA_PROFILE}
			# Make sure the final selection profile name has '-mfasession' suffix
			# (before this assignment it's not present when going from a base profile to an MFA profile)
			final_selection_ident="$AWS_MFA_PROFILE"

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

				writeSessionExpTime "${AWS_MFA_PROFILE}" "mfa"
			fi

		fi

	elif [[ "$active_mfa" == "false" ]]; then
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"
	fi

#----END DELETE

	# export final selection to the environment
	# (no change for the initialized MFA sessions)
	export AWS_PROFILE="$final_selection_ident"

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
		if [[ "${baseprofile_region[$selprofile_idx]}" != "" &&
			  "${mfaprofile}" == "true" ]]; then
			set_new_region=${baseprofile_region[$selprofile_idx]}
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
		if [[ "${baseprofile_output[$selprofile_idx]}" != "" &&
			"${mfaprofile}" == "true" ]]; then
			set_new_output=${baseprofile_output[$selprofile_idx]}
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

			getSessionExpiry _ret "${final_selection}"
			AWS_SESSION_EXPIRY=${_ret}
			AWS_SESSION_TYPE=MUST_ADD_TYPE_HERE
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
		echo -e "${BIWhite}${On_Black}\
*** THIS IS A NON-PERSISTENT MFA SESSION!${Color_Off} THE MFA SESSION ACCESS KEY ID,\\n
    SECRET ACCESS KEY, AND THE SESSION TOKEN ARE *ONLY* SHOWN BELOW!"
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
			envvar_config="unset AWS_PROFILE; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE; unset AWS_SESSION_EXPIRY; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}" 
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
			envvar_config="export AWS_PROFILE=\"${final_selection}\"; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE; unset AWS_SESSION_EXPIRY; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT${envvar_config_clear_custom_config}"
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
			echo "unset AWS_SESSION_TYPE"
			echo "unset AWS_SESSION_EXPIRY"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\""
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\""
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_TYPE=${AWS_SESSION_TYPE}"
				echo "export AWS_SESSION_EXPIRY=${AWS_SESSION_EXPIRY}"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; export AWS_SESSION_TYPE=${AWS_SESSION_TYPE}; export AWS_SESSION_EXPIRY=${AWS_SESSION_EXPIRY}; export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"${envvar_config_clear_custom_config}"

				if [[ "$OS" == "macOS" ]]; then
					echo -n "$envvar_config" | pbcopy
				elif [[ "$OS" == "Linux" ]] &&
					exists xclip; then

					echo -n "$envvar_config" | xclip -i
					xclip -o | xclip -sel clip
				fi
			else
				echo "unset AWS_SESSION_TYPE"
				echo "unset AWS_SESSION_EXPIRY"
				echo "unset AWS_SESSION_TOKEN"

				envvar_config="export AWS_PROFILE=\"${final_selection}\"; export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}; export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}; unset AWS_SESSION_TYPE; unset AWS_SESSION_EXPIRY; unset AWS_SESSION_TOKEN${envvar_config_clear_custom_config}"

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
			echo "unset AWS_SESSION_TYPE \\"
			echo "unset AWS_SESSION_EXPIRY \\"
			echo "unset AWS_SESSION_TOKEN"
		else
			echo "export AWS_PROFILE=\"${final_selection}\" \\"
			echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\" \\"
			echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\" \\"
			echo "export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \\"
			echo "export AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT} \\"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_TYPE=${AWS_SESSION_TYPE} \\"
				echo "export AWS_SESSION_EXPIRY=${AWS_SESSION_EXPIRY} \\"
				echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""
			else
				echo "unset AWS_SESSION_TYPE \\"
				echo "unset AWS_SESSION_EXPIRY \\"
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
