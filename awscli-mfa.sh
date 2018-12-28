#!/usr/bin/env bash
#!/bin/bash
#todo: ^delete 

# todo: handle root account max session time @3600 & warn if present
# todo: handle secondary role max session time @3600 & warn
# todo: arg parsing, help
# todo: "--quick" switch which forgoes the aws queries before
#       the presentation
# todo: output command prefix format
# todo: display effective session and method by which it is effective, i.e.
#       - none; no [default], nothing selected
#       - [default] profile in credentials/config
#       - selected profile via evvar AWS_SESSION
#       - in-env profile
#       
#       + config files in use

# NOTE: Debugging mode prints the secrets on the screen!
DEBUG="false"

#todo: remove the variable def here; must be an arg
quick_mode="true"

# enable debugging with '-d' or '--debug' command line argument..
[[ "$1" == "-d" || "$1" == "--debug" ]] && DEBUG="true"
# .. or by uncommenting the line below:
#DEBUG="true"

# Set the global MFA session length in seconds below; note that this
# only sets the client-side duration for the MFA session token! 
# The maximum length of a valid session is enforced by the IAM policy,
# and is unaffected by this value (if this duration is set to a longer
# value than the enforcing value in the IAM policy, the token will
# stop working before it expires on the client side). Matching this
# value with the enforcing IAM policy provides you with accurate detail 
# about how long a token will continue to be valid.
# 
# THIS VALUE CAN BE OPTIONALLY OVERRIDDEN PER EACH BASE PROFILE
# BY ADDING A "sessmax" ENTRY FOR A BASE PROFILE IN ~/.aws/config
#
# The AWS-side IAM policy may be set to session lengths between 
# 900 seconds (15 minutes) and 129600 seconds (36 hours);
# the example value below is set to 32400 seconds, or 9 hours.
MFA_SESSION_LENGTH_IN_SECONDS=32400

# Set the global ROLE session length in seconds below; this value
# is used when the enforcing IAM policy disallows retrieval of 
# the maximum role session length. The attached example MFA 
# enforcement policy (example-MFA-enforcement-policy.txt) allows
# this, and where a derivative of this enforcement policy is used,
# the below value should not need to be altered. With a correctly
# configured enforcement policy (i.e. following the example policy)
# this value is dynamically overridden when a specific session 
# maxtime is defined for a particular role.
# 
# The default role session length set by AWS for CLI access is 
# 3600 seconds, or 1 hour. This length can be altered by an IAM
# policy to range from 900 seconds (15 minutes) to 129600 seconds
# (36 hours).
#  
# Note that just like the maximum session length for the MFA sessions
# set above, this value only sets the client-side maximum duration 
# for the role session token! Changing this value does not affect
# the session length enforced by the policy, and in fact, if this 
# duration is set to a longer value than the enforcing value in
# the IAM policy (or the default 3600 seconds if no maxtime has
# been explicitly set in the policy), the role session token
# request WILL FAIL.
# 
# Furthermore, this value can also be optionally overridden per
# each role profile by adding a "sessmax" entry for a role in
# ~/.aws/config (this can be useful in situations where the maximum
# session length isn't available from AWS, such as when assuming
# a role at a third party AWS account whose policy disallows
# access to this information).
ROLE_SESSION_LENGTH_IN_SECONDS=3600

# Define the standard locations for the AWS credentials and
# config files; these can be statically overridden with 
# AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE envvars
# (this script will override these envvars only if the 			<<<FLAG 🚩
# "[default]" profile in the defined custom file(s) is
# defunct, thus reverting to the below default locations).
CONFFILE=~/.aws/config
CREDFILE=~/.aws/credentials

# The minimum time required (in seconds) remaining in
# an MFA or a role session for it to be considered valid
VALID_SESSION_TIME_SLACK=300

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
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function exists] command: ${1}${Color_Off}"
	command -v "$1" >/dev/null 2>&1
}

# prompt for a selection: 'yes' or 'no'
yesNo() {
	# $1 is yesNo_result
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function yesNo]${Color_Off}"

	local yesNo_result
	local old_stty_cfg

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	yesNo_result="$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )"
	stty "$old_stty_cfg"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: yesNo_result: ${yesNo_result}${Color_Off}"

	if echo "$yesNo_result" | grep -iq "^n" ; then
		yesNo_result="no"
	else
		yesNo_result="yes"
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${yesNo_result}${Color_Off}"

	eval "$1=\"${yesNo_result}\""
}

# prompt for a selection: '1' or '2'
oneOrTwo() {
	# $1 is oneOrTwo_result
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function oneOrTwo]${Color_Off}"

	local oneOrTwo_result
	local old_stty_cfg

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	oneOrTwo_result="$( while ! head -c 1 | grep -i '[12]' ;do true ;done )"
	stty "$old_stty_cfg"

	if echo "$oneOrTwo_result" | grep -iq "^1" ; then
		oneOrTwo_result="1"
	else
		oneOrTwo_result="2"
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: oneOrTwo_result: ${oneOrTwo_result}${Color_Off}"

	eval "$1=\"${oneOrTwo_result}\""
}

# precheck envvars for existing/stale session definitions
env_aws_status="unknown"  # unknown until status is actually known, even if it is 'none'
env_aws_type=""
checkInEnvCredentials() {

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function checkInEnvCredentials]${Color_Off}"

	local _ret
	local this_time="$(date "+%s")"
	local profiles_idx
	local parent_duration
	local this_assumed_role_name
	local this_session_type
	local this_session_expired="unknown"	# marker for AWS_SESSION_EXPIRY ('unknown' remains only if absent or corrupt)
	local active_env="false"				# any AWS_ envvars present in the environment
	local env_selector_present="false"		# AWS_PROFILE present?
	local env_secrets_present="false"		# are [any] in-env secrets present?
	local active_env_session="false"		# an apparent AWS session (mfa or role) present in the env (a token is present)

	# COLLECT THE AWS_ ENVVAR DATA

	ENV_AWS_PROFILE="$(env | grep AWS_PROFILE)"
	if [[ "$ENV_AWS_PROFILE" =~ ^AWS_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_PROFILE="${BASH_REMATCH[1]}"
		active_env="true"
		env_selector_present="true"
	fi

	ENV_AWS_PROFILE_IDENT="$(env | grep AWS_PROFILE_IDENT)"
	if [[ "$ENV_AWS_PROFILE_IDENT" =~ ^AWS_PROFILE_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_PROFILE_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_SESSION_IDENT="$(env | grep AWS_SESSION_IDENT)"
	if [[ "$ENV_AWS_SESSION_IDENT" =~ ^AWS_SESSION_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_SESSION_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_ACCESS_KEY_ID="$(env | grep AWS_ACCESS_KEY_ID)"
	if [[ "$ENV_AWS_ACCESS_KEY_ID" =~ ^AWS_ACCESS_KEY_ID[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_ACCESS_KEY_ID="${BASH_REMATCH[1]}"
		active_env="true"
		env_secrets_present="true"
	fi

	ENV_AWS_SECRET_ACCESS_KEY="$(env | grep AWS_SECRET_ACCESS_KEY)"
	if [[ "$ENV_AWS_SECRET_ACCESS_KEY" =~ ^AWS_SECRET_ACCESS_KEY[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_SECRET_ACCESS_KEY="${BASH_REMATCH[1]}"
		ENV_AWS_SECRET_ACCESS_KEY_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
	fi

	ENV_AWS_SESSION_TOKEN="$(env | grep AWS_SESSION_TOKEN)"
	if [[ "$ENV_AWS_SESSION_TOKEN" =~ ^AWS_SESSION_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TOKEN="${BASH_REMATCH[1]}"
		ENV_AWS_SESSION_TOKEN_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
		active_env_session="true"
	fi

	ENV_AWS_SESSION_TYPE="$(env | grep AWS_SESSION_TYPE)"
	if [[ "$ENV_AWS_SESSION_TYPE" =~ ^AWS_SESSION_TYPE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TYPE="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_SESSION_EXPIRY="$(env | grep AWS_SESSION_EXPIRY)"
	if [[ "$ENV_AWS_SESSION_EXPIRY" =~ ^AWS_SESSION_EXPIRY[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_EXPIRY="${BASH_REMATCH[1]}"
		active_env="true"

		# this_session_expired remains 'unknown' if a non-numeric-only
		#  value of ENV_AWS_SESSION_EXPIRY is encountered
		if [[ $ENV_AWS_SESSION_EXPIRY =~ ^([[:digit:]]+)$ ]]; then
			ENV_AWS_SESSION_EXPIRY="${BASH_REMATCH[1]}"		

			getRemaining _ret "$ENV_AWS_SESSION_EXPIRY"
			if [[ "${_ret}" -le 0 ]]; then
				this_session_expired="true"
			else
				this_session_expired="false"
			fi
		fi
	fi

	ENV_AWS_DEFAULT_REGION="$(env | grep AWS_DEFAULT_REGION)"
	if [[ "$ENV_AWS_DEFAULT_REGION" =~ ^AWS_DEFAULT_REGION[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_REGION="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_DEFAULT_OUTPUT="$(env | grep AWS_DEFAULT_OUTPUT)"
	if [[ "$ENV_AWS_DEFAULT_OUTPUT" =~ ^AWS_DEFAULT_OUTPUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_OUTPUT="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_CA_BUNDLE="$(env | grep AWS_CA_BUNDLE)"
	if [[ "$ENV_AWS_CA_BUNDLE" =~ ^AWS_CA_BUNDLE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CA_BUNDLE="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_SHARED_CREDENTIALS_FILE="$(env | grep AWS_SHARED_CREDENTIALS_FILE)"
	if [[ "$ENV_AWS_SHARED_CREDENTIALS_FILE" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SHARED_CREDENTIALS_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_CONFIG_FILE="$(env | grep AWS_CONFIG_FILE)"
	if [[ "$ENV_AWS_CONFIG_FILE" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CONFIG_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_METADATA_SERVICE_TIMEOUT="$(env | grep AWS_METADATA_SERVICE_TIMEOUT)"
	if [[ "$ENV_AWS_METADATA_SERVICE_TIMEOUT" =~ ^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_METADATA_SERVICE_TIMEOUT="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS="$(env | grep AWS_METADATA_SERVICE_NUM_ATTEMPTS)"
	if [[ "$ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS" =~ ^AWS_METADATA_SERVICE_NUM_ATTEMPTS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS="${BASH_REMATCH[1]}"
		active_env="true"
	fi

	## PROCESS THE ENVVAR RESULTS

	# THE SIX+ CASES OF AWS ENVVARS:
	# 
	# 1a. VALID corresponding persisted session profile (select-only-mfasession, select-only-rolesession)
	# 1b. INVALID corresponding persisted session profile (select-only-mfasession, select-only-rolesession)
	# 1c. UNCONFIRMED corresponding persisted session profile due absent expiry (select-only-mfasession, select-only-rolesession)
	# 1d. VALID corresponding persisted baseprofile (select-only-baseprofile)
	# 1e. INVALID corresponding persisted baseprofile (select-only-baseprofile)
	# 1f. UNCONFIRMED corresponding persisted baseprofile due to quick mode (select-only-baseprofile)
	# 
	# 2a. VALID corresponding persisted session profile (select-mirrored-mfasession, select-mirrored-rolesession)
	# 2b. INVALID corresponding persisted session profile (select-mirrored-mfasession, select-mirrored-rolesession)
	# 2c. UNCONFIRMED corresponding persisted session profile due to absent expiry (select-mirrored-mfasession, select-mirrored-rolesession)
	# 2d. VALID corresponding persisted baseprofile (select-mirrored-baseprofile)
	# 2e. INVALID corresponding persisted baseprofile (select-mirrored-baseprofile)
	# 2f. UNCONFIRED corresponding persisted baseprofile due to quick mode (select-mirrored-baseprofile)
	# 
	# 3a. INVALID expired named profile with differing secrets (select-diff-mfasession, select-diff-rolesession)
	# 3b. VALID named role session profile with differing secrets (select-diff-rolesession)
	# 3c. VALID named role session profile with differing secrets (select-diff-mfasession)
	# 3d. INVALID named session profile with differing secrets (select-diff-session)
	# 3e. VALID (assumed) named session profile with differing secrets (unident-session)
	# 
	# 4a. VALID (assumed) named baseprofile with differing secrets (select-diff-second-baseprofile)
	# 4b. VALID (assumed) named baseprofile with differing secrets (select-diff-rotated-baseprofile)
	# 4c. INVALID named baseprofile with differing secrets (select-diff-baseprofile)
	#
	# 5a. INVALID in-env session profile (AWS_PROFILE points to a non-existent persisted profile)
	# 5b. INVALID in-env baseprofile (AWS_PROFILE points to a non-existent persisted profile)
	# 5c. INVALID in-env selector only (AWS_PROFILE points to a non-existent persisted profile)
	# 
	# 6a. VALID unnamed, complete baseprofile (unident-baseprofile)
	# 6b. INVALID unnamed, complete baseprofile (unident-baseprofile)
	# 6c. UNCONFIRMED unnamed, complete baseprofile (unident-baseprofile)
	# 6d. INVALID (expired) unnamed, complete session profile (unident-session)
	# 6e. VALID unnamed, complete role session profile (unident-rolesession)
	# 6f. VALID unnamed, complete MFA session profile (unident-mfasession)
	# 6g. VALID unnamed, complete session profile (unident-session)
	# 
	# 7.  NO IN-ENVIRONMENT AWS PROFILE OR SESSION

	if [[ "$active_env" == "true" ]]; then  # some AWS_ vars present in the environment

		# BEGIN NAMED PROFILES

#todo: env_selector_present should include AWS_SESSION_IDENT and AWS_PROFILE_IDENT!

		if [[ "$env_selector_present" == "true" ]]; then

			# get the persisted merged_ident index for the in-env profile name
			#  (when AWS_PROFILE is defined, a persisted session profile of 
			#  the same name *must* exist)
			idxLookup env_profile_idx merged_ident[@] "$ENV_AWS_PROFILE"

			if [[ "$env_profile_idx" != "" ]] &&
				[[ "$env_secrets_present" == "false" ]]; then  # a named profile select only

				if [[ "${merged_type[$env_profile_idx]}" == "baseprofile" ]]; then
					env_aws_type="select-only-baseprofile"
				elif [[ "${merged_type[$env_profile_idx]}" == "mfasession" ]]; then
					env_aws_type="select-only-mfasession"
				elif [[ "${merged_type[$env_profile_idx]}" == "rolesession" ]]; then
					env_aws_type="select-only-rolesession"
				fi

				if [[ "${merged_type[$env_profile_idx]}" =~ session$ ]]; then

					# for session profile selects, go with the persisted session
					# status (which may be derived from expiry only if quick
					# mode is effective, or from expiry + get-caller-identity)
					if [[ ${merged_session_status[$env_profile_idx]} == "valid" ]]; then  # 1a: the corresponding persisted session profile is valid
						env_aws_status="valid"
					elif [[ ${merged_session_status[$env_profile_idx]} == "invalid" ]]; then  # 1b: the corresponding persisted session profile is invalid
						env_aws_status="invalid"
					else  # 1c: the corresponding persisted session profile doesn't have expiry
						env_aws_status="unconfirmed"
					fi
				else 
					# baseprofile selects validity
					if [[ "$quick_mode" == "false" ]]; then
						if [[ "${merged_baseprofile_arn[$env_profile_idx]}" != "" ]]; then  # 1d: the corresponding persisted baseprofile is valid
							env_aws_status="valid"
						else  # 1e: the corresponding persisted baseprofile is invalid
							env_aws_status="invalid"
						fi
					else  # 1f: quick mode is active; no way to confirm baseprofile validity
						env_aws_status="unconfirmed"
					fi
				fi

			elif [[ "$env_profile_idx" != "" ]] &&
				[[ "$env_secrets_present" == "true" ]]; then  # detected: a named profile select w/secrets (a persisted AWS_PROFILE + secrets)

				if [[ "$ENV_AWS_ACCESS_KEY_ID" == "${merged_aws_access_key_id[$env_profile_idx]}" ]]; then  # secrets are mirrored

					if [[ "${merged_type[$env_profile_idx]}" == "baseprofile" ]]; then
						env_aws_type="select-mirrored-baseprofile"
					elif [[ "${merged_type[$env_profile_idx]}" == "mfasession" ]]; then
						env_aws_type="select-mirrored-mfasession"
					elif [[ "${merged_type[$env_profile_idx]}" == "rolesession" ]]; then
						env_aws_type="select-mirrored-rolesession"
					fi

					if [[ "${merged_type[$env_profile_idx]}" =~ session$ ]]; then

						# for session profile selects, go with the persisted session
						# status (which may be derived from expiry only if quick
						# mode is effective, or from expiry + get-caller-identity)
						if [[ ${merged_session_status[$env_profile_idx]} == "valid" ]]; then  # 2a: the corresponding persisted session profile is valid
							env_aws_status="valid"
						elif [[ ${merged_session_status[$env_profile_idx]} == "invalid" ]]; then  # 2b: the corresponding persisted session profile is invalid
							env_aws_status="invalid"
						else  # 2c: the corresponding persisted session profile doesn't have expiry
							env_aws_status="unconfirmed"
						fi
					else 
						# baseprofile selects validity
						if [[ "$quick_mode" == "false" ]]; then
							if [[ "${merged_baseprofile_arn[$env_profile_idx]}" != "" ]]; then  # 2d: the corresponding persisted baseprofile is valid
								env_aws_status="valid"
							else  # 2e: the corresponding persisted baseprofile is invalid
								env_aws_status="invalid"
							fi
						else  # 2f: quick mode is active; no way to confirm baseprofile validity
							env_aws_status="unconfirmed"
						fi
					fi

				elif [[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] &&	 # this is a named session whose AWS_ACCESS_KEY_ID differs from that of the corresponding
					[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]] &&  #  persisted profile (this is known because of the previous condition did not match);
					[[ "$ENV_AWS_SESSION_TOKEN" != "" ]]; then   #  possibly a more recent session which wasn't persisted; verify

					# mark expired named in-env session invalid
					if [[ "$this_session_expired" == "true" ]]; then  # 3a: the named, diff in-env session has expired (cannot use differing persisted profile data)
						env_aws_status="invalid"
						env_aws_type="select-diff-session"

					elif [[ "$this_session_expired" == "false" ]]; then 

						if [[ "$quick_mode" == "false" ]]; then

							# test: get Arn for the in-env session
							getProfileArn _ret

							if [[ "${_ret}" =~ ^arn:aws:sts::[[:digit:]]+:assumed-role/([^/]+) ]]; then  # 3b: the named, diff in-env role session is valid
								this_iam_name="${BASH_REMATCH[1]}"
								env_aws_status="valid"
								env_aws_type="select-diff-rolesession"

							elif [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then  # 3c: the named in-env MFA session is valid
								this_iam_name="${BASH_REMATCH[1]}"
								env_aws_status="valid"
								env_aws_type="select-diff-mfasession"

							else  # 3d: the named in-env session is invalid
								env_aws_status="invalid"
								env_aws_type="select-diff-session"

							fi

						else  # 3e: quick mode is active; assume valid since the session
							  #  hasn't expired; the session type is not known
							env_aws_status="valid"
							env_aws_type="unident-session"
						fi
					fi

					# NAMED SESSIONS, TYPE DETERMINED; ADD A REFERENCE MARKER

					if [[ "$env_aws_status" == "valid" ]] &&
						[[ "$quick_mode" == "false" ]]; then

						if [[ "$this_iam_name" == "${merged_username[$env_profile_idx]}" ]] && 	# confirm that the in-env session is actually for the same profile as the persisted one
																								#  NOTE: this doesn't distinguish between a baseprofile and an MFA session!

							[[ "${merged_aws_session_token[$env_profile_idx]}" != "" ]] &&		# make sure the corresponding persisted profile is also a session (i.e. has a token)

							( [[ "$ENV_AWS_SESSION_EXPIRY" != "" ]] &&  													# in-env expiry is set
							  [[ "${merged_aws_session_expiry[$env_profile_idx]}" != "" ]] &&								# the persisted profile's expiry is also set
							  [[ "${merged_aws_session_expiry[$env_profile_idx]}" -lt "$ENV_AWS_SESSION_EXPIRY" ]] ); then	# and the in-env expiry is more recent
				
							# set a marker for corresponding persisted profile
							merged_has_in_env_session[$env_profile_idx]="true"  

							# set a marker for the base/role profile
							merged_has_in_env_session[${merged_parent_idx[$env_profile_idx]}]="true"  

						fi
					fi

				elif [[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] &&	# this is a named in-env baseprofile whose AWS_ACCESS_KEY_ID
					[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]] && #  differs from that of the corresponding persisted profile;
					[[ "$ENV_AWS_SESSION_TOKEN" == "" ]]; then  #  could be rotated or second credentials stored in-env only.

					# get Arn for the named in-env baseprofile
					getProfileArn _ret

					if [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then
						this_iam_name="${BASH_REMATCH[1]}"
						env_aws_status="valid"

						if [[ "$this_iam_name" == "${merged_username[$env_profile_idx]}" ]]; then  # 4a: a named baseprofile select with differing secrets

							# a second funtional key for the same baseprofile?
							env_aws_type="select-diff-second-baseprofile"
						
						elif [[ $this_iam_name != "" ]] &&
							[[ ${merged_username[$env_profile_idx]} == "" ]]; then  # 4b: a named baseprofile select with differing secrets
							
							# the persisted baseprofile is noop;
							# are these rotated credentials?
							env_aws_type="select-diff-rotated-baseprofile"
						fi

					else  # 4c: an invalid, named baseprofile with differing secrets
						env_aws_status="invalid"
						env_aws_type="select-diff-baseprofile"

					fi					
				fi

			elif [[ "$env_profile_idx" == "" ]]; then  # invalid (#4): a named profile that isn't persisted (w/wo secrets)
													   # (named profiles *must* have a persisted profile, even if it's a stub)
				env_aws_status="invalid"

				if [[ "$active_env_session" == "true" ]]; then  # 5a: a complete in-env session profile with an invalid AWS_PROFILE
					env_aws_type="named-session-orphan"
				elif [[ "$env_secrets_present" == "true" ]]; then  # 5b: a complete in-env baseprofile with an invalid AWS_PROFILE
					env_aws_type="named-baseprofile-orphan"
				else  # 5c: AWS_PROFILE selector only, pointing to a non-existent persisted profile
					env_aws_type="named-select-orphan"
				fi
			fi

		# BEGIN UNNAMED PROFILES

#todo: if ENV_AWS_SESSION_IDENT is set, it can connect an otherwise "unnamed" profile to a [possibly] persisted profile

		elif [[ "$ENV_AWS_PROFILE" == "" ]] &&
			[[ "$active_env_session" == "false" ]]; then

			if [[ "$quick_mode" == "false" ]]; then
				
				env_aws_type="unident-baseprofile"
				# get Arn for the unnamed in-env baseprofile
				getProfileArn _ret

				if [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then  # valid 6a: an unnamed, valid baseprofile
					this_iam_name="${BASH_REMATCH[1]}"
					env_aws_status="valid"
# todo: attempt to match w/key_id, arn - if match, match internally (for display?)
				else  # 6b: an invalid unnamed baseprofile
					env_aws_status="invalid"
				fi

			else  # 6c: a valid unnamed baseprofile (quick mode is active; status unconfirmed)
				env_aws_status="unconfirmed"
				env_aws_type="unident-baseprofile"
# todo: attempt to match w/key_id - if match, match internally (for display?)
			fi

		elif [[ "$ENV_AWS_PROFILE" == "" ]] &&
			[[ "$active_env_session" == "true" ]]; then

			if [[ "$this_session_expired" == "true" ]]; then  # 6d: an invalid (expired) unnamed session 
				env_aws_status="invalid"
				env_aws_type="unident-session"

			elif [[ "$this_session_expired" == "false" ]]; then  # the unnamed, in-env session hasn't expired according to ENV_AWS_SESSION_EXPIRY

				if [[ "$quick_mode" == "false" ]]; then
			
					# get Arn for the unnamed in-env session
					getProfileArn _ret

					if [[ "${_ret}" =~ ^arn:aws:sts::[[:digit:]]+:assumed-role/([^/]+) ]]; then  # 6e: an unnamed, valid rolesession
						this_iam_name="${BASH_REMATCH[1]}"
						env_aws_status="valid"
						env_aws_type="unident-rolesession"

					elif [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then  # 6f: an unnamed, valid mfasession
						this_iam_name="${BASH_REMATCH[1]}"
						env_aws_status="valid"
						env_aws_type="unident-mfasession"
# todo: attempt to match, w/arn - if match, match internally (for display?)
					else  # 6f: an unnamed, invalid session
						env_aws_status="invalid"
						env_aws_type="unident-session"
					fi

				else  # 6g: quick mode is active; assume valid since the session
					  #  hasn't expired. the session type is not known
					env_aws_status="valid"
					env_aws_type="unident-session"	

				fi
			fi
		fi

	else  # 7: no in-env AWS_ variables

		env_aws_status="none"
	fi

	# OUTPUT A NOTIFICATION OF AN INVALID PROFILE
	# 
	# AWS_PROFILE must be empty or refer to *any* profile in ~/.aws/{credentials|config}
	# (Even if all the values are overridden by AWS_* envvars they won't work if the 
	# AWS_PROFILE is set to point to a non-existent persistent profile!)
	if [[ $env_aws_status == "invalid" ]]; then
		# In-env AWS credentials (session or baseprofile) are not valid;
		# commands without a profile selected explicitly with '--profile' will fail
		
		if [[ "$env_aws_type" =~ baseprofile$ ]]; then

			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE SELECTED/CONFIGURED IN THE ENVIRONMENT IS INVALID.${Color_Off}\\n"

		elif [[ "$env_aws_type" =~ session$ ]]; then

			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS SESSION SELECTED/CONFIGURED IN THE ENVIRONMENT IS "

			if [[ "${this_session_expired}" == "true" ]]; then
				echo -e "EXPIRED.${Color_Off}\\n"
			else
				echo -e "INVALID.${Color_Off}\\n"
			fi

		elif [[ "$env_aws_type" == "named-baseprofile-orphan" ]]; then

			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE SELECTED IN THE ENVIRONMENT DOES NOT EXIST.${Color_Off}\\n"

		elif [[ "$env_aws_type" == "named-session-orphan" ]]; then

			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS SESSION SELECTED IN THE ENVIRONMENT DOES NOT EXIST.${Color_Off}\\n"

		elif [[ "$env_aws_type" == "named-select-orphan" ]]; then

			echo -e "\\n${BIRed}${On_Black}\
NOTE: THE AWS PROFILE SELECTED IN THE ENVIRONMENT DOES NOT EXIST.${Color_Off}\\n"
		
		fi

		echo -e "\\Purge the invalid AWS envvars with:\\n\
		${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}\\n\
		or else you must include '--profile someprofilename' to every aws command.\\n\
		Note that if you activate this script's final output, it will also fix the environment.\\n"

	fi

	# detect and print an informative notice of 
	# the effective AWS envvars
	if [[ "${AWS_PROFILE}" != "" ]] ||
		[[ "${AWS_PROFILE_IDENT}" != "" ]] ||
		[[ "${AWS_SESSION_IDENT}" != "" ]] ||
		[[ "${AWS_ACCESS_KEY_ID}" != "" ]] ||
		[[ "${AWS_SECRET_ACCESS_KEY}" != "" ]] ||
		[[ "${AWS_SESSION_TOKEN}" != "" ]] ||
		[[ "${AWS_ROLESESSION_EXPIRY}" != "" ]] ||
		[[ "${AWS_SESSION_TYPE}" != "" ]] ||
		[[ "${AWS_DEFAULT_REGION}" != "" ]] ||
		[[ "${AWS_DEFAULT_OUTPUT}" != "" ]] ||
		[[ "${AWS_CA_BUNDLE}" != "" ]] ||
		[[ "${AWS_SHARED_CREDENTIALS_FILE}" != "" ]] ||
		[[ "${AWS_CONFIG_FILE}" != "" ]] ||
		[[ "${AWS_METADATA_SERVICE_TIMEOUT}" != "" ]] ||
		[[ "${AWS_METADATA_SERVICE_NUM_ATTEMPTS}" != ""	]]; then



			echo
			echo "NOTE: THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE CURRENTLY IN EFFECT:"
			echo
			[[ "$ENV_AWS_PROFILE" != "" ]] && echo "   AWS_PROFILE: ${ENV_AWS_PROFILE}${env_notice}"
			[[ "$ENV_AWS_PROFILE_IDENT" != "" ]] && echo "   AWS_PROFILE_IDENT: ${ENV_AWS_PROFILE_IDENT}"
			[[ "$ENV_AWS_SESSION_IDENT" != "" ]] && echo "   AWS_SESSION_IDENT: ${ENV_AWS_SESSION_IDENT}"
			[[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] && echo "   AWS_ACCESS_KEY_ID: $ENV_AWS_ACCESS_KEY_ID"
			[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]] && echo "   AWS_SECRET_ACCESS_KEY: $ENV_AWS_SECRET_ACCESS_KEY_PR"
			[[ "$ENV_AWS_SESSION_TOKEN" != "" ]] && echo "   AWS_SESSION_TOKEN: $ENV_AWS_SESSION_TOKEN_PR"
			if [[ "$ENV_AWS_SESSION_EXPIRY" != "" ]]; then
				getRemaining env_seconds_remaining "${ENV_AWS_SESSION_EXPIRY}"
				getPrintableTimeRemaining env_session_remaining_pr "${env_seconds_remaining}"
				echo "   AWS_SESSION_EXPIRY: $ENV_AWS_SESSION_EXPIRY (${env_session_remaining_pr})"
			fi
			[[ "$ENV_AWS_SESSION_TYPE" != "" ]] && echo "   AWS_SESSION_TYPE: $ENV_AWS_SESSION_TYPE"
			[[ "$ENV_AWS_DEFAULT_REGION" != "" ]] && echo "   AWS_DEFAULT_REGION: $ENV_AWS_DEFAULT_REGION"
			[[ "$ENV_AWS_DEFAULT_OUTPUT" != "" ]] && echo "   AWS_DEFAULT_OUTPUT: $ENV_AWS_DEFAULT_OUTPUT"
			[[ "$ENV_AWS_CONFIG_FILE" != "" ]] && echo "   AWS_CONFIG_FILE: $ENV_AWS_CONFIG_FILE"
			[[ "$ENV_AWS_SHARED_CREDENTIALS_FILE" != "" ]] && echo "   AWS_SHARED_CREDENTIALS_FILE: $ENV_AWS_SHARED_CREDENTIALS_FILE"
			[[ "$ENV_AWS_CA_BUNDLE" != "" ]] && echo "   AWS_CA_BUNDLE: $ENV_AWS_CA_BUNDLE"
			[[ "$ENV_AWS_METADATA_SERVICE_TIMEOUT" != "" ]] && echo "   AWS_METADATA_SERVICE_TIMEOUT: $ENV_AWS_METADATA_SERVICE_TIMEOUT"
			[[ "$ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS" != "" ]] && echo "   AWS_METADATA_SERVICE_NUM_ATTEMPTS: $ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS"
			echo
	fi
}

# workaround function for lack of macOS bash's (3.2) assoc arrays
idxLookup() {
	# $1 is idxLookup_result (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function idxLookup] looking up '${3}'${Color_Off}"

	local idxLookup_result
	declare -a arr=("${!2}")
	local key="$3"
 	local idxLookup_result=""
 	local maxIndex

 	maxIndex="${#arr[@]}"
 	((maxIndex--))

	for (( i=0; i<=maxIndex; i++ ))
	do 
		if [[ "${arr[$i]}" == "$key" ]]; then
			idxLookup_result="$i"
			break
		fi
	done

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${idxLookup_result}${Color_Off}"
	eval "$1=\"$idxLookup_result\""
}

# catches duplicate properties in the credentials and config files
declare -a dupes
dupesCollector() {
	# $1 is the profile_ident
	# $2 is the current line (raw)
	# $3 source_file (for display)

	local profile_ident="$1"
	local line="$2"
	local source_file="$3"
	local this_prop

	# check for dupes; exit if one is found
	if [[ "$profile_ident" != "" ]]; then

		if [[ "$profile_ident_hold" == "" ]]; then
			# initialize credfile_profile_hold (the first loop); this is a global
			profile_ident_hold="${profile_ident}"

		elif [[ "$profile_ident_hold" != "${profile_ident}" ]]; then

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** checking for $source_file dupes for '${profile_ident_hold}'..${Color_Off}"

			# on subsequent loops trigger exitOnArrDupes check
			exitOnArrDupes dupes[@] "${profile_ident_hold}" "props"
			unset dupes

			profile_ident_hold="${profile_ident}"
		else
			if [[ "$line" != "" ]]; then

				if [[ ! "$line" =~ ^[[:space:]]*#.* ]] &&
					[[ "$line" =~ ^([^[:space:]]+)[[:space:]]*=.* ]]; then

					this_prop="${BASH_REMATCH[1]}"

					#strip leading/trailing spaces
					this_prop="$(echo "$this_prop" | xargs echo -n)"

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  adding to the dupes array: '${this_prop}'${Color_Off}"
					dupes[${#dupes[@]}]="${this_prop}"
				fi
			fi
		fi
	fi
}

# check the provided array for duplicates; exit if any are found
exitOnArrDupes() {
	# $1 is the array to check
	# $2 is the profile/file being checked
	# $3 is the source type (props/credfile/conffile)

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function exitOnArrDupes] checking dupes for ${3} @${2}'${Color_Off}"

	local dupes=("${!1}")
	local ident="$2"
	local checktype="$3"
	local itr_outer
	local itr_inner
	local hits=0
	local last_hit

	for ((itr_outer=0; itr_outer<${#dupes[@]}; ++itr_outer))
	do
		for ((itr_inner=0; itr_inner<${#dupes[@]}; ++itr_inner))
		do
			if [[ "${dupes[${itr_outer}]}" == "${dupes[${itr_inner}]}" ]]; then
				(( hits++ ))
				last_hit="${dupes[${itr_inner}]}"
			fi
		done
		if [[ $hits -gt 1 ]]; then
			if [[ "$checktype" == "props" ]]; then
				echo -e "\\n${BIRed}${On_Black}A duplicate property '${last_hit}' found in the profile '${ident}'. Cannot continue.${Color_Off}\\n\\n"
			elif [[ "$checktype" == "conffile" ]]; then
				echo -e "\\n${BIRed}${On_Black}A duplicate profile label '[${last_hit}]' found in the config file '${ident}'. Cannot continue.${Color_Off}\\n\\n"
			elif [[ "$checktype" == "credfile" ]]; then
				echo -e "\\n${BIRed}${On_Black}A duplicate profile label '[${last_hit}]' found in the credentials file '${ident}'. Cannot continue.${Color_Off}\\n\\n"
			fi
			exit 1
		else
			hits=0
		fi
	done
}

# adds a new property+value to the defined config file
addConfigProp() {
	# $1 is the target file
	# $2 is the target profile (the anchor; requires the label with a "profile_" prefix for non-default profiles in CONFFILE)
	# $3 is the property
	# $4 is the value
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function addConfigProp] target_file: $1, target_profile: $2, property: $3, value: $4${Color_Off}"

	local target_file="$1"
	local target_profile="$2"
	local new_property="$3"
	local new_value="$4"
	local replace_me
	local DATA

	replace_me="\\[${target_profile}\\]"

	DATA="[${target_profile}]\\n${new_property} = ${new_value}"

	# is there really no better way to do this
	# while trying to only use the builtins while
	# remaining bash 3.2 compatible (because macOS)?
	sed -i -e 's/\[profile /\[profile_/g' "${target_file}"
	echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${target_file}")" > "${target_file}"
	sed -i -e 's/\[profile_/\[profile /g' "${target_file}"
}

# updates an existing property value in the defined config file
updateUniqueConfigPropValue() {
	# $1 is target file
	# $2 is old property value
	# $3 is new property value
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function updateUniqueConfigPropValue] target_file: $1, old_property_value: $2, new_property_value: $3${Color_Off}"

	local target_file="$1"
	local old_value="$2"
	local new_value="$3"

	if [[ "$OS" == "macOS" ]]; then 
		sed -i '' -e "s/${old_value}/${new_value}/g" "$target_file"
	else 
		sed -i -e "s/${old_value}/${new_value}/g" "$target_file"
	fi
}

# todo: confirm that this works for both default and 'profile' profiles (like add)
# 
# deletes an existing property value in the defined config file
deleteConfigProp() {
	# $1 is target file
	# $2 is the target profile
	# $3 is the prop name to be deleted
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function deleteCofnigProp] target_file: $1, target_profile: $2, prop_to_delete: $3${Color_Off}"

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

	TMPFILE="$(mktemp "$HOME/tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")"

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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function writeSessionExpTime] this_ident: $1, new_session_expiration_timestamp: $2${Color_Off}"

	local this_ident="$1"
	local new_session_expiration_timestamp="$2"

	local idx
	local old_session_exp

	# get idx for the current ident
	idxLookup idx merged_ident[@] "$this_ident"

	# find the selected profile's existing
	# expiry time if one exists
	getSessionExpiry old_session_exp "$this_ident"

	if [[ "$old_session_exp" != "" ]]; then
		# time entry exists for the profile, update it
		updateUniqueConfigPropValue "$CREDFILE" "$old_session_exp" "$new_session_expiration_timestamp"
	else
		# no time entry exists for the profile; 
		# add a new property line after the header "$this_ident"
		addConfigProp "$CREDFILE" "${this_ident}" "aws_session_expiry" "$new_session_expiration_timestamp"
	fi
}

writeSessmax() {
	# $1 is the target ident (role)
	# $2 is the sessmax value

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function writeSessmax] target_ident: $1, sessmax_value: $2${Color_Off}"

	local this_target_ident="$1"
	local this_sessmax="$2"
	local local_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	if [[ "${merged_sessmax[$local_idx]}" == "" ]]; then
		# add the sessmax property
		addConfigProp "$CONFFILE" "profile_$this_target_ident" "sessmax" "$this_sessmax"

	elif [[ "${this_sessmax}" == "erase" ]]; then
		# delete the existing sessmax property
		deleteConfigProp "$CONFFILE" "profile_$this_target_ident" "sessmax"

	else
		# update the existing sessmax value (delete+add)
		deleteConfigProp "$CONFFILE" "profile_$this_target_ident" "sessmax"
		addConfigProp "$CONFFILE" "profile_$this_target_ident" "sessmax" "$this_sessmax"
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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function writeRoleSourceProfile] target_ident: $1, source_profile_ident: $2${Color_Off}"

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

		addConfigProp "$CONFFILE" "profile_$target_ident" "source_profile" "$source_profile_ident"
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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function writeBaseprofileMfaArn] target_ident: $1, vMFAd_Arn: $2${Color_Off}"

	local this_ident="$1"
	local baseprofile_vmfad_arn="$2"

	local idx

	# get idx for the current ident
	idxLookup idx merged_ident[@] "$this_ident"

	# must have a profile index to proceed
	if [[ "$idx" != "" ]]; then

		if [[ "$baseprofile_vmfad_arn" == "erase" ]]; then
			# vmfad has gone away; delete the existing mfad_arn entry
			deleteConfigProp "$CONFFILE" "profile_${merged_ident[$idx]}" "mfa_arn"
		elif [[ "$baseprofile_vmfad_arn" != "" ]]; then
			# add a vmfad entry (none exists previously)
			addConfigProp "$CONFFILE" "profile_${merged_ident[$idx]}" "mfa_arn" "$baseprofile_vmfad_arn"
		fi
	fi
}

writeRoleMFASerialNumber() {
	# $1 is the target profile ident to add mfa_serial to
	# $2 is the mfa_serial

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function writeRoleMFASerialNumber] target_profile: $1, mfa_serial: $2${Color_Off}"

	local this_target_ident="$1"
	local this_mfa_serial="$2"
	local local_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	if [[ "${merged_type[$local_idx]}" == "role" ]]; then

		if [[ "${merged_role_mfa_serial[$local_idx]}" == "" ]]; then
			# add the mfa_serial property
			addConfigProp "$CONFFILE" "profile_$this_target_ident" "mfa_serial" "$this_mfa_serial"

		elif [[ "${this_mfa_serial}" == "erase" ]]; then  # "mfa_serial" is set to "erase" when the MFA requirement for a role has gone away
			# delete the existing mfa_serial property
			deleteConfigProp "$CONFFILE" "profile_$this_target_ident" "mfa_serial"
		else
			# update the existing mfa_serial value (delete+add)
			deleteConfigProp "$CONFFILE" "profile_$this_target_ident" "mfa_serial"
			addConfigProp "$CONFFILE" "profile_$this_target_ident" "mfa_serial" "$this_mfa_serial"
		fi
	fi
}

# return the session expiry time for
# the given role/mfa session profile
getSessionExpiry() {
	# $1 is getSessionExpiry_result
	# $2 is the profile ident

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getSessionExpiry] profile_ident: '${2}'${Color_Off}"

	local getSessionExpiry_result
	local this_ident="$2"

	local idx
	local getSessionExpiry_result
 
	# find the profile's init/expiry time entry if one exists
	idxLookup idx merged_ident[@] "$this_ident"

	getSessionExpiry_result="${merged_aws_session_expiry[$idx]}"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getSessionExpiry_result}${Color_Off}"
	eval "$1=\"${getSessionExpiry_result}\""
}

getMaxSessionDuration() {
	# $1 is getMaxSessionDuration_result
	# $2 is the profile ident
	# $3 is "baseprofile" or "role";
	#    required for the baseprofiles and roles (but optional for the sessions
	#    since the session type can be derived from the profile_ident)

#todo: could root login be resolved here so that the default root session length could be returned?

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getMaxSessionDuration] profile_ident: $2, profile_type (optional): $3${Color_Off}"

	local getMaxSessionDuration_result
	local this_profile_ident="$2"
	local this_sessiontype="$3"

	local idx
	local getMaxSessionDuration_result

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
		getMaxSessionDuration_result="${merged_sessmax[$idx]}"

	else
		# sessmax is not being used; using the defaults

		if [[ "$this_sessiontype" == "baseprofile" ]]; then
			getMaxSessionDuration_result="$MFA_SESSION_LENGTH_IN_SECONDS"

		elif [[ "$this_sessiontype" == "role" ]]; then
			getMaxSessionDuration_result=3600  # the default AWS role session length is 3600 seconds if not otherwise defined

		fi
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getMaxSessionDuration_result}${Color_Off}"
	eval "$1=\"${getMaxSessionDuration_result}\""
}

# Returns remaining seconds for the given expiry timestamp
# In the result 0 indicates expired, -1 indicates NaN input;
# if arg #3 is 'true', then the human readable datetime is
# returned instead
getRemaining() {
	# $1 is getRemaining_result
	# $2 is the expiration timestamp
	# $3 optional (default: 'seconds' remaining, 'datetime' expiration epoch, 'timestamp' expiration timestamp)

	local getRemaining_result
	local expiration_timestamp="$2"
	local expiration_date
	local this_time="$(date "+%s")"
	local getRemaining_result="0"
	local this_session_time_slack
	local timestamp_format="invalid"
	local exp_time_format="seconds"  # seconds = seconds remaining, datetime = expiration datetime, timestamp = expiration timestamp
	[[ "$3" != "" ]] && exp_time_format="$3"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getRemaining] expiration_timestamp: $2, expiration time format (output): ${exp_time_format}${Color_Off}"

	if [[ "${expiration_timestamp}" =~ ^[[:digit:]]{10}$ ]]; then
		timestamp_format="timestamp"

		if [[ "$OS" == "macOS" ]]; then
			expiration_date=$(date -jur $expiration_timestamp '+%Y-%m-%d %H:%M (UTC)')
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  macOS epoch->date conversion result: ${expiration_date}${Color_Off}"
		elif [[ "$OS" =~ Linux$ ]]; then
			expiration_date=$(date -d "@$expiration_timestamp" '+%Y-%m-%d %H:%M (UTC)')
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  Linux epoch->date conversion result: ${expiration_date}${Color_Off}"
		else
			timestamp_format="invalid"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  Could not convert to datetime (unknown OS)${Color_Off}"
		fi

	elif [[ "${expiration_timestamp}" =~ ^[[:digit:]]{4}-[[:digit:]]{2}-[[:digit:]]{2}T[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2}Z$ ]]; then
		timestamp_format="date"
		expiration_date="$expiration_timestamp"

		if [[ "$OS" == "macOS" ]]; then
			expiration_timestamp=$(date -juf "%Y-%m-%dT%H:%M:%SZ" "$expiration_timestamp" "+%s")
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  macOS date->epoch conversion result: ${expiration_timestamp}${Color_Off}"
		elif [[ "$OS" =~ Linux$ ]]; then
			expiration_timestamp=$(date -u -d"$expiration_timestamp" "+%s")
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  Linux date->epoch conversion result: ${expiration_timestamp}${Color_Off}"
		else
			timestamp_format="invalid"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  Could not convert to epoch (unknown OS)${Color_Off}"
		fi
	fi

	if [[ "${timestamp_format}" != "invalid" ]]; then
		
		(( this_session_time_slack=this_time+VALID_SESSION_TIME_SLACK ))
		if [[ $this_session_time_slack -lt $expiration_timestamp ]]; then
			(( getRemaining_result=expiration_timestamp-this_time ))
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  this_session_time_slack: $this_session_time_slack, this_time: $this_time, VALID_SESSION_TIME_SLACK: $VALID_SESSION_TIME_SLACK, getRemaining_result: $getRemaining_result${Color_Off}"
		else
			getRemaining_result="0"
		fi

		# optionally output expiration timestamp or expiration datetime
		# instead of the default "seconds remaining"
		if [[ "${exp_time_format}" == "timestamp" ]]; then
			getRemaining_result="${expiration_timestamp}"
		elif [[ "${exp_time_format}" == "datetime" ]]; then
			getRemaining_result="${expiration_date}"
		fi

	else
		getRemaining_result="-1"
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getRemaining_result}${Color_Off}"
	eval "$1=\"${getRemaining_result}\""
}

# return printable output for given 'remaining' timestamp
# (must be pre-incremented with profile duration,
# such as getRemaining() datestamp output)
getPrintableTimeRemaining() {
	# $1 is getPrintableTimeRemaining_result
	# $2 is the time_in_seconds

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getPrintableTimeRemaining] time_in_seconds: $2${Color_Off}"

	local getPrintableTimeRemaining_result
	local time_in_seconds="$2"

	case $time_in_seconds in
		-1)
			getPrintableTimeRemaining_result=""
			;;
		0)
			getPrintableTimeRemaining_result="00h:00m:00s"
			;;
		*)
			getPrintableTimeRemaining_result="$(printf '%02dh:%02dm:%02ds' $((time_in_seconds/3600)) $((time_in_seconds%3600/60)) $((time_in_seconds%60)))"
			;;
	esac

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getPrintableTimeRemaining_result}${Color_Off}"
	eval "$1=\"${getPrintableTimeRemaining_result}\""
}

getProfileArn() {
	# $1 is getProfileArn_result
	# $2 is the ident

	local getProfileArn_result
	local this_ident="$2"
	local this_profile_arn

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getProfileArn] this_ident: $2${Color_Off}"

	if [[ "$this_ident" == "" ]] &&						# if ident is not provided and
		[[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] &&			# env_aws_access_key_id is present
		[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]]; then	# env_aws_secret_access_key is present
														# env_aws_session_token may or may not be present; if it is, it is used automagically

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** no ident provided; testing in-env profile${Color_Off}"

		# in-env secrets present, profile not defined here: using in-env secrets
		this_profile_arn=$(aws sts get-caller-identity \
			--query 'Arn' \
			--output text 2>&1)

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}(in-env credentials present) result for: 'aws sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${this_profile_arn}${Color_Off}"
	
	elif [[ "$this_ident" != "" ]]; then

		# using the defined persisted profile
		this_profile_arn=$(aws --profile "$this_ident" sts get-caller-identity \
			--query 'Arn' \
			--output text 2>&1)

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$this_ident\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${this_profile_arn}${Color_Off}"
	
	else
		echo -e "\\n${BIRed}${On_Black}Ident not provided and no in-env profile. Cannot continue (program error).${Color_Off}\\n"
		exit 1

	fi

	if [[ "$this_profile_arn" =~ ^arn:aws: ]] &&
		[[ ! "$this_profile_arn" =~ 'error occurred' ]]; then

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Arn found; valid profile${Color_Off}"
		getProfileArn_result="$this_profile_arn"
	else
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** No Arn found; invalid profile${Color_Off}"
		getProfileArn_result=""
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getProfileArn_result}${Color_Off}"
	eval "$1=\"${getProfileArn_result}\""
}

isProfileValid() {
	# $1 is isProfileValid_result
	# $2 is the ident

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function isProfileValid] this_ident: $2${Color_Off}"

	local isProfileValid_result
	local this_ident="$2"
	local this_profile_arn

	getProfileArn _ret "$this_ident"

	if [[ "${_ret}" =~ ^arn:aws: ]]; then
		isProfileValid_result="true"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The profile '$this_ident' exists and is valid.${Color_Off}"
	else
		isProfileValid_result="false"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}The profile '$this_ident' not present or invalid.${Color_Off}"
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${isProfileValid_result}${Color_Off}"
	eval "$1=\"${isProfileValid_result}\""
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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function checkAWSErrors] aws_raw_return: ${Yellow}${On_Black}$2${BIYellow}${On_Black}, profile_in_use: $profile_in_use, custom_error: $4 ${Color_Off}\\n"

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
	# $1 is getAccountAlias_result (returns the account alias if found)
	# $2 is the profile_ident

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getAccountAlias] profile_ident: $2${Color_Off}"

	local getAccountAlias_result
	local local_profile_ident="$2"

	local account_alias_result
	local cache_hit="false"
	local cache_idx
	local itr

	if [[ "$local_profile_ident" == "" ]]; then
		# no input, return blank result
		getAccountAlias_result=""
	else

		for ((itr=0; itr<${#account_alias_cache_table_ident[@]}; ++itr))
		do
			if [[ "${account_alias_cache_table_ident[$itr]}" == "$local_profile_ident" ]]; then
				result="${account_alias_cache_table_result[$itr]}"
				cache_hit="true"
				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}Account alias found from cache for profile ident: '$local_profile_ident'\\n${ICyan}${account_alias_result}${Color_Off}"
			fi
		done

		if  [[ "$cache_hit" == "false" ]]; then
			# get the account alias (if any) for the profile
			account_alias_result="$(aws --profile "$local_profile_ident" iam list-account-aliases \
				--output text \
				--query 'AccountAliases' 2>&1)"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"$local_profile_ident\" iam list-account-aliases --query 'AccountAliases' --output text':\\n${ICyan}${account_alias_result}${Color_Off}"

			if [[ "$account_alias_result" =~ 'error occurred' ]]; then
				# no access to list account aliases
				# for this profile or other error
				getAccountAlias_result=""
			else
				getAccountAlias_result="$account_alias_result"
				cache_idx="${#account_alias_cache_table_ident[@]}"
				account_alias_cache_table_ident[$cache_idx]="$local_profile_ident"
				account_alias_cache_table_result[$cache_idx]="$account_alias_result"
			fi
		fi
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getAccountAlias_result}${Color_Off}"
	eval "$1=\"$getAccountAlias_result\""
}

dynamicAugment() {

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function dynamicAugment]${Color_Off}"

	local profile_check
	local cached_get_role
	local get_this_mfa_arn
	local get_this_role_arn
	local get_this_role_sessmax
	local get_this_role_mfa_req
	local get_this_session_status
	local idx
	local notice_reprint="true"
	local first_role_loop="true"

	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do

		if [[ "$notice_reprint" == "true" ]]; then
			echo -ne "\\n${BIWhite}${On_Black}Please wait"
			notice_reprint="false"
		fi

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** dynamic augment for ident '${merged_ident[$idx]}' (${merged_type[$idx]})${Color_Off}"
		
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then  # BASEPROFILE AUGMENT ---------------------------------

			# get the user ARN; this should be always
			# available for valid profiles
			getProfileArn _ret "${merged_ident[$idx]}"

			if [[ "${_ret}" =~ ^arn:aws: ]]; then
				merged_baseprofile_arn[$idx]="${_ret}"

				# get the actual username (may be different
				# from the arbitrary profile ident)
				if [[ "${_ret}" =~ ([[:digit:]]+):user.*/([^/]+)$ ]]; then
					merged_account_id[$idx]="${BASH_REMATCH[1]}"
					merged_username[$idx]="${BASH_REMATCH[2]}"
				fi

				# Check to see if this profile has access currently. Assuming
				# the provided MFA policies are utilized, this query determines
				# positively whether an MFA session is required for access (while
				# 'sts get-caller-identity' above verified that the creds are valid)

				profile_check="$(aws --profile "${merged_ident[$idx]}" iam get-access-key-last-used \
					--access-key-id ${merged_aws_access_key_id[$idx]} \
					--query 'AccessKeyLastUsed.LastUsedDate' \
					--output text 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$idx]}\" iam get-access-key-last-used --access-key-id  --query 'AccessKeyLastUsed.LastUsedDate' --output text':\\n${ICyan}${profile_check}${Color_Off}"

				if [[ "$profile_check" =~ ^[[:digit:]]{4} ]]; then  # access available as permissioned
					merged_baseprofile_operational_status[$idx]="ok"

				elif [[ "$profile_check" =~ 'AccessDenied' ]]; then  # requires an MFA session (or bad policy)
					merged_baseprofile_operational_status[$idx]="reqmfa"

				elif [[ "$profile_check" =~ 'could not be found' ]]; then  # should not happen since 'sts get-caller-id' test passed
					merged_baseprofile_operational_status[$idx]="none"

				else  # catch-all; should not happen since 'sts get-caller-id' test passed
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

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$idx]}\" iam list-mfa-devices --user-name \"${merged_username[$idx]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${get_this_mfa_arn}${Color_Off}"

				if [[ "$get_this_mfa_arn" =~ ^arn:aws: ]]; then
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

			if [[ "${first_role_loop}" == "true" ]]; then 

				first_role_loop="false"

				if [[ "$jq_available" == "false" ]]; then
					echo -e "\\n${BIWhite}${On_Black}\
Since you are using roles, consider installing 'jq'.${Color_Off}\\n
It will speed up some role-related operations and\\n\
make it possible to automatically import roles that\\n\
are initialized outside of this script.\\n"

					if [[ "$OS" == "macOS" ]] && 
						[[ "$has_brew" == "true" ]]; then 
						
						echo -e "Install with: 'brew install jq'\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "apt" ]]; then

						echo -e "Install with:\\nsudo apt update && sudo apt -y install jq\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "yum" ]]; then

						echo -e "Install with:\\nsudo yum install -y epel-release && sudo yum install -y jq\\n"

					else
						echo -e "Install 'jq' with your operating system's package manager.\\n"
					fi

				elif [[ "$jq_minimum_version" == "false" ]]; then
					echo -e "\\n${BIWhite}${On_Black}\
Please upgrade your 'jq' installation (minimum required version is 1.5).${Color_Off}\\n"

					if [[ "$OS" == "macOS" ]] && 
						[[ "$has_brew" == "true" ]]; then 

						echo -e "Upgrade with: 'brew upgrade jq'\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "apt" ]]; then

						echo -e "Upgrade with:\\nsudo apt update && sudo apt -y upgrade jq\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "yum" ]]; then

						echo -e "Upgrade with: 'sudo yum upgrade -y jq'\\n"

					else
						echo -e "Upgrade 'jq' with your package manager.\\n"
					fi
				fi
			fi  # end first_role_loop

			# a role must have a source_profile defined 
			if [[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then

				notice_reprint="true"

				echo -e "\\n\\n${BIRed}${On_Black}\
The role profile '${merged_ident[$idx]}' does not have a source_profile defined.${Color_Off}\\n\
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

					# prompt for a baseprofile selection
					echo -en  "\\n\
NOTE: If you don't set a source profile, you can't use this role until you do so.\\n${BIWhite}${On_Black}\
ENTER A SOURCE PROFILE ID AND PRESS ENTER (or Enter by itself to skip):${Color_Off} "
					read -r role_auth
					echo

					(( max_sel_val=selval+1 ))
					if [[ "$role_auth" -gt 0 && "$role_auth" -lt $max_sel_val ]]; then
						# this is a baseprofile selector for
						# a valid role source_profile

						(( actual_source_index=role_auth-1 ))
						# everybody with the EnforceMFA policy is allowed 
						# to query roles without an active MFA session;
						# try to use the selected profile to query the role
						# (we already know the role's Arn, so this is just
						# a reverse lookup to validate). If jq is available,
						# this will cache the result.
						if [[ "$jq_minimum_version_available" ]]; then
#todo: should any query be preceded with
# [[ merged_baseprofile_arn[$idx] != "" ]] ..?
# if ! quick.. ?
# .. to make sure that the baseprofile is valid?
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

						elif [[ "$get_this_role_arn" =~ .*NoSuchEntity.* ]]; then
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
						[[ ! "${merged_sessmax[$idx]}" == "" ]] && 
						[[ ! "$get_this_role_sessmax" == "3600" ]]; then

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

		elif [[ "${merged_type[$idx]}" =~ mfasession|rolesession ]]; then  # MFA OR ROLE SESSION AUGMENT ------------

			# no point to augment this session if the timestamps indicate
			# the session has expired. Note: this also checks the session
			# validity for the sessions whose init+sessmax or expiry
			# weren't set for some reason. After this process
			# merged_session_status will be populated for all sessions
			# with one of the following values:
			# valid, expired, invalid (i.e. not expired but not functional)
			if [[ "${merged_session_status[$idx]}" != "expired" ]]; then

				getProfileArn _ret "${merged_ident[$idx]}"

				if [[ "${_ret}" =~ ^arn:aws: ]] &&
					[[ ! "${_ret}" =~ 'error occurred' ]]; then

					merged_session_status[$idx]="valid"
				else
					merged_session_status[$idx]="invalid"
				fi
			fi
		fi

		[[ "$DEBUG" != "true" ]] &&
			echo -n "."
	done

	# phase II for things that have phase I deps
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

				# merged_username is now available for all baseprofiles
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
	# $1 is getMfaToken_result
	# $2 is token_target ('mfa' or 'role')

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getMfaToken] token_target: $2${Color_Off}"
	
	getMfaToken_result=""
	local token_target="$2"

	while :
	do
		echo -en "${BIWhite}${On_Black}"
		read -p ">>> " -r getMfaToken_result
		echo -en "${Color_Off}"
		if [[ "$token_target" == "mfa" ]]; then

			if ! [[ "$getMfaToken_result" =~ ^$ || "$getMfaToken_result" =~ ^[0-9]{6}$ ]]; then
				echo -e "${BIRed}${On_Black}The MFA token must be exactly six digits, or blank to bypass (to use the baseprofile without an MFA session).${Color_Off}"
				continue
			else
				break
			fi

		elif [[ "$token_target" == "role" ]]; then

			if ! [[ "$getMfaToken_result" =~ ^[0-9]{6}$ ]]; then
				echo -e "${BIRed}${On_Black}The MFA token must be exactly six digits.${Color_Off}"
				continue
			else
				break
			fi
		fi
	done

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getMfaToken_result}${Color_Off}"
	eval "$1=\"$getMfaToken_result\""
}

persistSessionMaybe() {
 	# $1 is the baseprofile ident
	# $2 is the target (session) ident
	# $3 is session result dataset
	# $4 (bool) is, if present, a request for no-questions-asked persist (a call by the role session init MFA init request)

	local baseprofile_ident="$1"
	local target_session_ident="$2"
	local session_data="$3"
	local confs_profile_idx
	local creds_profile_idx
	local auto_persist="false"
	local interactive_persist="false"
	[[ "$4" == "true" ]] && auto_persist="true"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function persistSessionMaybe] baseprofile_ident: $baseprofile_ident, target_session_ident: $target_session_ident, auto_persist: $auto_persist, session_data: $session_data${Color_Off}"

	if [[ "${auto_persist}" == "false" ]]; then

		echo -e "${BIWhite}${On_Black}\
Make this MFA session persistent?${Color_Off} (Saves the session in $CREDFILE\\n\
so that you can return to it during its validity period, ${AWS_SESSION_EXPIRY_PR}.)"

		read -s -p "$(echo -e "${BIWhite}${On_Black}Yes (default) - make peristent${Color_Off}; No - only the envvars will be used ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]] ||
			[[ $REPLY == "" ]]; then

			interactive_persist="true"
		fi
	fi

	if [[ "${auto_persist}" == "true" ]] ||
		[[ "${interactive_persist}" == "true" ]]; then

		# get index in confs array if any
		idxLookup confs_profile_idx confs_ident[@] "$AWS_SESSION_IDENT"

		if [[ "$confs_profile_idx" == "" ]]; then

			# no existing profile was found; make sure there's
			# a stub entry for the session profile in $CONFFILE
			# in preparation to persisting the profile
			echo -en "\\n\\n">> "$CONFFILE"
			echo "[profile ${AWS_SESSION_IDENT}]" >> "$CONFFILE"
		fi

		# get index in creds array if any (use duplicate as 
		# the creds_ident is truncated during merge)
		idxLookup creds_profile_idx creds_ident_duplicate[@] "$AWS_SESSION_IDENT"

		if [[ "$creds_profile_idx" == "" ]]; then

			# no existing profile was found; make sure there's
			# a stub entry for the session profile in $CONFFILE
			# in preparation to persisting the profile
			echo -en "\\n\\n">> "$CREDFILE"
			echo "[${AWS_SESSION_IDENT}]" >> "$CREDFILE"
		fi

#todo: the region and the output are persisted somewhere else; should they
#      be moved here?

		# PERSIST THE CONFIG
		# persist the session expiration time
		writeSessionExpTime "$AWS_SESSION_IDENT" "$AWS_SESSION_EXPIRY"
		
		# a global indicator that a persistent MFA session has been initialized
		persistent_MFA="true"

		# PERSIST THE CREDENTIALS

		# export the selection to the remaining subshell commands in this script
		# so that "--profile" selection is not required, and in fact should not
		# be used for setting the credentials (or else they go to the conffile)
		export AWS_PROFILE="$AWS_SESSION_IDENT"

		# NOTE: These do not require the "--profile" switch because AWS_PROFILE
		#       has been exported above. If you set --profile, the details
		#       go to the CONFFILE instead of CREDFILE (so don't set it! :-)
		aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
		aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
		aws configure set aws_session_token "$AWS_SESSION_TOKEN"
	fi
}

AWS_SESSION_INITIALIZED="false"
acquireSession() {
	# $1 is acquireSession_result
	# $2 is the baseprofile or the role profile ident
	# $3 is, if present, a request for no-questions-asked auto-persist (a recursive call by the role session init)

	local session_baseprofile_ident="$2"
	local auto_persist_request="false"
	[[ "$3" == "true" ]] && auto_persist_request="true"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function acquireSession] base/role profile ident: $2, auto_persist: $3${Color_Off}"

	mfa_token=""
	local acquireSession_result
	local session_request_type="unknown"
	local this_role_arn
	local this_role_session_name
	local source_profile_has_session
	local source_profile_mfa_session_status
	local role_init_profile
	local mfa_session_detail
	local profile_idx
	local serial_switch=""
	local token_switch=""
	local external_id_switch=""
	local session_duration
	local profile_check
	local output_type
	local result=""
	local result_check
	local session_word
	local session_init="false"
	local update_session_idx

	[[ "$jq_minimum_version_available" ]] &&
		output_type="json" ||
		output_type="text"

	# get the requesting profile idx
	idxLookup profile_idx merged_ident[@] "$session_baseprofile_ident"

	# get the type of session being requested ("baseprofile" for mfasession, or "role" for rolesession)
	if [[ "${merged_type[$profile_idx]}" != "" ]]; then
		session_request_type="${merged_type[$profile_idx]}"
	fi

	if [[ "$session_request_type" == "baseprofile" ]]; then  # INIT BASEPROFILE MFASESSION ----------------------------

		getMaxSessionDuration session_duration "$session_baseprofile_ident" "baseprofile"

		echo -e "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${merged_ident[$profile_idx]}'${Color_Off} to start/renew an MFA session,\\n\
or leave empty (just press [ENTER]) to use the selected profile without the MFA.\\n"

		if [[ "${auto_persist_request}" == "false" ]]; then
			getMfaToken mfa_token "mfa"
		else  # this is a recursive req by rolesession init to acquire a parent
			  # baseprofile MFA session; do not allow skipping of the MFA token entry
			getMfaToken mfa_token "role"
		fi

		if [[ "$mfa_token" != "" ]]; then 

			acquireSession_result="$(aws --profile "${merged_ident[$profile_idx]}" sts get-session-token \
				--serial-number "${merged_mfa_arn[$profile_idx]}" \
				--duration "$session_duration" \
				--token-code "$mfa_token" \
				--output "$output_type")"

			if [[ "$DEBUG" == "true" ]]; then
				echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$profile_idx]}\" sts get-session-token --serial-number \"${merged_mfa_arn[$profile_idx]}\" --duration \"$session_duration\" --token-code \"$mfa_token\" --output \"$output_type\"':\\n${ICyan}${acquireSession_result}${Color_Off}"
			fi

			# exits on error
			checkAWSErrors "true" "$acquireSession_result" "${merged_ident[$profile_idx]}" "An error occurred while attempting to acquire the MFA session credentials; cannot continue!"

			# determines whether to print session details
			session_profile="true"

		else  # empty mfa_token

			if [[ "$DEBUG" == "true" ]]; then
				echo -e "\\n${Cyan}${On_Black}** Requesting baseprofile as-is (no MFA session initialized)${Color_Off}"
			fi

			AWS_PROFILE="${merged_ident[$profile_idx]}"

			# determines whether to print session details
			session_profile="false"
		fi

	elif [[ "$session_request_type" == "role" ]]; then  # INIT ROLESESSION --------------------------------------------
		# get the role's source_profile
		role_init_profile="${merged_role_source_profile_ident[$profile_idx]}"

		# does the source_profile have an MFA session?
		source_profile_has_session="${merged_has_session[${merged_role_source_profile_idx[$profile_idx]}]}"

		# is the MFA session valid?
		# (role profile IDX -> role source_profile IDX -> source profile's session IDX -> source profile's session status)
		source_profile_mfa_session_status="${merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$profile_idx]}]}]}"

		if [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&
			[[ "$source_profile_has_session" == "true" ]] &&
			[[ "$source_profile_mfa_session_status" == "valid" ]]; then
			# ROLE: MFA required, source profile has an active MFA

			# use the source profile's active MFA session to authenticate 
			role_init_profile="${merged_role_source_profile_ident[$profile_idx]}-mfasession"

		elif [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&
			( [[ "$source_profile_has_session" == "false" ]] ||
			[[ "$source_profile_mfa_session_status" != "valid" ]] ) &&  # includes expired, invalid, and unknown session statuses
			[[ "${merged_role_mfa_serial[$profile_idx]}" != "" ]]; then  # since the source_profile's merged_mfa_arn is acquired dynamically, the persistent merged_role_mfa_serial has a higher chance of being available (from run-to-run)
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

				# this is recursive; the third param requests silent auto persist
				acquireSession mfa_session_detail "${merged_role_source_profile_ident[$profile_idx]}" "true"

				# the aquireSession with "true" as the third param auto-persists the new
				# session so that it can be used here simply by referring to the ident
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

		elif [[ "${merged_role_mfa_required[$profile_idx]}" == "false" ]]; then
			# no MFA required, do not include MFA Arn in
			# the request, just init the role session

			token_switch=""
			serial_switch=""
		fi

		# generate '--external-id' switch if an exeternal ID has been defined in config
		if [[ "${merged_role_external_id[$profile_idx]}" != "" ]]; then
			external_id_switch="--external-id ${merged_role_external_id[$profile_idx]}"
		else
			external_id_switch=""
		fi

		getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role"

#todo: should an in-env only MFA session be taken into account when assuming a role? probably not...

		acquireSession_result="$(aws --profile $role_init_profile sts assume-role \
			$serial_switch $token_switch $external_id_switch \
			--role-arn "${merged_role_arn[$profile_idx]}" \
			--role-session-name "${merged_role_session_name[$profile_idx]}" \
			--duration-seconds $session_duration \
			--output $output_type)"

		if [[ "$DEBUG" == "true" ]]; then
			echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_ident[$profile_idx]}\" sts assume-role $serial_switch $token_switch $external_id_switch --role-arn \"${merged_role_arn[$profile_idx]}\" --role-session-name \"${merged_role_session_name[$profile_idx]}\" --duration-seconds \"$session_duration\" --output \"$output_type\"':\\n${ICyan}${acquireSession_result}${Color_Off}"
		fi

		# exits on error
		checkAWSErrors "true" "$acquireSession_result" "$role_init_profile" "An error occurred while attempting to acquire the role session credentials; cannot continue!"

		# determines whether to print session details
		session_profile="true"

	else  # NO SESSION INIT (should never happen; the session request type is "unknown", "mfasession", or "rolesession")

		echo -e "${BIRed}${On_Black}\
A $session_request_type cannot request a session (program error).\\n\
Cannot continue.${Color_Off}"

		exit 1
	fi

	# VALIDATE AND FINALIZE SESSION INIT ------------------------------------------------------------------------------

	# only process if a session was initialized; skip if user didn't
	# enter an MFA token (i.e., requested to use a baseprofile as-is)
	if [[ "${session_profile}" == "true" ]]; then

		if [[ "$output_type" == "json" ]]; then

			result_check="$(printf '\n%s\n' "$acquireSession_result" | jq -r .Credentials.AccessKeyId)"

		elif [[ "$output_type" == "text" ]]; then

			# strip extra spaces
			result="$(echo "$result" | xargs echo -n)"

			result_check="$(printf '%s' "$acquireSession_result" | awk '{ print $2 }')"
		fi

		# make sure valid credentials were received, then unpack;
		#  all session aws_access_key_id's start with "ASIA":
		#  https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/
		if [[ "$result_check" =~ ^ASIA ]]; then

			if [[ "$output_type" == "json" ]]; then
				AWS_ACCESS_KEY_ID="$(printf '\n%s\n' "$acquireSession_result" | jq -r .Credentials.AccessKeyId)"
				AWS_SECRET_ACCESS_KEY="$(printf '\n%s\n' "$acquireSession_result" | jq -r .Credentials.SecretAccessKey)"
				AWS_SESSION_TOKEN="$(printf '\n%s\n' "$acquireSession_result" | jq -r .Credentials.SessionToken)"
				AWS_SESSION_EXPIRY="$(printf '\n%s\n' "$acquireSession_result" | jq -r .Credentials.Expiration)"

			elif [[ "$output_type" == "text" ]]; then

				read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SESSION_EXPIRY <<< $(printf '%s' "$acquireSession_result" | awk '{ print $2, $4, $5, $3 }')
			fi

			if [[ "$session_request_type" == "baseprofile" ]]; then

				echo -e "${Green}${On_Black}MFA session token acquired.${Color_Off}\\n"
				# setting globals (depends on the use-case which one will be exported)
				AWS_PROFILE="${merged_ident[$profile_idx]}-mfasession"
				AWS_SESSION_IDENT="${merged_ident[$profile_idx]}-mfasession"

				AWS_SESSION_TYPE="mfasession"
		
			elif [[ "$session_request_type" == "role" ]]; then

				echo -e "${Green}${On_Black}Role session token acquired.${Color_Off}\\n"
				# setting globals (depends on the use-case which one will be exported)
				AWS_PROFILE="${merged_ident[$profile_idx]}-rolesession"
				AWS_SESSION_IDENT="${merged_ident[$profile_idx]}-rolesession"

				AWS_SESSION_TYPE="rolesession"
			fi

			AWS_SESSION_PARENT_IDX="${profile_idx}"

			if [[ "$auto_persist_request" == "true" ]]; then
				# auto-persist request for the MFA session initialized for the role session init
				echo -e "${Green}${On_Black}Requesting session persist.${Color_Off}\\n"
				persistSessionMaybe "${merged_ident[$profile_idx]}" "$AWS_SESSION_IDENT" "$acquireSession_result" "true"
			else
				# only set AWS_SESSION_INITIALIZED for the user-requested sessions
				# (i.e. do not set it for the persisted MFA session needed for the
				# role session init)
				AWS_SESSION_INITIALIZED="true"
			fi

			# export the session credentials for the remainder of this script
			export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
			export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
			export AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"

			# additional time calculations
			getRemaining session_seconds_remaining "${AWS_SESSION_EXPIRY}"
			getPrintableTimeRemaining AWS_SESSION_EXPIRY_PR "${session_seconds_remaining}"
			getRemaining AWS_SESSION_EXPIRY "${AWS_SESSION_EXPIRY}" "timestamp"

				## DEBUG
			if [[ "$DEBUG" == "true" ]]; then
				echo
				echo -e "${BIYellow}${On_Black}AWS_PROFILE: ${Yellow}${On_Black}${AWS_PROFILE}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SESSION_IDENT: ${Yellow}${On_Black}${AWS_SESSION_IDENT}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_ACCESS_KEY_ID: ${Yellow}${On_Black}${AWS_ACCESS_KEY_ID}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SECRET_ACCESS_KEY: ${Yellow}${On_Black}${AWS_SECRET_ACCESS_KEY}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SESSION_TOKEN: ${Yellow}${On_Black}${AWS_SESSION_TOKEN}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SESSION_EXPIRY: ${Yellow}${On_Black}${AWS_SESSION_EXPIRY} (in ${AWS_SESSION_EXPIRY_PR} from now)${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SESSION_TYPE: ${Yellow}${On_Black}${AWS_SESSION_TYPE}${Color_Off}"
				echo -e "${BIYellow}${On_Black}AWS_SESSION_PARENT_IDX: ${Yellow}${On_Black}${AWS_SESSION_PARENT_IDX}${Color_Off}"
				echo -e "${BIYellow}${On_Black}auto_persist_request: ${Yellow}${On_Black}${auto_persist_request}${Color_Off}"
				echo
			fi
			## END DEBUG

			eval "$1=\"${acquireSession_result}\""

		else  # the session token was not received

			if [[ "$session_request_type" == "baseprofile" ]]; then

				session_word="An MFA"

			elif [[ "$session_request_type" == "role" ]]; then

				session_word="A role"
			fi

			echo -e "${BIRed}${On_Black}\
$session_word session could not be initialized for the profile '${merged_ident[$profile_idx]}'.\\n\
Cannot continue.${Color_Off}\\n\\n"

			exit 1
		fi
#todo: should the baseprofile-only values be set here -- probably not, they're not of a "session"?
	fi  # close [[ "${session_profile}" == "true" ]]
}

# sets the output and the region for the given
# session ident (global transits are used)
setSessionOutputAndRegion() {
	# $1 is the session profile to act on
	# $2 (bool) persist output and region for the profile;
	#    "false" (or undef) only sets the vars in this script

	local output_region_profile_ident="$1"
	local persist="$2"
	[[ "${persist}" == "" ]] && persist="false"

	local add_region_prop="false"
	local set_new_region
	local profile_idx

	idxLookup profile_idx merged_ident[@] "$output_region_profile_ident"

	if [[ "${profile_idx}" != "" ]]; then
		# previously persisted, but it can be an older session

		if [[ "${merged_region[$profile_idx]}" != "" ]]; then
			# a persisted region exists for the session
			# profile of the same name, so we'll use it
			AWS_DEFAULT_REGION="${merged_region[$profile_idx]}"

		else
			# a persisted profile exists,
			# but the region wasn't part of it
			add_region_prop="true"
		fi
	else
		# not previously persisted, so add
		# (at this point we know a stub exists)
		add_region_prop="true"
	fi


	if [[ "$add_region_prop" == "true" ]]; then

		# does the parent have a region?
		if [[ "${merged_region[$AWS_SESSION_PARENT_IDX]}" != "" ]]; then
			# it's available so we'll use it!
			AWS_DEFAULT_REGION="${merged_region[$AWS_SESSION_PARENT_IDX]}"

		elif [[ "${default_region}" != "" ]]; then  # parent has no region.. maybe the default is available?
			# we're in luck, default is defined, so we'll use it!
			AWS_DEFAULT_REGION="${default_region}"	

		else
			# region is not available for this profile; warn
			
			AWS_DEFAULT_REGION="unavailable"

# 🚩FLAG >>> COULD THIS CHECK NOT BE CHECKED WHEN THE PROFILE IS SELECTED
#             SO THAT THE USER CAN AVOID TRYING TO START THE SESSION IF IT'S
#             ULTIMATELY INVALID?? And besides, how do you start a session
#             without the region def?? I don't think you can!
		
			echo "sorry, no region.. we're bailing out!"
			exit 1
		fi

	fi

	# REGION AND OUTPUT SOURCES
	# 
	# baseprofile -> config
	# mfa session -> host baseprofile config
	# role session -> host baseprofile config
	#
	# 1. determine if this is a persisted profile or a new session (token or not)
	# 2. if a session, determine if this is previously persisted (merge arrays)
	# 3a. if no previous persist (or property) look for the source (merge arrays)
	# 3b. if source is not avl, look for default (valid_default_exists -> deafult_region, default_output)
	# 3c. if default is not avl for output, use json (the default) for output
	#     if default is not avl for region, exit w/error

	# - when this function is reached, it's automatically a persisted profile (or, at least, a to-be-persisted profile)
	#   and stubs have created at this point (since this is called from persisteSessionMaybe)

	# AWS_SESSION_PARENT_IDX is available for the parent index
	# merged_region
	# merged_output
	# 
	# default_region
	# default_output

	# If the region and output format have not been set for this profile, set them.
	# For the parent/baseprofiles, use the defaults; for the MFA profiles use first
	# the base/parent settings if present, then the defaults if base/parent doesn't
	# have them.

	# retrieve parent profile region if an MFA profile
	if [[ "${baseprofile_region[$selprofile_idx]}" != "" &&
		  "${session_profile}" == "true" ]]; then

		set_new_region="${baseprofile_region[$selprofile_idx]}"

		echo -e "\\n
NOTE: Region had not been configured for the selected MFA profile;\\n\
      it has been set to same as the parent profile ('$set_new_region')."

	fi

	if [[ "${set_new_region}" == "" ]]; then
		if [[ "$default_region" != "" ]]; then
			set_new_region="${default_region}"
			echo -e "\\n
NOTE: Region had not been configured for the selected profile;\\n
      it has been set to the default region ('${default_region}')."
  		else
			echo -e "\\n${BIRed}${On_Black}\
NOTE: Region had not been configured for the selected profile\\n\
      and the defaults were not available (the baseprofiles:\\n\
      the default region; the MFA/role sessions: the region of\\n\
      the parent profile, then the default region). Cannot continue.\\n\\n\
      Please set the default region, or region for the profile\\n\
      (or the parent profile for MFA/role sessions) and try again."

  			exit 1
  		fi
	fi

	AWS_DEFAULT_REGION="${set_new_region}"
	if [[ "$mfa_token" == "" ]] ||
		( [[ "$mfa_token" != "" ]] && [[ "$persistent_MFA" == "true" ]] ); then
		
		aws configure --profile "${final_selection_ident}" set region "${set_new_region}"
	fi

	# retrieve parent profile output format if an MFA profile
	if [[ "${baseprofile_output[$selprofile_idx]}" != "" &&
		"${session_profile}" == "true" ]]; then
		set_new_output="${baseprofile_output[$selprofile_idx]}"
		echo -e "\
NOTE: The output format had not been configured for the selected MFA profile;\\n
      it has been set to same as the parent profile ('$set_new_output')."
	fi
	if [[ "${set_new_output}" == "" ]]; then
		set_new_output="${default_output}"
		echo -e "\
NOTE: The output format had not been configured for the selected profile;\\n
      it has been set to the default output format ('${default_output}')."
	fi
#todo^ was the default set, or is 'json' being used as the default internally?

	AWS_DEFAULT_OUTPUT="${set_new_output}"
	if [[ "$mfa_token" == "" ]] ||
		( [[ "$mfa_token" != "" ]] && 
		  [[ "$persistent_MFA" == "true" ]] ); then
		
		aws configure --profile "${final_selection_ident}" set output "${set_new_output}"
	fi
}


## END FUNCTIONS ======================================================================================================

## MAIN ROUTINE START =================================================================================================
## PREREQUISITES CHECK

# Check OS for some supported platforms
if exists uname ; then
	OSr="$(uname -a)"

	if [[ "$OSr" =~ .*Linux.*Microsoft.* ]]; then
		OS="WSL_Linux"
		has_brew="false"

	elif [[ "$OSr" =~ .*Darwin.* ]]; then
		OS="macOS"
	
		# check for brew
		brew_string="$(brew --version 2>&1 | sed -n 1p)"
	
		[[ "${brew_string}" =~ ^Homebrew ]] &&
			has_brew="true" ||
			has_brew="false"

	elif [[ "$OSr" =~ .*Linux.* ]]; then
		OS="Linux"
		has_brew="false"

	else
		OS="unknown"
		has_brew="false"
		echo
		echo "NOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM."
		echo
	fi
else 
	OS="unknown"
	has_brew="false"
fi

[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** OS: '${OS}', has_brew: '${has_brew}'${Color_Off}"

coreutils_status="unknown"
if  [[ "$OS" =~ Linux$ ]]; then

	if exist apt ; then
		install_command="apt"

		# do not run in WSL_Linux
		if [[ "$OS" == "Linux" ]]; then
			coreutils_status=$(dpkg-query -s coreutils 2>/dev/null | grep Status | grep -o installed)
		fi

	elif exists yum ; then
		install_command="yum"

		# do not run in WSL_Linux
		if [[ "$OS" == "Linux" ]] &&
			exists rpm; then
			coreutils_status=$(rpm -qa | grep -i ^coreutils | head -n 1)
		fi
	else
		install_command="unknown"
	fi

	# blank status == not installed; "unknown" == untested
	if [[ "${coreutils_status}" == "" ]]; then

		echo -e "\\n${BIRed}${On_Black}'coreutils' is required on Linux. Cannot continue.${Color_Off}\\nPlease install with your operating system's package manager, then try again.\\n\\n"

		if [[ "${install_command}" == "apt" ]]; then

			echo -e "Install with:\\nsudo apt update && sudo apt -y install coreutils\\n"

		elif [[ "${install_command}" == "yum" ]]; then

			echo -e "Install with:\\nsudo yum install -y coreutils\\n"
		fi

		exit 1
	fi

elif [[ "$OS" == "macOS" ]] &&
	[[ "$has_brew" == "true" ]]; then

	install_command="brew"
else
	install_command="unknown"
fi

[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** install_command: '${install_command}'${Color_Off}"

# is AWS CLI installed?
if ! exists aws ; then

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** NO awscli!${Color_Off}"

	if [[ "$OS" == "macOS" ]]; then

		printf "\\n\
***************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/install-macos.html\\n\
***************************************************************************************************************************\\n\\n"

	elif [[ "$OS" =~ Linux$ ]]; then

		printf "\\n\
***************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html\\n\
***************************************************************************************************************************\\n\\n"

	else

		printf "\\n\
******************************************************************************************************************************\\n\
This script requires the AWS CLI. See the details here: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html\\n\
******************************************************************************************************************************\\n\\n"

	fi

	exit 1
fi
[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** awscli detected!${Color_Off}"

filexit="false"
# check for ~/.aws directory
# if the custom config defs aren't in effect
if ( [[ "$AWS_CONFIG_FILE" == "" ]] ||
	[[ "$AWS_SHARED_CREDENTIALS_FILE" == "" ]] ) &&
	[[ ! -d ~/.aws ]]; then

	echo
	echo -e "${BIRed}${On_Black}\
AWSCLI configuration directory '~/.aws' is not present.${Color_Off}\\n\
Make sure it exists, and that you have at least one profile configured\\n\
using the 'config' and/or 'credentials' files within that directory.\\n"
	filexit="true"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ -f "$AWS_CONFIG_FILE" ]]; then

	active_config_file="$AWS_CONFIG_FILE"
	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A custom configuration file defined with AWS_CONFIG_FILE envvar in effect: '$AWS_CONFIG_FILE'${Color_Off}"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ ! -f "$AWS_CONFIG_FILE" ]]; then

	echo
	echo -e "${BIRed}${On_Black}\
The custom AWSCLI configuration file defined with AWS_CONFIG_FILE envvar,\\n\
'$AWS_CONFIG_FILE', was not found.${Color_Off}\\n\
Make sure it is present or purge the envvars with:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [[ -f "$CONFFILE" ]]; then
	active_config_file="$CONFFILE"

else
	echo
	echo -e "${BIRed}${On_Black}\
The AWSCLI configuration file '$CONFFILE' was not found.${Color_Off}\\n\
Make sure it and '$CREDFILE' files exist (at least one\\n\
configured baseprofile is requred for this script to be operational).\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"
fi

# SUPPORT CUSTOM CREDENTIALS FILE SET WITH ENVVAR
if [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[[ -f "$AWS_SHARED_CREDENTIALS_FILE" ]]; then

	active_credentials_file="$AWS_SHARED_CREDENTIALS_FILE"
	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar in effect: '$AWS_SHARED_CREDENTIALS_FILE'${Color_Off}"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[[ ! -f "$AWS_SHARED_CREDENTIALS_FILE" ]]; then

	echo
	echo -e "${BIRed}${On_Black}\
The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar,\\n\
'$AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\n\
Make sure it is present, or purge the envvar.\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [[ -f "$CREDFILE" ]]; then
	active_credentials_file="$CREDFILE"

else
	# assume any existing creds are in $CONFFILE;
	# create a shared credentials file stub for session creds
    touch "$CREDFILE"
    chmod 600 "$CREDFILE"

	active_credentials_file="$CREDFILE"

	echo
	echo -e "${BIWhite}${On_Black}\
NOTE: A shared credentials file ('~/.aws/credentials') was not found;\\n\
      assuming existing credentials are in the config file ('$CONFFILE').${Color_Off}\\n\\n\
NOTE: A blank shared credentials file ('~/.aws/credentials') was created\\n\
      as the session credentials will be stored in it."

fi

if [[ "$filexit" == "true" ]]; then

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Necessary config files not present; exiting!${Color_Off}"
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"

# make sure the selected CONFFILE has a linefeed in the end
c="$(tail -c 1 "$CONFFILE")"
if [[ "$c" != "" ]]; then
	echo "" >> "$CONFFILE"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Adding linefeed to '${CONFFILE}'${Color_Off}"
fi

# make sure the selected CREDFILE has a linefeed in the end
c="$(tail -c 1 "$CREDFILE")"
if [[ "$c" != "" ]]; then
	echo "" >> "$CREDFILE"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Adding linefeed to '${CONFFILE}'${Color_Off}"
fi

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

# label identifying regex for both CREDFILE and CONFFILE
# (allows illegal spaces for warning purposes)
label_regex='^[[:space:]]*\[[[:space:]]*(.*)[[:space:]]*\][[:space:]]*'

# regex for invalid headers (used for both CREDFILE and CONFFILE checks)
prespacecheck1_regex='^[[:space:]]*\[[[:space:]]+[^[:space:]]+'
# regex for invalid property entries (used for both CREDFILE and CONFFILE checks)
prespacecheck2_regex='^[[:space:]]+[^[:space:]]+'
prespace_check="false"

# regex for invalid labels (i.e. "[profile anyprofile]")
credentials_labelcheck_regex='^[[:space:]]*\[[[:space:]]*profile[[:space:]]+'
illegal_profilelabel_check="false"

if [[ $CREDFILE != "" ]]; then
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Starting credfile check ('${CREDFILE}')${Color_Off}"

	profile_ident_hold=""
	declare -a labels_for_dupes

	while IFS='' read -r line || [[ -n "$line" ]]; do

		if [[ "$line" =~ $label_regex ]]; then

			profile_ident="${BASH_REMATCH[1]}"

			# save labels for label dupes check
			labels_for_dupes[${#labels_for_dupes[@]}]="${profile_ident}"

			# check for disallowed spaces in front of the label 
			# or in front of the label name
			if [[ "$line" =~ $credentials_labelcheck_regex ]]; then
				illegal_profilelabel_check="true"
			fi
		fi

		if [[ "$profile_ident" != "" ]]; then
			profile_header_check="true"
			(( profile_count++ ))
		fi 

		if [[ "$profile_ident" =~ -mfasession|-rolesession$ ]]; then
			(( session_profile_count++ ))
		fi 

		if [[ "$line" =~ ^aws_access_key_id.* ]]; then 
			access_key_id_check="true"
		fi

		if [[ "$line" =~ ^aws_secret_access_key.* ]]; then
			secret_access_key_check="true"
		fi

		if	[[ "$line" =~ ^(cli_timestamp_format).* ]] ||
			[[ "$line" =~ ^(credential_source).* ]] ||
			[[ "$line" =~ ^(external_id).* ]] ||
			[[ "$line" =~ ^(mfa_serial).* ]] ||
			[[ "$line" =~ ^(mfa_arn).* ]] ||
			[[ "$line" =~ ^(output).* ]] ||
			[[ "$line" =~ ^(sessmax).* ]] ||
			[[ "$line" =~ ^(region).* ]] ||
			[[ "$line" =~ ^(role_arn).* ]] ||
			[[ "$line" =~ ^(ca_bundle).* ]] ||
			[[ "$line" =~ ^(source_profile).* ]] ||
			[[ "$line" =~ ^(role_session_name).* ]] ||
			[[ "$line" =~ ^(parameter_validation).* ]]; then 
	
			this_line_match="${BASH_REMATCH[1]}"			
			creds_unsupported_props="${creds_unsupported_props}      - ${this_line_match}\\n"
			conffile_props_in_credfile="true"
		fi

		if [[ "$line" =~ $prespacecheck1_regex ]] ||
			[[ "$line" =~ $prespacecheck2_regex ]]; then
			prespace_check="true"
		fi

		# check for dupes; exit if one is found
		dupesCollector "$profile_ident" "$line"

	done < "$CREDFILE"
fi

# check for duplicate profile labels and exit if any are found
exitOnArrDupes labels_for_dupes[@] "$CREDFILE" "credfile"
unset labels_for_dupes

if [[ "$prespace_check" == "true" ]]; then
	echo -e "\\n${BIRed}${On_Black}\
NOTE: One or more lines in '$CREDFILE' have spaces in front of them;\\n\
      they are not allowed as AWSCLI cannot parse the file as it is!${Color_Off}\\n
      Please edit the credentials file to remove the disallowed spaces and try again.\\n\\n\
Examples (OK):\\n\
--------------\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[some_other_profile]\\n\
aws_access_key_id=AKIA...\\n\
\\n\
Examples (NOT OK):\\n\
------------------\\n\
[ default]  <- no spaces within the label brackets!\\n\
  aws_access_key_id = AKIA...  <- no leading spaces!\\n\
\\n\
  [some_other_profile]  <- no leading spaces on the labels lines!\\n\
  aws_access_key_id=AKIA...  <- no spaces on the property lines!\\n"

      exit 1
fi

if [[ "$illegal_profilelabel_check" == "true" ]]; then
	echo -e "\\n${BIRed}${On_Black}\
NOTE: One or more of the profile labels in '$CREDFILE' have the keyword
      'profile' in the beginning. This is not allowed in the credentials file.${Color_Off}\\n\
      Please edit the '$CREDFILE' to correct the error(s) and try again!\\n\\n\
Examples (OK):\\n\
--------------\\n\
OK:\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[some_other_profile]\\n\
aws_access_key_id=AKIA...\\n\
\\n\
Examples (NOT OK):\\n\
------------------\\n\
[profile default]  <- no 'profile' keyword for the 'default' profile EVER!\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[profile some_other_profile] <- no 'profile' keyword for any profile in the credentials file!\\n\
aws_access_key_id=AKIA...\\n"

      exit 1
fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	# only one profile is present
	ONEPROFILE="true"
fi

if [[ "$conffile_props_in_credfile" == "true" ]]; then
	echo -e "\\n${BIWhite}${On_Black}\
NOTE: The credentials file ('$CREDFILE') contains the following properties\\n\
      only supported in the config file ('$CONFFILE'):\\n\\n\
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
prespace_check="false"

# regex for invalid labels ("[profile default]"); 
# any illegal spaces are ignored as it's a separate check
config_labelcheck1_regex='^[[:space:]]*\[[[:space:]]*profile[[:space:]]+default[[:space:]]*\]'
illegal_defaultlabel_check="false"
# regex for invalid labels ("[some_other_profile]");
# allows default to not flag all non-default labels;
# any illegal spaces are ignored as it's a separate check
config_labelcheck2_negative_regex='^[[:space:]]*\[[[:space:]]*(profile[[:space:]]+.*|default[[:space:]]*)\]'
illegal_profilelabel_check="false"

[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Checking for invalid labels in '${CONFFILE}'${Color_Off}"
profile_ident_hold=""
declare -a labels_for_dupes
while IFS='' read -r line || [[ -n "$line" ]]; do

	if [[ "$line" =~ $label_regex ]]; then

		profile_ident="${BASH_REMATCH[1]}"

		# save labels for label dupes check
		labels_for_dupes[${#labels_for_dupes[@]}]="${profile_ident}"

		if [[ "$line" =~ $config_labelcheck1_regex ]]; then
			illegal_defaultlabel_check="true"
		fi

		if ! [[ "$line" =~ $config_labelcheck2_negative_regex ]]; then
			illegal_profilelabel_check="true"
		fi
	fi

	if [[ "$profile_ident" != "" ]]; then
		profile_header_check="true"
		(( profile_count++ ))
	fi 

	if [[ "$profile_ident" =~ -mfasession|-rolesession$ ]]; then
		(( session_profile_count++ ))
	fi 

	if [[ "$line" =~ ^aws_access_key_id.* ]]; then 
		access_key_id_check="true"
	fi

	if [[ "$line" =~ ^aws_secret_access_key.* ]]; then
		secret_access_key_check="true"
	fi
	
	if [[ "$line" =~ $prespacecheck1_regex ]] ||
		[[ "$line" =~ $prespacecheck2_regex ]]; then
		prespace_check="true"
	fi

	# check for dupes; exit if one is found
	dupesCollector "$profile_ident" "$line"

done < "$CONFFILE"

# check for duplicate profile labels and exit if any are found
exitOnArrDupes labels_for_dupes[@] "$CONFFILE" "conffile"
unset labels_for_dupes

if [[ "$prespace_check" == "true" ]]; then
	echo -e "\\n${BIRed}${On_Black}\
NOTE: One or more lines in '$CONFFILE' have spaces in front of them;\\n\
      they are not allowed as AWSCLI cannot parse the file as it is!${Color_Off}\\n
      Please edit the configuration file to remove the disallowed\\n\
      spaces and try again.\\n\\n\
Examples:\\n\
---------\\n\
OK:\\n\
[default]\\n\
region = us-east-1\\n\
\\n\
[profile some_other_profile]\\n\
region=us-east-1\\n\\n\
NOT OK:\\n\
[ default]\\n\
  region = us-east-1\\n\
\\n\
  [profile some_other_profile]\\n\
  region=us-east-1"

      exit 1
fi

if [[ "$illegal_defaultlabel_check" == "true" ]]; then
	echo -e "\\n${BIRed}${On_Black}\
NOTE: The default profile label in '$CONFFILE' has the keyword 'profile'\\n\
      in the beginning. This is not allowed in the AWSCLI config file.${Color_Off}\\n\
      Please edit the '$CONFFILE' to correct the error and try again!\\n\\n\
An example:\\n\
-----------\\n\
OK:\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
NOT OK:\\n\
[profile default]\\n\
aws_access_key_id = AKIA...\\n"

      exit 1
fi

if [[ "$illegal_profilelabel_check" == "true" ]]; then
	echo -e "\\n${BIRed}${On_Black}\
NOTE: One or more of the profile labels in '$CONFFILE' are missing the keyword 'profile'\\n\
      from the beginning. This is not allowed in the config file.${Color_Off}\\n\
      NOTE: The 'default' profile is an exception; it may NOT have the 'profile' keyword).\\n\
      Please edit the '$CONFFILE' to correct the error(s) and try again!\\n\\n\
Examples:\\n\
---------\\n\
OK:\\n\
[profile not_the_default_profile]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
NOT OK:\\n\
[not_the_default_profile]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[profile default]\\n\
aws_access_key_id = AKIA...\\n"

      exit 1
fi

if [[ "$profile_count" -eq 0 ]] &&
	[[ "$session_profile_count" -gt 0 ]]; then

	echo
	echo -e "\\n${BIRed}${On_Black}\
THE ONLY CONFIGURED PROFILE WITH CREDENTIALS MAY NOT BE A SESSION PROFILE.${Color_Off}\\n\\n\
Please add credentials for at least one baseprofile, and try again.\\n"

	exit 1

fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	# only one profile is present
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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Checking for the default profile${Color_Off}"

	isProfileValid _ret "default"
	if [[ "${_ret}" == "false" ]]; then
		valid_default_exists="false"
		default_region=""
		default_output=""

		echo -e "${BIWhite}${On_Black}\
NOTE: The default profile is not present.${Color_Off}\\n\
      As a result the default parameters (region, output format)\\n\
      are not available and you need to also either define the\\n\
      profile in the environment (such as, using this script),\\n\
      or select the profile for each awscli command using\\n\
      the '--profile {some profile name}' switch.\\n"

	else

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** 'default' profile found${Color_Off}"
		valid_default_exists="true"

		# get default region and output format
		default_region="$(aws --profile default configure get region)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get region':\\n${ICyan}'${default_region}'${Color_Off}"

		default_output="$(aws --profile default configure get output)"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for 'aws --profile default configure get output':\\n${ICyan}'${default_output}'${Color_Off}"

	fi

	if [[ "$default_region" == "" ]]; then
		echo -e "${BIWhite}${On_Black}\
NOTE: The default region has not been configured.${Color_Off}\\n\
      You need to use the '--region {some AWS region}' switch\\n\
      for commands that require the region if the base/role profile\\n\
      in use doesn't have the region set. You can set the default region\\n\
      in '$CONFFILE', for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set region \"us-east-1\"${Color_Off}\\n
      (NOTE: do NOT use '--profile default' switch when configuring the defaults!)\\n"

	fi

	# warn if the default output doesn't exist; set to 'json' (the AWS default)
	if [[ "$default_output" == "" ]]; then
		# default output is not set in the config;
		# set the default to the AWS default internally 
		# (so that it's available for the MFA sessions)
		default_output="json"

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}default output for this script was set to: ${ICyan}json${Color_Off}"
		echo -e "\\n\
NOTE: The default output format has not been configured; the AWS default, 
      'json', is used. You can modify it, for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set output \"table\"${Color_Off}\\n
      (NOTE: do NOT use '--profile default' switch when configuring the defaults!)\\n"

	fi

	echo

	## FUNCTIONAL PREREQS PASSED; PROCEED WITH CUSTOM CONFIGURATION/PROPERTY READ-IN ----------------------------------

	# define profiles arrays, variables
	declare -a creds_ident
	declare -a creds_aws_access_key_id
	declare -a creds_aws_secret_access_key
	declare -a creds_aws_session_token
	declare -a creds_aws_session_expiry
	declare -a creds_type
	persistent_MFA="false"
	profiles_init=0
	creds_iterator=0
	unset dupes

	# an ugly hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	roles_in_credfile="false"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}ITERATING CREDFILE ---${Color_Off}"
	while IFS='' read -r line || [[ -n "$line" ]]; do
		
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}iterating credfile line: ${line}${Color_Off}"

		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			# don't increment on first pass
			# (to use index 0 for the first item)
			if [[ $profiles_init -eq 0 ]]; then
				creds_ident[$creds_iterator]="${_ret}"
				profiles_init=1
			elif [[ "${creds_ident[$creds_iterator]}" != "${_ret}" ]]; then
				((creds_iterator++))
				creds_ident[$creds_iterator]="${_ret}"
			fi
			
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}creds_iterator ${creds_iterator}: ${_ret}${Color_Off}"

			if [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -mfasession$ ]]; then

				creds_type[$creds_iterator]="mfasession"

			elif [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -rolesession$ ]]; then

				creds_type[$creds_iterator]="rolesession"
			else
				creds_type[$creds_iterator]="baseprofile"
			fi
		fi

		# aws_access_key_id
		[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_access_key_id[$creds_iterator]="${BASH_REMATCH[1]}"

		# aws_secret_access_key
		[[ "$line" =~ ^aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_secret_access_key[$creds_iterator]="${BASH_REMATCH[1]}"

		# aws_session_token
		[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			creds_aws_session_token[$creds_iterator]="${BASH_REMATCH[1]}"

		# aws_session_expiry
		[[ "$line" =~ ^aws_session_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			creds_aws_session_expiry[$creds_iterator]="${BASH_REMATCH[1]}"

		# role_arn (not stored; only for warning)
		if [[ "$line" =~ ^role_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			this_role="${BASH_REMATCH[1]}"

			echo -e "\\n${BIRed}${On_Black}\
NOTE: The role '${this_role}' is defined in the credentials\\n\
      file ('$CREDFILE') and will be ignored.${Color_Off}\\n\\n\
      The credentials file may only contain credentials;\\n\
      you should define roles in the config file ('$CONFFILE').\\n"

		fi

	done < "$CREDFILE"

	# duplicate creds_ident for profile stub check for persistence
	# (the original array gets truncated during merge)
	creds_ident_duplicate=("${creds_ident[@]}")

	# init arrays to hold profile configuration detail
	# (may also include credentials)
	declare -a confs_ident
	declare -a confs_aws_access_key_id
	declare -a confs_aws_secret_access_key
	declare -a confs_aws_session_token
	declare -a confs_aws_session_expiry
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
	unset dupes

#todo: detect profile dupes

	# read in the config file params
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}ITERATING CONFFILE ---${line}${Color_Off}"
	while IFS='' read -r line || [[ -n "$line" ]]; do

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}iterating conffile line: ${line}${Color_Off}"

		if [[ "$line" =~ ^\[[[:space:]]*profile[[:space:]]*(.*)[[:space:]]*\].* ]] ||
			[[ "$line" =~ ^\[[[:space:]]*(default)[[:space:]]*\].* ]]; then
			_ret="${BASH_REMATCH[1]}"

			# don't increment on first pass
			# (to use index 0 for the first item)
			if [[ $confs_init -eq 0 ]]; then
				confs_ident[$confs_iterator]="${_ret}"
				confs_init=1
			elif [[ "${confs_ident[$confs_iterator]}" != "${_ret}" ]]; then
				((confs_iterator++))
				confs_ident[$confs_iterator]="${_ret}"
			fi

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}confs_iterator ${confs_iterator}: ${_ret}${Color_Off}"

			# assume baseprofile type; this will be overridden for roles
			confs_type[$confs_iterator]="baseprofile"
		fi

		# aws_access_key_id
		[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_access_key_id[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_secret_access_key
		[[ "$line" =~ ^aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_secret_access_key[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_session_expiry (should always be blank in the config, but just in case)
		[[ "$line" =~ ^aws_session_expiry[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_aws_session_expiry[$confs_iterator]="${BASH_REMATCH[1]}"

		# aws_session_token
		[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] &&
			confs_aws_session_token[$confs_iterator]="${BASH_REMATCH[1]}"

		# ca_bundle
		[[ "$line" =~ ^ca_bundle[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_ca_bundle[$confs_iterator]="${BASH_REMATCH[1]}"

		# cli_timestamp_format
		[[ "$line" =~ ^cli_timestamp_format[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_cli_timestamp_format[$confs_iterator]="${BASH_REMATCH[1]}"

		# sessmax
		[[ "$line" =~ ^sessmax[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_sessmax[$confs_iterator]="${BASH_REMATCH[1]}"

		# mfa_arn
		[[ "$line" =~ ^mfa_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_mfa_arn[$confs_iterator]="${BASH_REMATCH[1]}"

		# output
		[[ "$line" =~ ^output[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_output[$confs_iterator]="${BASH_REMATCH[1]}"

		# parameter_validation
		[[ "$line" =~ ^parameter_validation[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_parameter_validation[$confs_iterator]="${BASH_REMATCH[1]}"

		# region
		[[ "$line" =~ ^region[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_region[$confs_iterator]="${BASH_REMATCH[1]}"

		# role_arn
		if [[ "$line" =~ ^role_arn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_arn[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		# (role) credential_source
		[[ "$line" =~ ^credential_source[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_credential_source[$confs_iterator]="${BASH_REMATCH[1]}"

		# (role) source_profile
		[[ "$line" =~ ^source_profile[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_source_profile_ident[$confs_iterator]="${BASH_REMATCH[1]}"

		# (role) external_id
		[[ "$line" =~ ^external_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_external_id[$confs_iterator]="${BASH_REMATCH[1]}"

		# (role) mfa_serial
		[[ "$line" =~ ^mfa_serial[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_mfa_serial[$confs_iterator]="${BASH_REMATCH[1]}"

		# role_session_name 
		[[ "$line" =~ ^role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_role_session_name[$confs_iterator]="${BASH_REMATCH[1]}"

	done < "$CONFFILE"

	# UNIFIED ARRAYS (config+credentials)
	declare -a merged_ident  # baseprofile name, *-mfasession, or *-rolesession
	declare -a merged_type  # baseprofile, role, mfasession, rolesession
	declare -a merged_aws_access_key_id
	declare -a merged_aws_secret_access_key
	declare -a merged_aws_session_token
	declare -a merged_has_in_env_session  # true/false for baseprofiles, roles, sessions: a more recent in-env session exists (i.e. expiry is further out)
	declare -a merged_has_session  # true/false (baseprofiles and roles only; not session profiles)
	declare -a merged_session_idx  # reference to the associated session profile index (baseprofile->mfasession or role->rolesession) in this array (from offline augment)
	declare -a merged_parent_idx  # idx of the parent (baseprofile or role) for mfasessions and rolesessions for easy lookup of the parent data (from offline augment)
	declare -a merged_sessmax  # optional profile-specific session length
	declare -a merged_mfa_arn  # baseprofile's configured vMFAd if one exists; like role's sessmax, this is written to config, and re-verified by dynamic augment
	declare -a merged_session_status  # valid/expired/unknown/invalid (session profiles only; valid/expired/unknown based on recorded time in offline, valid/unknown translated to valid/invalid in online augmentation)
	declare -a merged_aws_session_expiry  # both MFA and role session expiration timestamp 
	declare -a merged_session_remaining  # remaining seconds in session; automatically calculated for mfa and role profiles
	declare -a merged_ca_bundle
	declare -a merged_cli_timestamp_format
	declare -a merged_mfa_serial  # role's assigned mfa_serial (derived from its baseprofile, i.e. from merged_mfa_arn)
	declare -a merged_output
	declare -a merged_parameter_validation
	declare -a merged_region  # precedence: environment, baseprofile (for mfasessions, roles [via source_profile])

	# ROLE ARRAYS
	declare -a merged_role_arn  # this must be provided by the user for a valid role config
	declare -a merged_role_name  # this is discerned/set from the merged_role_arn
	declare -a merged_role_credential_source
	declare -a merged_role_external_id  # optional external id if defined
	declare -a merged_role_mfa_serial  # role's mfa_serial if set, triggers MFA request when the profile is referenced; acquired from the source_profile
	declare -a merged_role_session_name
	declare -a merged_role_source_profile_ident
	declare -a merged_role_source_profile_idx

	# DYNAMIC AUGMENT ARRAYS
	declare -a merged_baseprofile_arn  # based on get-caller-identity, this can be used as the validity indicator for the baseprofiles (combined with merged_session_status for the select_status)
	declare -a merged_baseprofile_operational_status  # ok/reqmfa/none/unknown based on 'iam get-access-key-last-used' (a 'valid' profile can be 'reqmfa' depending on policy; but shouldn't be 'none' or 'unknown' since 'sts get-caller-id' passed)
	declare -a merged_account_alias
	declare -a merged_account_id
	declare -a merged_username  # username derived from a baseprofile, or role name from a role profile
	declare -a merged_user_arn
	declare -a merged_role_source_username  # username for a role's source profile, derived from the source_profile (if avl)
	declare -a merged_role_mfa_required  # if a role profile has a functional source_profile, this is derived from get-role and query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"'

	# BEGIN CONF/CRED ARRAY MERGING PROCESS ---------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Creating merged arrays; importing config/creds file contents${Color_Off}"

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

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}merged itr ${itr}: ${merged_ident[$itr]}${Color_Off}"

	done

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Creating merged arrays; importing credentials-only contents${Color_Off}"

	# merge in possible credentials-only profiles as they
	# would not have been merged by the above process
	for ((itr=0; itr<${#creds_ident[@]}; ++itr))
	do
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}merge itr ${itr}...${Color_Off}"

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
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  .. merged ${merged_ident[$merge_idx]} at merge_idx ${merge_idx}${Color_Off}"
		fi

	done


	## awscli AND jq VERSION CHECK (this needs to happen for awscli after the config file checks) ---------------------

	# check for the minimum awscli version
	aws_version_raw="$(aws --version)"
	aws_version_string="$(printf '%s' "$aws_version_raw" | awk '{ print $1 }')"

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

	# check for jq, version
	jq_version_string="$(jq --version)"
	jq_available="false"
	jq_minimum_version_available="false"

	if [[ "$jq_version_string" =~ ^jq-.*$ ]]; then
		jq_available="true"	
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** 'jq' detected!${Color_Off}"

		[[ "$jq_version_string" =~ ^jq-([[:digit:]]+)\.([[:digit:]]+)$ ]] &&
			jq_version_major="${BASH_REMATCH[1]}"
			jq_version_minor="${BASH_REMATCH[2]}"

		if [ "${jq_version_major}" -ge 1 ] &&
			[ "${jq_version_minor}" -ge 5 ]; then

			jq_minimum_version_available="true"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** 'jq' version >1.5 available (${jq_version_string})${Color_Off}"
		fi
	fi

	[[ "$DEBUG" == "true" && "$jq_available" == "false" ]] && echo -e "\\n${BIYellow}${On_Black}** no 'jq'${Color_Off}"

	## BEGIN OFFLINE AUGMENTATION -------------------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Offline augmentation: PHASE I${Color_Off}"

	# SESSION PROFILES offline augmentation: discern and set merged_has_session,
	# merged_session_idx, and merged_role_source_profile_idx
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
	do

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  idx: $idx${Color_Off}"

		# set has_in_env_session to 'false' (augment changes this to "true"
		# only when the in-env session is more recent than the persisted one,
		# when the full secrets are in-env and only a stub is persisted,
		# or if the persisted session is expired/invalid); only set for 
		# baseprofiles and roles
		if [[ "${merged_type[$idx]}" =~ ^(baseprofile|role)$ ]]; then 
			has_in_env_session[$idx]="false"
		fi

		# set merged_has_in_env_session to "false" by default for all profile types
		merged_has_in_env_session[$idx]="false"

		for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))  # iterate all profiles for each profile
		do

			# add merged_has_session and merged_session_idx properties to the baseprofile and role indexes
			# to make it easier to generate the selection arrays; add merged_parent_idx property to the
			# mfasession and rolesession indexes to make it easier to set has_in_env_session
			if [[ "${merged_ident[$int_idx]}" =~ ^${merged_ident[$idx]}-(mfasession|rolesession)$ ]]; then
				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  found session for index $idx: session index $int_idx${Color_Off}"
				merged_has_session[$idx]="true"
				merged_session_idx[$idx]="$int_idx"
				merged_parent_idx[$int_idx]="$idx"
			fi

			# add merged_role_source_profile_idx property to easily access a role's source_profile data
			# (this assumes that the role has source_profile set in config; dynamic augment will happen
			# later unless '--quick' is used, and this will be repeated then)
			if [[ "${merged_role_source_profile_ident[$int_idx]}" == "${merged_ident[$idx]}" ]]; then
				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  found source profile for role index $idx: source index $int_idx${Color_Off}"
				merged_role_source_profile_idx[$idx]="$int_idx"
			fi

		done
	done


	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Offline augmentation: PHASE II${Color_Off}"

	# further offline augmentation: persistent profile standardization (relies on
	# merged_role_source_profile_idx assignment, above, having been completed)
	# including region, role_name, and role_session name
	# 
	# also determines/sets merged_session_status
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
	do

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}     Iterating merged ident ${merged_ident[$idx]}..${Color_Off}"

		# BASE PROFILES: Warn if neither the region is set
		# nor is the default region configured
		if [[ "${merged_type[$idx]}" == "baseprofile" ]] &&	# this is a baseprofile
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
			[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then # and the source_profile has a region set

			merged_region[$idx]="${merged_region[${merged_role_source_profile_idx[$idx]}]}"

			# make the role region persistent
			aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}"

		elif [[ "${merged_type[$idx]}" == "role" ]] &&  # this is a role
			[[ "${merged_region[$idx]}" == "" ]] &&     # a region has not been set for this role

			( ( [[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&				  # (the source_profile has been defined
			[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" == "" ]] ) ||  # .. but it doesn't have a region set
																						  #  OR
			[[ "${merged_role_source_profile_idx[$idx]}" == "" ]] ) &&					  # the source_profile has not been defined)
																						  #  AND
			[[ "$default_region" == "" ]]; then											  # .. and the default region is not available

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

			addConfigProp "$CONFFILE" "profile_${merged_ident[$idx]}" "role_session_name" "${merged_role_session_name[$idx]}" 
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
		if [[ "${merged_type[$idx]}" =~ ^(mfasession|rolesession)$ ]]; then
			
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}       calculating remaining seconds to the expiry timestamp of ${merged_aws_session_expiry[$idx]}..${Color_Off}"

			getRemaining _ret "${merged_aws_session_expiry[$idx]}"
			merged_session_remaining[$idx]="${_ret}"

			[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}       remaining session (seconds): ${_ret}${Color_Off}"

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

			[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}       session status set to: ${merged_session_status[$idx]}${Color_Off}"

		else
			# base & role profiles
			merged_session_status[$idx]=""
		fi

	done


	## END ROLE PROFILE OFFLINE AUGMENTATION --------------------------------------------------------------------------

	if [[ "$quick_mode" == "false" ]]; then
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** starting dynamic augment${Color_Off}"
		dynamicAugment
	else
		echo -e "${BIYellow}${On_Black}Quick mode selected; skipping the dynamic data augmentation.${Color_Off}"
	fi

	# check possible existing config in
	# the environment before proceeding
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** in-env credentials check${Color_Off}"
	checkInEnvCredentials


	## BEGIN SELECT ARRAY DEFINITIONS ---------------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** creating select arrays${Color_Off}"

	declare -a select_ident  # imported merged_ident
	declare -a select_type  # baseprofile or role
	declare -a select_status  # merged profile status (baseprofiles: operational status if known; role profiles: has a defined, operational source profile if known)
	declare -a select_merged_idx  # idx in the merged array (the key to the other info)
	declare -a select_has_session  # baseprofile or role has a session profile (active/valid or not)
	declare -a select_merged_session_idx  # index of the associated session profile
	declare -a select_display  # display backreference

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
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]}${Color_Off}"

			select_type[$select_idx]="baseprofile"
			(( baseprofile_count++ ))
			
			if [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" != "" ]]; then  # sts get-caller-identity had checked out ok for the baseprofile

				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" == "" ]]; then  # sts get-caller-identity had not worked on the baseprofile

				select_status[$select_idx]="invalid"

			else  # quick mode is active; baseprofile validity cannot be confirmed
				select_status[$select_idx]="unknown"
			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
echo "setting select_merged_session_idx to ${merged_session_idx[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"
			(( select_idx++ ))
		fi
	done

	# NOTE: select_idx is intentionally not reset
	#       before continuing below
	role_count="0"
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "role" ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]} (role)${Color_Off}"

			select_type[$select_idx]="role"
			(( role_count++ ))

			if [[ "${merged_role_arn[$idx]}" == "" ]]; then  # does not have an arn
				
				select_status[$select_idx]="invalid"

			elif [[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then  # does not have a source_profile

				select_status[$select_idx]="invalid_nosource"

			elif [[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&  # has a source_profile..
				[[ "${merged_baseprofile_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then  # .. but the source_profile is not valid

				select_status[$select_idx]="invalid_source"

			elif ( [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_mfa_required[$idx]}" == "false" ]] ) ||  # above OK + no MFA required (confirmed w/quick off)

				( [[ "$quick_mode" == "true" ]] &&
				[[ "${merged_role_mfa_serial[$idx]}" == "" ]] ); then  # above OK + no MFA required (based on absence of mfa_serial w/quick on)
				
				select_status[$select_idx]="valid"
	
			elif ( [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_mfa_required[$idx]}" == "true" ]] ) &&  # MFA is required..
				
				[[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # .. and the source_profile has a valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="valid"

			elif ( [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_role_mfa_required[$idx]}" == "true" ]] ) &&  # MFA is required..
				
				[[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then  # .. and the source_profile has no valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="invalid_mfa"

			else
				# quick_mode is active and MFA is required (plus a catch-all for other possible use-cases)
				select_status[$select_idx]="unknown"

			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
echo "setting select_has_session to ${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"
echo "setting select_merged_session_idx to ${merged_session_idx[$idx]}"

			(( select_idx++ ))
		fi
	done

	# DISPLAY THE PROFILE SELECT MENU, GET THE SELECTION --------------------------------------------------------------
	
	single_profile="false"

	# set default "false" for a single profile MFA request
	mfa_req="false"

	# determines whether to print session details
	session_profile="false"

	# displays a single profile + a possible associated persistent MFA session
	if [[ "${baseprofile_count}" -eq 0 ]]; then  # no baseprofiles found; bailing out									#1 - NO BASEPROFILES

		echo -e "${BIRed}${On_Black}No baseprofiles found. Cannot continue.${Color_Off}\\n\\n"

		exit 1

	elif [[ "${baseprofile_count}" -eq 1 ]] &&  # only one baseprofile is present (it may or may not have a session)..	#2 - ONE BASEPROFILE ONLY (W/WO SESSION)
		[[ "${role_count}" -eq 0 ]]; then  # .. and no roles; use the simplified menu
		
		single_profile="true"

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
Without a vMFAd the listed baseprofile can only be used as-is.\\n"

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
		else  # no baseprofiles in 'valid' (not quick) or 'unknown' (quick) status; bailing out

			echo -e "${BIRed}${On_Black}No valid baseprofiles found; please check your configuration files.\\nCannot continue.${Color_Off}\\n\\n"
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
			[[ "${merged_session_status[${select_merged_session_idx[0]}]}" =~ ^(valid|unknown)$ ]] ); then  # and it's ok by timestamp or the timestamp doesn't exist

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
					echo "Using the baseprofile as-is (no MFA).."
					selprofile="1"
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
						session_profile="true"
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

	# MULTI-PROFILE MENU
	# (roles are only allowed with at least one baseprofile)
	elif [[ "${baseprofile_count}" -gt 1 ]] ||   # more than one baseprofile is present..								#3 - >1 BASEPROFILES (W/WO SESSION), (≥1 ROLES)
												 # -or-
		( [[ "${baseprofile_count}" -ge 1 ]] &&  # one or more baseprofiles are present
		[[ "${role_count}" -ge 1 ]] ); then      # .. AND one or more session profiles are present

		if [[ "$quick_mode" == "true" ]]; then
			echo -e "${BIWhite}${On_Black}\\n** NOTE: Quick mode in effect; dynamic information is not available.${Color_Off}\\n\\n"
		fi

		# create the baseprofile selections
		echo
		echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS PROFILES: ${Color_Off}"
		echo

		# this may be different as this count will not include
		# the invalid, non-selectable profiles
		selectable_profiles_count=0
		display_idx=0

		for ((idx=0; idx<${#select_ident[@]}; ++idx))
		do
			if [[ "${select_type[$idx]}" == "baseprofile" ]] &&
				[[ "${select_status[$idx]}" =~ ^(valid|unknown)$ ]]; then

				# increment selectable_profiles_count
				(( selectable_profiles_count++ ))

				# make a more-human-friendly selector digit (starts from 1)
				(( display_idx++ ))

				select_display[$display_idx]="$idx"

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

					# print the baseprofile entry
					echo -en "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify})\\n"

					# print an associated session entry if one exist and is valid
					if [[ "${select_has_session[$idx]}" == "true" ]] &&
						[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" == "valid" ]]; then
						
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

						echo -e "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} ${Purple}${On_Black}(${pr_remaining} of the validity period remaining)${Color_Off}"
					fi

					echo

				else  # quick_mode is active; print abbreviated data

					# print the baseprofile
					echo -en "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off}\\n"

					# print an associated session if exist and not expired (i.e. 'valid' or 'unknown')
					if [[ "${select_has_session[$idx]}" == "true" ]] &&
						[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" != "expired" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

						echo -e "${BIWhite}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} (${pr_remaining} of the validity period remaining)"
					fi
					echo
				fi

			elif [[ "${select_type[$idx]}" == "baseprofile" ]] &&
				[[ "${select_status[$idx]}" == "invalid" ]]; then

				# print the invalid baseprofile notice
				echo -e "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (credentials have no access)"
				echo
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
					[[ "${select_status[$idx]}" =~ ^(valid|unknown)$ ]]; then

					# make a more-human-friendly selector digit (starts from 1)
					(( selval=idx+1 ))

					# increment selctable_profiles_count
					(( selectable_profiles_count++ ))

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
						if [[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" == "valid" ]]; then
							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

							echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} role session${Color_Off} (${pr_remaining} of the validity period remaining)"
						fi

					else  # quick_mode is active; print abbreviated data

						# print the role
						echo -en "${BIWhite}${On_Black}${selval}: ${select_ident[$idx]}${Color_Off}\\n"

						# print an associated session if exist and not expired (i.e. 'valid' or 'unknown')
						if [[ "${select_has_session[$idx]}" == "true" ]] &&
							[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" != "expired" ]]; then

							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

							echo -e "${BIWhite}${On_Black}${selval}s: ${select_ident[$idx]} role session${Color_Off} (${pr_remaining} of the validity period remaining)"
						fi
					fi

					echo

#todo: add remediation suggestions to the INVALID errors, when available
				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid" ]]; then

					# print the invalid role profile notice
					echo -e "INVALID: ${select_ident[$idx]} (the role profile is missing the role identifier ('role_arn'))"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_source" ]]; then

					# print the invalid role profile notice
					echo -e "INVALID: ${select_ident[$idx]} (configured source profile is non-functional)"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_nosource" ]]; then

					# print the invalid role profile notice
					echo -e "INVALID: ${select_ident[$idx]} (source profile not defined for the role)"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_mfa" ]]; then

					# print the invalid role profile notice
					echo -e "INVALID: ${select_ident[$idx]} (role requires MFA, but source profile has no vMFAd configured)"

				fi
			done
		fi

		if [[ "$quick_mode" == "false" ]]; then
			echo -e "\
You can switch to a baseprofile to use it as-is, start an MFA session for\\n\
a baseprofile if it is marked as \"vMFAd enabled\", or switch to an existing\\n\
active MFA or role session if any are available (indicated by the letter 's' after\\n\
the profile ID, e.g. '1s'; NOTE: the expired MFA and role sessions are not shown).\\n"

		else
			echo -e "\
You can switch to a baseprofile to use it as-is, start an MFA session for\\n\
a baseprofile if it has a vMFAd configured/enabled, or switch to an existing\\n\
active MFA or role session if any are available (indicated by the letter 's' after\\n\
the profile ID, e.g. '1s'; NOTE: the expired MFA and role sessions are not shown).\\n"

		fi

		# prompt for profile selection
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE ID:${Color_Off} "
		read -r selprofile
		echo -en  "\\n"

	fi  # end profile selections


	# PROCESS THE SELECTION -------------------------------------------------------------------------------------------

	if [[ "$selprofile" != "" ]]; then

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** selection received: ${selprofile}${Color_Off}"

		# check for a valid selection pattern
		if [[ ! "$selprofile" =~ ^[[:digit:]]+$ ]] &&
			[[ ! "$selprofile" =~ ^[[:digit:]]+s$ ]]; then 

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

			# first check that the selection is in range
			(( adjusted_display_idx=selprofile_selval-1 ))

			# does the selected profile exist? (this includes baseprofiles/roleprofiles);
			if [[ $adjusted_display_idx -gt $selectable_profiles_count ||
				$selprofile_idx -lt 0 ]]; then

				# a selection outside of the existing range was specified -> exit
				echo -e "There is no profile '${selprofile_selval}'. Cannot continue.\\n"
				exit 1
			fi

			# look up select index by the selected display index
			# (select index includes possible invalids and can thus be a different value)
			selprofile_idx="${select_display[$selprofile_selval]}"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** display index in select array: ${selprofile} (${select_ident[$selprofile_idx]})${Color_Off}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** selprofile_idx: ${selprofile_idx}${Color_Off}"

			# was an existing and valid session profile selected?
			[[ $selprofile =~ ^[[:digit:]]+(s)$ ]] &&
				selprofile_session_check="${BASH_REMATCH[1]}"

			if [[ "$selprofile_session_check" != "" ]] &&
				[[ "${select_has_session[$selprofile_idx]}" == "true" ]] &&
				# For this to be a valid session profile, it must be
				# in 'valid' (not quick) or 'unknown' (quick) status
				[[ "${merged_session_status[${select_merged_session_idx[$selprofile_idx]}]}" =~ ^(valid|unknown)$ ]]; then
				
				# A SESSION PROFILE WAS SELECTED <<<<<<<========================

				# get the session profile's index and ident (the selection digit is that of the base/role profile
				# while 's' is just an indicator for the session but it has no intrinsic profile reference)
				final_selection_idx="${select_merged_session_idx[$selprofile_idx]}"
				final_selection_ident="${merged_ident[$final_selection_idx]}"

				if [[ "$select_type" == "baseprofile" ]]; then  # select_type is 'baseprofile' or 'role' because selection menus don't have session details internally

					final_selection_type="mfasession"
					echo -e "SELECTED MFA SESSION PROFILE: ${final_selection_ident} (for the baseprofile \"${select_ident[$selprofile_idx]}\")"

				elif [[ "$select_type" == "role" ]]; then

					final_selection_type="rolesession"
					echo -e "SELECTED ROLE SESSION PROFILE: ${final_selection_ident} (for the role profile \"${select_ident[$selprofile_idx]}\")"

				fi

				# determines whether to print session details
				session_profile="true"

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
				final_selection_type="role"
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

	# ACQUIRE SESSION -------------------------------------------------------------------------------------------------

	# this is an MFA request (an vMFAd ARN exists but the MFA is not active; 
	# all baseprofile selections from the multi-menu are considered MFA requests
	# (user has the option to hit enter at the MFA code prompt to opt to use the
	# baseprofile as-is), while from the simplified single-profile menu the MFA
	# session request is explicit.

	if [[ "${merged_mfa_arn[$final_selection_idx]}" != "" ]] &&  # quick_mode off: merged_mfa_arn comes from dynamicAugment; quick_mode on: merged_mfa_arn comes from confs_mfa_arn (if avl)
		( ( [[ "$single_profile" == "false" ]] &&  # limit to multiprofiles
			[[ "$final_selection_type" == "baseprofile" ]] ) ||  # baseprofile selection from the multiprofile menu
			[[ "$mfa_req" == "true" ]] ); then  # 'mfa_req' is an explicit MFA request used by the simplified single baseprofile display 

		# BASEPROFILE MFA REQUEST

		# reassigned for better code narrative below
		AWS_BASEPROFILE_IDENT="$final_selection_ident"
		echo -e "\\nAcquiring an MFA session token for the baseprofile: ${BIWhite}${On_Black}${AWS_BASEPROFILE_IDENT}${Color_Off}..."

		# acquire MFA session
		acquireSession mfa_session_data "$AWS_BASEPROFILE_IDENT"

		# session_profile is set in acquireSession
		if [[ "${session_profile}" == "true" ]]; then

			# Add the '-mfasession' suffix to final_selection_ident,
			# for the session that was just created. Note that this
			# variable was updated globally in acquireSession
			final_selection_ident="$AWS_SESSION_IDENT"

			persistSessionMaybe "$AWS_BASEPROFILE_IDENT" "$AWS_SESSION_IDENT" "$mfa_session_data"

		else  # use a baseprofile as-is

			final_selection_ident="$AWS_BASEPROFILE_IDENT"

			# export final selection for subshells (awscli commands)
			export AWS_PROFILE="$AWS_BASEPROFILE_IDENT"
		fi

	elif [[ "$quick_mode" == "true" ]] &&  # quick mode is active..
		[[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&  # .. and there was no vMFAd ARN in the conf -- could be new or not [yet] persisted; notify and exit
		( ( [[ "$single_profile" == "false" ]] &&  # limit to multiprofiles
			[[ "$final_selection_type" == "baseprofile" ]] ) ||  # baseprofile selection from the multiprofile menu
			[[ "$mfa_req" == "true" ]] ); then  # single-profile MFA session req

#todo: should we do JIT lookup for the vMFAd Arn in quick mode rather than bail out here?
#      ... I think so! quick mode's goal is not to disable functionality but just to cut out
#      non-essential functionality, and this _is_ essential.

# if vMFAd is found JIT, this would start a session

		echo -e "\\n${BIRed}${On_Black}\
A vMFAd was not found for this profile in the quick mode!${Color_Off}\\n\
It is possible that the vMFAd has not been persisted yet; please run\\n\
this script first without the '--quick/-q' switch to confirm.\\n\
If a vMFAd is still unavailable, run 'enable-disable-vmfa-device.sh'\\n\
script to configure and enable the vMFAd for this profile, then try again.\\n"

		exit 1

	elif [[ "$quick_mode" == "false" ]] &&  # quick_mode is inactive..
		[[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&  # .. and no vMFAd is configured (no dynamically acquired vMFAd ARN); print a notice and exit
		( ( [[ "$single_profile" == "false" ]] &&  # limit to multiprofiles
		    [[ "$final_selection_type" == "baseprofile" ]] ) ||  # baseprofile selection from the multiprofile menu
		[[ "$mfa_req" == "true" ]] ); then  # single-profile MFA session req

		# determines whether to print session details
		session_profile="false"

		# switching the single-profile mfa_req to false since no vMFAd is available
		mfa_req="false"

		if [[ "$quick_mode" == "false" ]] &&  # quick_mode is inactive..
			[[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]]; then  # and the profile has no Arn.. this is an invalid profile!

			echo -e "\\n${BIRed}${On_Black}*** THIS PROFILE WAS FLAGGED INVALID, AND LIKELY WILL NOT WORK! ***${Color_Off}"

		else

		echo -e "\\n${BIRed}${On_Black}\
A vMFAd has not been configured/enabled for this profile!${Color_Off}\\n\
To start an MFA session for this profile you need to first run\\n\
'enable-disable-vmfa-device.sh' script to configure and enable\\n\
the vMFAd for this profile.\\n\
\\n\
However, you can use this baseprofile as-is without an MFA session.\\n\
Note that the effective security policy may limit your access\\n\
without an active MFA session."

		fi

		echo -e "\\nDo you want to use the baseprofile without an MFA session? ${BIWhite}${On_Black}Y/N${Color_Off}"
		yesNo yes_or_no

		if [[ "${yes_or_no}" == "no" ]]; then
			echo -e "\\n${BIWhite}${On_Black}Exiting.${Color_Off}\\n"
			exit 1
		fi

	elif [[ "$final_selection_type" == "role" ]]; then  # only selecting roles; all the critical parameters have already been 
														# checked for select_ arrays; invalid profiles cannot have final_ params.
		# ROLE SESSION REQUEST

		# reassigned for better code narrative below
		AWS_ROLE_PROFILE_IDENT="$final_selection_ident"
		echo -e "\\nAcquiring a role session token for the role profile: ${BIWhite}${On_Black}${AWS_ROLE_PROFILE_IDENT}${Color_Off}..."

		acquireSession roleSessionData "$AWS_ROLE_PROFILE_IDENT"

		# Add the '-rolesession' suffix to final_selection_ident,
		# as it's not there yet since the session was just created.
		# This is a global updated in acquireSession
		final_selection_ident="$AWS_SESSION_IDENT"

		persistSessionMaybe "$AWS_ROLE_PROFILE_IDENT" "$AWS_SESSION_IDENT" "$role_session_data"
	fi


	# USE THE PROFILE AS-IS (THIS MAY BE AN EXISTING ACTIVE SESSION, OR A NON-MFA BASEPROFILE) ------------------------

	# this is _not_ a new MFA session, so read in selected persistent values
	# (for the new MFA/role sessions they are already present as they were 
	# set in acquireSession as globals)

	if [[ "$mfa_token" == "" ]] ||
		( [[ "${single_profile}" == "true" ]] &&
		  [[ "${mfa_req}" == "false" ]] ); then

		AWS_ACCESS_KEY_ID="${merged_aws_access_key_id[${final_selection_idx}]}"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}aws_access_key_id retrieved from the merge arrays:\\n${ICyan}${AWS_ACCESS_KEY_ID}${Color_Off}"

		AWS_SECRET_ACCESS_KEY="${merged_aws_secret_access_key[${final_selection_idx}]}"
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}aws_access_key_id retrieved from the merge arrays:\\n${ICyan}${AWS_SECRET_ACCESS_KEY}${Color_Off}"
		
		if [[ "$session_profile" == "true" ]]; then  # this is a persistent MFA profile (a subset of [[ "$mfa_token" == "" ]])
			AWS_SESSION_TOKEN="${merged_aws_session_token[${final_selection_idx}]}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}aws_session_token retrieved from the merge arrays:\\n${ICyan}${AWS_SESSION_TOKEN}${Color_Off}"

			getSessionExpiry _ret "${final_selection_ident}"
			AWS_SESSION_EXPIRY="${_ret}"
			AWS_SESSION_TYPE="$final_selection_type"
		fi
	fi


	# OUTPUT SELECTED PROFILE/SESSION DETAILS -------------------------------------------------------------------------

#todo: delete these
AWS_DEFAULT_REGION="us-east-1"
AWS_DEFAULT_OUTPUT="table"

	if [[ "$session_profile" == "true" ]]; then
		getRemaining session_expiration_datetime "$AWS_SESSION_EXPIRY" "datetime"
	fi

#OS="WSL_Linux"

	echo -e "\\n\\n${BIWhite}${On_DGreen}                            * * * PROFILE DETAILS * * *                            ${Color_Off}\\n"

	if [[ "$session_profile" == "true" ]]; then
		echo -e "${BIWhite}${On_Black}MFA profile name: '${final_selection_ident}'${Color_Off}"
		echo
	else
		echo -e "${BIWhite}${On_Black}Profile name '${final_selection_ident}'${Color_Off}"
		echo -e "\\n${BIWhite}${On_Black}NOTE: This is not an MFA session!${Color_Off}"
		echo 
	fi
	echo -e "Region is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_REGION}${Color_Off}"
	echo -e "Output format is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_OUTPUT}${Color_Off}"
	echo

	if 	( [[ "$mfa_token" != "" ]] &&
		  [[ "$persistent_MFA" == "false" ]] ); then

		# always export secrets when initialized
		# a new session and selected not to persist

		secrets_out="true"

	else  # otherwise ask the user (since the profile is now always persisted)

		# Display the persistent profile's envvar details for export?
		read -s -p "$(echo -e "${BIWhite}${On_Black}Do you want to export the selected profile's secrets to the environment?${Color_Off} - ${BIWhite}${On_Black}[Y]${Color_Off}/[N] ")" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]] ||
			[[ $REPLY == "" ]]; then

			secrets_out="true"
		else
			secrets_out="false"
		fi
		echo
		echo
	fi

	if [[ "$mfa_token" != "" ]] && [[ "$persistent_MFA" == "false" ]]; then
		echo -e "${BIWhite}${On_Black}\
*** THIS IS A NON-PERSISTENT MFA SESSION! ${BIYellow}${On_Black}THE MFA SESSION ACCESS KEY ID,\\n\
    SECRET ACCESS KEY, AND THE SESSION TOKEN ARE *ONLY* SHOWN BELOW!${Color_Off}"

	fi

	echo -e "${BIWhite}${On_Black}THE ACTIVATION COMMANDS FOR THE SELECTED PROFILE:${Color_Off}"

	echo

	maclinux_adhoc_remove="env "
	maclinux_adhoc_add=""

	maclinux_exporter=""
	wincmd_exporter=""
	powershell_exporter=""

	if [[ "$secrets_out" == "false" ]]; then

		if [[ "$final_selection_ident" == "default" ]]; then
			
			# default profile requires no environment
			# selector to be effective
			echo "unset AWS_PROFILE"

			maclinux_exporter+="unset AWS_PROFILE; "

			maclinux_adhoc_remove+="-u AWS_PROFILE "

		elif [[ "$final_selection_ident" != "default" ]]; then

			# selector must be exported for all non-default
			# profiles when the secrets are not exported
			echo "export AWS_PROFILE=\"${final_selection_ident}\""

			maclinux_exporter+="export AWS_PROFILE=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_PROFILE=\"${final_selection_ident}\" "
		fi

		echo "unset AWS_PROFILE_IDENT"
		echo "unset AWS_ACCESS_KEY_ID"
		echo "unset AWS_SECRET_ACCESS_KEY"
		echo "unset AWS_DEFAULT_OUTPUT"
		echo "unset AWS_DEFAULT_REGION"
		echo "unset AWS_SESSION_EXPIRY"
		echo "unset AWS_SESSION_IDENT"
		echo "unset AWS_SESSION_TOKEN"
		echo "unset AWS_SESSION_TYPE"

		maclinux_exporter+="unset AWS_PROFILE_IDENT; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_DEFAULT_OUTPUT; unset AWS_DEFAULT_REGION; unset AWS_SESSION_EXPIRY; unset AWS_SESSION_IDENT; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE"

		maclinux_adhoc_remove+="-u AWS_PROFILE_IDENT -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_DEFAULT_OUTPUT -u AWS_DEFAULT_REGION -u AWS_SESSION_EXPIRY -u AWS_SESSION_IDENT -u AWS_SESSION_TOKEN -u AWS_SESSION_TYPE "

	else  # exporting the secrets

		# we'll never export AWS_PROFILE when the secrets are exported
		# to the environment; also note that AWS_PROFILE is *never 
		# exported to PowerShell our Windows CMD output, as those 
		# environments are not expected to have preconfigured profiles

		if [[ "$session_profile" == "true" ]]; then
			echo "export AWS_SESSION_IDENT=\"${final_selection_ident}\""

			maclinux_exporter+="export AWS_SESSION_IDENT=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_SESSION_IDENT=\"${final_selection_ident}\" "

		else
			echo "export AWS_PROFILE_IDENT=\"${final_selection_ident}\""

			maclinux_exporter+="export AWS_SESSION_IDENT=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_SESSION_IDENT=\"${final_selection_ident}\" "

		fi

		echo "export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\""
		echo "export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\""
		echo "export AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\""
		echo "export AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\""

		maclinux_exporter+="export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\"; export AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\"; "

		maclinux_adhoc_add+="AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\" AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\" AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\" AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\" "

		if [[ "$session_profile" == "true" ]]; then
			echo "export AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\""
			echo "export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\""
			echo "export AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\""
			echo "unset AWS_PROFILE_IDENT"
			echo "unset AWS_PROFILE"

			maclinux_exporter+="export AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\"; export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"; export AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\"; unset AWS_PROFILE; unset AWS_PROFILE_IDENT"

			maclinux_adhoc_remove+="-u AWS_PROFILE -u AWS_PROFILE_IDENT "
			maclinux_adhoc_add+="AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\" AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\" AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\""
		else
			echo "unset AWS_SESSION_EXPIRY"
			echo "unset AWS_SESSION_IDENT"
			echo "unset AWS_SESSION_TOKEN"
			echo "unset AWS_SESSION_TYPE"
			echo "unset AWS_PROFILE"

			maclinux_exporter+="unset AWS_SESSION_EXPIRY; unset AWS_SESSION_IDENT; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE; unset AWS_PROFILE"

			maclinux_adhoc_remove+="-u AWS_SESSION_EXPIRY -u AWS_SESSION_IDENT -u AWS_SESSION_TOKEN -u AWS_SESSION_TYPE -u AWS_PROFILE"
		fi
	fi

	maclinux_adhoc_exporter="${maclinux_adhoc_remove} ${maclinux_adhoc_add}"

	# Windows command prompt and PowerShell are not expected to have
	# configured profiles so a complete profile w/secrets is always exported
	if [[ "$session_profile" == "false" ]]; then
		wincmd_exporter+="set AWS_PROFILE=&&set AWS_SESSION_EXPIRY=&&set AWS_SESSION_IDENT=&&set AWS_SESSION_TOKEN=&&set AWS_SESSION_TYPE=&&set AWS_PROFILE_IDENT=${final_selection_ident}&&"
		powershell_exporter+="\$env:AWS_PROFILE=\"\"; \$env:AWS_SESSION_EXPIRY=\"\"; \$env:AWS_SESSION_IDENT=\"\"; \$env:AWS_SESSION_TOKEN=\"\"; \$env:AWS_SESSION_TYPE=\"\"; \$env:AWS_PROFILE_IDENT=\"${final_selection_ident}\"; "
	else  # session
		wincmd_exporter+="set AWS_PROFILE=&&set AWS_PROFILE_IDENT=&&set AWS_SESSION_EXPIRY=${session_expiration_datetime}&&set AWS_SESSION_IDENT=${final_selection_ident}&&set AWS_SESSION_TYPE=${AWS_SESSION_TYPE}&&set AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}&&"
		powershell_exporter+="\$env:AWS_PROFILE=\"\"; \$env:AWS_PROFILE_IDENT=\"\"; \$env:AWS_SESSION_EXPIRY=\"${session_expiration_datetime}\"; \$env:AWS_SESSION_IDENT=\"${final_selection_ident}\"; \$env:AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\"; \$env:AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"; "
	fi
	wincmd_exporter+="set AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}&&set AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}&&set AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}&&set AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
	powershell_exporter+="\$env:AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; \$env:AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; \$env:AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\"; \$env:AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\""


	# DISPLAY THE ACTIVATION STRINGS ----------------------------------------------------------------------------------

	if [[ "$OS" == "macOS" ]] ||
		[[ "$OS" =~ Linux$ ]]; then 

		echo -e "\\n${BIWhite}${On_Black}\
To use this selected profile ad-hoc to bypass the currently effective profile for a single command without\\n\
modifying the environment permanently, use the following prefix in the bash shell (macOS, Linux, WSL Linux):${Color_Off}\\n"
		echo -e "$maclinux_adhoc_exporter ${BIWhite}${On_Black}{your command here}${Color_Off}"

		echo -e "\\n${BIYellow}${On_Black}\
To activate this selected profile permanently in the bash shell (macOS, Linux, WSL Linux)\\n\
SIMPLY PASTE THE FOLLOWING AT PROMPT AND HIT [ENTER]!${Color_Off}\\n"
		echo -e "${Yellow}${On_Black}$maclinux_exporter${Color_Off}"

		if [[ "$OS" == "WSL_Linux" ]]; then

			echo -e "\\n${Cyan}${On_Black}\
Since you're using Windows bash shell (\"WSL bash\"), exports for Windows Powershell and\\n\
Windows command prompt are also provided. Simply paste one of the following into the respective\\n\
environment and hit [Enter], and the selected profile will be active in that environment:${Color_Off}\\n"

			echo -e "${BICyan}${On_Black}Windows Powershell:${Color_Off}\\n"
			echo -e "${Cyan}${On_Black}$powershell_exporter${Color_Off}"

			echo -e "\\n${BICyan}${On_Black}Windows command prompt:${Color_Off}\\n"
			echo -e "${Cyan}${On_Black}$wincmd_exporter${Color_Off}\\n"
		fi

		echo -e "\\n${BIRed}${On_Black}\
*** YOUR SELECTED PROFILE IS NOT EFFECTIVE UNTIL YOU ACTIVATE IT AS INSTRUCTED ABOVE! ***${Color_Off}\\n"

	# COPY ACTIVATION PROFILE TO THE CLIPBOARD ------------------------------------------------------------------------

		if [[ "$OS" == "macOS" ]] ||
			( [[ "$OS" == "Linux" ]] &&
			exists xclip ); then

			if [[ "$OS" == "Linux" ]] &&
				exists xclip; then

				echo -n "Xclip found. "
			fi

			export_this=""
			echo "Which export string do you want on your clipboard for easy pasting?"
			read -s -p "$(echo -e "Set [E]nvironment, export for [A]d-hoc use, or [D]o not copy? ${BIWhite}${On_Black}[E]${Color_Off}/A/D ")" -n 1 -r
			echo
			if [[ $REPLY =~ ^[Ee]$ ]] ||
				[[ $REPLY == "" ]]; then

				export_this="$maclinux_exporter"
				export_string="Set Environment"
				
			elif [[ $REPLY =~ ^[Aa]$ ]]; then

				export_this="$maclinux_adhoc_exporter"
				export_string="Ad-hoc Use"

			else
				echo
			fi

			# the actual export
			if [[ "$export_this" != "" ]]; then

				if [[ "$OS" == "macOS" ]]; then

					echo -n "$export_this" | pbcopy

				elif [[ "$OS" == "Linux" ]]; then

					echo -n "$export_this" | xclip -i
					xclip -o | xclip -sel clip
				fi

				echo -e "\\n${BIGreen}${On_Black}The $export_string string has been copied on your clipboard.${Color_Off}\\nNow paste it at the prompt!"

#todo: add note for xclip users about the correct clipboard selection

			fi

		elif [[ "$OS" == "Linux" ]] &&
			! exists xclip; then

			echo -e "\
** NOTE: If you're using an X GUI on Linux, install 'xclip' to have\\n\
         the activation command copied to the clipboard automatically!"

		fi
	fi

	if [[ "$OS" == "WSL_Linux" ]]; then

		echo -e "\
Which export string do you want on your clipboard for easy pasting?\\n\
Note that the clipboard is shared between WSL bash and Windows otherwise."
		read -s -p "$(echo -e "Set Environment in [B]ash, [P]owerShell, or in Windows [C]ommand Prompt;\\nexport for bash [A]d-hoc use, or [D]o not copy? ${BIWhite}${On_Black}[B]${Color_Off}/P/D/C/A/D ")" -n 1 -r
		echo

		export_this=""
		if [[ $REPLY =~ ^[Bb]$ ]] ||
			[[ $REPLY == "" ]]; then

			export_this="$maclinux_exporter"
			export_string="Set WSL Bash Environment"

		elif [[ $REPLY =~ ^[Pp]$ ]]; then

			export_this="$powershell_exporter"
			export_string="Set PowerShell Environment"

		elif [[ $REPLY =~ ^[Cc]$ ]]; then

			export_this="$wincmd_exporter"
			export_string="Set Windows Command Prompt Environment"
			
		elif [[ $REPLY =~ ^[Aa]$ ]]; then

			export_this="$maclinux_adhoc_exporter"
			export_string="Bash Ad-hoc Use"
		else
			echo
		fi

		# the actual export
		if [[ "$export_this" != "" ]]; then
			echo "${export_this}"|clip.exe

			echo -e "\\n${BIGreen}${On_Black}The $export_string string has been copied on your clipboard.${Color_Off}\\nNow paste it at the prompt!"
		fi
	fi
	echo
fi
