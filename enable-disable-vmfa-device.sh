#!/usr/bin/env bash

################################################################################
# version 2.1.0 - 22 January 2019 - MIT license
# 
# Copyright 2019 Ville Walveranta / 605 LLC
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################

# NOTE: Debugging mode prints the secrets on the screen!
DEBUG="false"

# enable debugging with '-d' or '--debug' command line argument..
[[ "$1" == "-d" || "$1" == "--debug" ]] && DEBUG="true"
# .. or by uncommenting the line below:
#DEBUG="true"

echo -e "Starting..."
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
MFA_SESSION_LENGTH_IN_SECONDS="32400"

# Define the standard locations for the AWS credentials and
# config files; these can be statically overridden with 
# AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE envvars
# (this script will override these envvars only if the 
# "[default]" profile in the defined custom file(s) is
# defunct, thus reverting to the below default locations).
CONFFILE="$HOME/.aws/config"
CREDFILE="$HOME/.aws/credentials"

# The minimum time required (in seconds) remaining in
# an MFA or a role session for it to be considered valid
VALID_SESSION_TIME_SLACK="300"

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
	# $1 is the command being checked

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function exists] command: ${1}${Color_Off}"

	# returns a boolean
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

# precheck envvars for existing/stale session definitions
env_aws_status="unknown"  # unknown until status is actually known, even if it is 'none'
env_aws_type=""
checkInEnvCredentials() {

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function checkInEnvCredentials]${Color_Off}"

	local _ret
	local this_session_expired="unknown"	# marker for AWS_SESSION_EXPIRY ('unknown' remains only if absent or corrupt)
	local active_env="false"				# any AWS_ envvars present in the environment
	local env_selector_present="false"		# AWS_PROFILE present?
	local env_secrets_present="false"		# are [any] in-env secrets present?
	local active_env_session="false"		# an apparent AWS session (mfa or role) present in the env (a token is present)
	local expired_word=""
	local profile_prefix=""

	# COLLECT THE AWS_ ENVVAR DATA

	ENV_AWS_PROFILE="$(env | grep AWS_PROFILE)"
	if [[ "$ENV_AWS_PROFILE" =~ ^AWS_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_PROFILE="${BASH_REMATCH[1]}"
		active_env="true"
		env_selector_present="true"
	else
		unset ENV_AWS_PROFILE
	fi

	ENV_AWS_PROFILE_IDENT="$(env | grep AWS_PROFILE_IDENT)"
	if [[ "$ENV_AWS_PROFILE_IDENT" =~ ^AWS_PROFILE_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_PROFILE_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_PROFILE_IDENT
	fi

	ENV_AWS_SESSION_IDENT="$(env | grep AWS_SESSION_IDENT)"
	if [[ "$ENV_AWS_SESSION_IDENT" =~ ^AWS_SESSION_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_SESSION_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SESSION_IDENT
	fi

	ENV_AWS_ACCESS_KEY_ID="$(env | grep AWS_ACCESS_KEY_ID)"
	if [[ "$ENV_AWS_ACCESS_KEY_ID" =~ ^AWS_ACCESS_KEY_ID[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_ACCESS_KEY_ID="${BASH_REMATCH[1]}"
		active_env="true"
		env_secrets_present="true"
	else
		unset ENV_AWS_ACCESS_KEY_ID
	fi

	ENV_AWS_SECRET_ACCESS_KEY="$(env | grep AWS_SECRET_ACCESS_KEY)"
	if [[ "$ENV_AWS_SECRET_ACCESS_KEY" =~ ^AWS_SECRET_ACCESS_KEY[[:space:]]*=[[:space:]]*(.*)$ ]]; then 
		ENV_AWS_SECRET_ACCESS_KEY="${BASH_REMATCH[1]}"
		ENV_AWS_SECRET_ACCESS_KEY_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
	else
		unset ENV_AWS_SESSION_TOKEN
	fi

	ENV_AWS_SESSION_TOKEN="$(env | grep AWS_SESSION_TOKEN)"
	if [[ "$ENV_AWS_SESSION_TOKEN" =~ ^AWS_SESSION_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TOKEN="${BASH_REMATCH[1]}"
		ENV_AWS_SESSION_TOKEN_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
		active_env_session="true"
	else
		unset 
	fi

	ENV_AWS_SESSION_TYPE="$(env | grep AWS_SESSION_TYPE)"
	if [[ "$ENV_AWS_SESSION_TYPE" =~ ^AWS_SESSION_TYPE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TYPE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SESSION_TYPE
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
	else
		unset ENV_AWS_SESSION_EXPIRY
	fi

	ENV_AWS_DEFAULT_REGION="$(env | grep AWS_DEFAULT_REGION)"
	if [[ "$ENV_AWS_DEFAULT_REGION" =~ ^AWS_DEFAULT_REGION[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_REGION="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_DEFAULT_REGION
	fi

	ENV_AWS_DEFAULT_OUTPUT="$(env | grep AWS_DEFAULT_OUTPUT)"
	if [[ "$ENV_AWS_DEFAULT_OUTPUT" =~ ^AWS_DEFAULT_OUTPUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_OUTPUT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_DEFAULT_OUTPUT
	fi

	ENV_AWS_CA_BUNDLE="$(env | grep AWS_CA_BUNDLE)"
	if [[ "$ENV_AWS_CA_BUNDLE" =~ ^AWS_CA_BUNDLE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CA_BUNDLE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_CA_BUNDLE
	fi

	ENV_AWS_SHARED_CREDENTIALS_FILE="$(env | grep AWS_SHARED_CREDENTIALS_FILE)"
	if [[ "$ENV_AWS_SHARED_CREDENTIALS_FILE" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SHARED_CREDENTIALS_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SHARED_CREDENTIALS_FILE
	fi

	ENV_AWS_CONFIG_FILE="$(env | grep AWS_CONFIG_FILE)"
	if [[ "$ENV_AWS_CONFIG_FILE" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CONFIG_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_CONFIG_FILE
	fi

	ENV_AWS_METADATA_SERVICE_TIMEOUT="$(env | grep AWS_METADATA_SERVICE_TIMEOUT)"
	if [[ "$ENV_AWS_METADATA_SERVICE_TIMEOUT" =~ ^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_METADATA_SERVICE_TIMEOUT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_METADATA_SERVICE_TIMEOUT
	fi

	ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS="$(env | grep AWS_METADATA_SERVICE_NUM_ATTEMPTS)"
	if [[ "$ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS" =~ ^AWS_METADATA_SERVICE_NUM_ATTEMPTS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS
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
	# 3a. INVALID expired named profile with differing secrets (select-diff-session)
	# 3b. VALID named role session profile with differing secrets (select-diff-rolesession)
	# 3c. VALID named role session profile with differing secrets (select-diff-mfasession)
	# 3d. INVALID named session profile with differing secrets (select-diff-session)
	# 3e. VALID (assumed) named session profile with differing secrets (select-diff-session)
	# 
	# 4a. VALID (assumed) named baseprofile with differing secrets (select-diff-second-baseprofile)
	# 4b. VALID (assumed) named baseprofile with differing secrets (select-diff-rotated-baseprofile)
	# 4c. INVALID named baseprofile with differing secrets (select-diff-baseprofile)
	#
	# 5a. INVALID in-env session profile (AWS_PROFILE points to a non-existent persisted profile)
	# 5b. INVALID in-env baseprofile (AWS_PROFILE points to a non-existent persisted profile)
	# 5c. INVALID in-env selector only (AWS_PROFILE points to a non-existent persisted profile)
	# 
	# --UNNAMED ENV PROFILE--
	# 
	# 6a. VALID ident/unident, complete baseprofile (unident-baseprofile)
	# 6b. INVALID ident/unident, complete baseprofile (unident-baseprofile)
	# 6c. UNCONFIRMED ident/unident, complete baseprofile (unident-baseprofile)
	# 6d. INVALID (expired) ident/unident, complete session profile (unident-session)
	# 6e. VALID ident/unident, complete role session profile (unident-rolesession)
	# 6f. VALID ident/unident, complete MFA session profile (unident-mfasession)
	# 6g. VALID ident/unident, complete session profile (unident-session)
	# 
	# 7.  NO IN-ENVIRONMENT AWS PROFILE OR SESSION

	if [[ "$active_env" == "true" ]]; then  # some AWS_ vars present in the environment

		# BEGIN NAMED IN-ENV PROFILES

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
					# baseprofile select validity
					if [[ "${merged_baseprofile_arn[$env_profile_idx]}" != "" ]]; then  # 1d: the corresponding persisted baseprofile is valid
						env_aws_status="valid"
					else  # 1e: the corresponding persisted baseprofile is invalid
						env_aws_status="invalid"
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
						if [[ "${merged_baseprofile_arn[$env_profile_idx]}" != "" ]]; then  # 2d: the corresponding persisted baseprofile is valid
							env_aws_status="valid"
						else  # 2e: the corresponding persisted baseprofile is invalid
							env_aws_status="invalid"
						fi
					fi

				elif [[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] &&	 # this is a named session whose AWS_ACCESS_KEY_ID differs from that of the corresponding
					[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]] &&  #  persisted profile (this is known because of the previous condition did not match);
					[[ "$ENV_AWS_SESSION_TOKEN" != "" ]]; then   #  possibly a more recent session which wasn't persisted; verify

					env_aws_type="select-diff-session"
					
					# mark expired named in-env session invalid
					if [[ "$this_session_expired" == "true" ]]; then  # 3a: the named, diff in-env session has expired (cannot use differing persisted profile data)
						env_aws_status="invalid"

					elif [[ "$this_session_expired" == "false" ]]; then 

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
						fi

					fi

					# NAMED IN-ENV SESSIONS, TYPE DETERMINED; ADD A REFERENCE MARKER IF IN-ENV SESSION IS NEWER

					if [[ "$env_aws_status" == "valid" ]]; then

						if [[ "$this_iam_name" == "${merged_username[$env_profile_idx]}" ]] && 	# confirm that the in-env session is actually for the same profile as the persisted one
																								#  NOTE: this doesn't distinguish between a baseprofile and an MFA session!

							[[ "${merged_aws_session_token[$env_profile_idx]}" != "" ]] &&		# make sure the corresponding persisted profile is also a session (i.e. has a token)

							[[ "$ENV_AWS_SESSION_EXPIRY" != "" &&  														# in-env expiry is set
							   "${merged_aws_session_expiry[$env_profile_idx]}" != "" &&								# the persisted profile's expiry is also set
							   "${merged_aws_session_expiry[$env_profile_idx]}" -lt "$ENV_AWS_SESSION_EXPIRY" ]]; then	# and the in-env expiry is more recent
				
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

		# BEGIN IDENT/UNIDENT (BUT UNNAMED, i.e. NO AWS_PROFILE) IN-ENV PROFILES

		elif [[ "$env_selector_present" == "false" ]] &&
			[[ "$env_secrets_present" == "true" ]] &&
			[[ "$active_env_session" == "false" ]]; then

			# THIS IS AN UNNAMED BASEPROFILE

			# is the referential ident present?
			if [[ "ENV_AWS_PROFILE_IDENT" != "" ]]; then
				env_aws_type="ident-baseprofile"
			else
				env_aws_type="unident-baseprofile"
			fi

			# get Arn for the ident/unident in-env baseprofile
			getProfileArn _ret

			if [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then  # valid 6a: an ident/unident, valid baseprofile
				this_iam_name="${BASH_REMATCH[1]}"
				env_aws_status="valid"

			else  # 6b: an invalid ident/unident baseprofile
				env_aws_status="invalid"
			fi

		elif [[ "$env_selector_present" == "false" ]] &&
			[[ "$env_secrets_present" == "true" ]] &&
			[[ "$active_env_session" == "true" ]]; then

			# THIS IS AN UNNAMED SESSION PROFILE

			# is the referential ident present?
			if [[ "$ENV_AWS_SESSION_IDENT" != "" ]]; then
				env_aws_type="ident-session"
			else
				env_aws_type="unident-session"
			fi

			if [[ "$this_session_expired" == "true" ]]; then  # 6d: an invalid (expired) ident/unident session 
				env_aws_status="invalid"

			else  # the ident/unident, in-env session hasn't expired according to ENV_AWS_SESSION_EXPIRY

				# get Arn for the ident/unident in-env session
				getProfileArn _ret

				if [[ "${_ret}" =~ ^arn:aws:sts::[[:digit:]]+:assumed-role/([^/]+) ]]; then  # 6e: an ident/unident, valid rolesession
					this_iam_name="${BASH_REMATCH[1]}"
					env_aws_status="valid"

					if [[ "$env_aws_type" == "ident-session" ]]; then
						env_aws_type="ident-rolesession"
					else
						env_aws_type="unident-rolesession"
					fi

				elif [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]]; then  # 6f: an ident/unident, valid mfasession
					this_iam_name="${BASH_REMATCH[1]}"
					env_aws_status="valid"

					if [[ "$env_aws_type" == "ident-session" ]]; then
						env_aws_type="ident-mfasession"
					else
						env_aws_type="unident-mfasession"
					fi

				else  # 6f: an unnamed, invalid session

					env_aws_status="invalid"
				fi
			fi
		fi

	else  # 7: no in-env AWS_ variables

		env_aws_status="none"
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

			echo -e "${BIWhite}${On_Black}THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE PRESENT:${Color_Off}"
			echo
			[[ "$ENV_AWS_PROFILE" != "" ]] && echo "   AWS_PROFILE: ${ENV_AWS_PROFILE}"
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
	
	else
		echo -e "No AWS environment variables present at this time.\\n"
	fi

	# ENVIRONMENT DETAIL OUTPUT

	if [[ "$this_session_expired" == "true" ]]; then
		expired_word=" (expired)"
	fi

	if [[ "$env_secrets_present" == "true" ]] &&
		[[ "$active_env_session" == "false" ]]; then

		profile_prefix="base"

	elif [[ "$env_secrets_present" == "true" ]] &&
		[[ "$active_env_session" == "true" ]]; then

		profile_prefix="session "

		if [[ "$env_aws_type" =~ -mfasession$ ]]; then
			profile_prefix="MFA session "
		elif [[ "$env_aws_type" =~ -rolesession$ ]]; then
			profile_prefix="role session "
		fi
	fi

	if [[ "$valid_default_exists" == "true" ]]; then
		purge_env_phrase=" or purge the environment with:\\n${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}"
	else
		purge_env_phrase="."
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

			echo -e "${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE CURRENTLY SELECTED/CONFIGURED\\n\
      IN THE ENVIRONMENT IS INVALID.\\n${Color_Off}"

		elif [[ "$env_aws_type" =~ session$ ]]; then

			echo -en "${BIRed}${On_Black}\
NOTE: THE AWS SESSION CURRENTLY SELECTED/CONFIGURED\\n\
      IN THE ENVIRONMENT IS "

			if [[ "${this_session_expired}" == "true" ]]; then
				echo -e "EXPIRED (SEE ABOVE).\\n${Color_Off}"
			else
				echo -e "INVALID (SEE ABOVE).\\n${Color_Off}"
			fi

		elif [[ "$env_aws_type" == "named-baseprofile-orphan" ]]; then

			echo -e "${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE SELECTED IN THE ENVIRONMENT\\n\
      (SEE ABOVE) DOES NOT EXIST.\\n${Color_Off}"

		elif [[ "$env_aws_type" == "named-session-orphan" ]]; then

			echo -e "${BIRed}${On_Black}\
NOTE: THE AWS SESSION CURRENTLY SELECTED IN THE ENVIRONMENT\\n\
      (SEE ABOVE) DOES NOT EXIST.\\n${Color_Off}"

		elif [[ "$env_aws_type" == "named-select-orphan" ]]; then

			echo -e "${BIRed}${On_Black}\
NOTE: THE AWS PROFILE SELECTED IN THE ENVIRONMENT (SEE ABOVE)\\n\
      DOES NOT EXIST.\\n${Color_Off}"
		
		fi
	fi

	status_printed="false"

	[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}env_aws_type: $env_aws_type, env_aws_status: $env_aws_status\\n${Color_Off}"

	if [[ "$env_aws_type" =~ ^select-only- ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		echo -e "${Green}${On_Black}\
The selected persisted ${profile_prefix}profile '$ENV_AWS_PROFILE' is valid.${Color_Off}\\n\
No credentials are present in the environment."

	elif [[ "$env_aws_type" =~ ^select-mirrored- ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		echo -e "${Green}${On_Black}\
The mirrored persisted ${profile_prefix}profile '$ENV_AWS_PROFILE' is valid.${Color_Off}\\n\
Valid mirrored credentials are present in the environment."

	elif [[ "$env_aws_type" =~ ^select-diff-.*session ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		echo -e "${Green}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_PROFILE' with\\n\
a persisted reference (maybe to an older session?) is valid.${Color_Off}\\n\
Valid unique credentials are present in the environment."

	elif [[ "$env_aws_type" =~ ^select-diff-.*-baseprofile ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		echo -e "${BIYellow}${On_Black}\
NOTE: The valid in-env baseprofile '$ENV_AWS_PROFILE' has different credentials\\n\
      than its persisted counterpart! Are you using a second API key, or have you\\n\
      rotated the key? Be sure to save it before you replace the environment with\\n\
      the output of this script!${Color_Off} Valid unique credentials are present\\n\
      in the environment."

	elif [[ "$env_aws_type" =~ ^(un)*ident-(baseprofile|session|rolesession|mfasession)$ ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		if [[ "$env_aws_type" =~ ^ident-(baseprofile|session|rolesession|mfasession)$ ]]; then

			echo -e "${Green}${On_Black}\
The in-env ${profile_prefix}profile '${ENV_AWS_PROFILE_IDENT}${ENV_AWS_SESSION_IDENT}'\\n\
with a detached reference to a persisted profile is valid.${Color_Off}\\n\
Valid credentials are present in the environment."

		else

			echo -e "${Green}${On_Black}\
The unidentified in-env ${profile_prefix}profile is valid.${Color_Off}\\n\
Valid credentials are present in the environment."

		fi

	elif [[ "$env_aws_type" =~ ^select-only- ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		echo -e "${Red}${On_Black}\
The selected persisted ${profile_prefix}profile '$ENV_AWS_PROFILE' is invalid${expired_word}.${Color_Off}\\n\
No credentials are present in the environment. You must use the '--profile {profile name}' with\\n\
the aws commands until you select a new profile/session${purge_env_phrase}"

	elif [[ "$env_aws_type" =~ ^select-mirrored- ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		echo -e "${Red}${On_Black}\
The mirrored persisted ${profile_prefix}profile '$ENV_AWS_PROFILE' is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must use the '--profile {profile name}' with\\n\
the aws commands until you select a new profile/session${purge_env_phrase}"

	elif [[ "$env_aws_type" =~ ^select-diff-.*session ||
		    "$env_aws_type" =~ ^select-diff-baseprofile ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		echo -e "${Red}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_PROFILE' with a persisted reference\\n\
is invalid${expired_word}.${Color_Off} Invalid unique credentials are present in the\\n\
environment. You must use the '--profile {profile name}' with the aws commands until\\n\
you select a new profile/session${purge_env_phrase}"

	elif [[ "$env_aws_type" =~ -orphan$ ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		echo -e "${Red}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_PROFILE' refers to a persisted profile\\n\
of the same name (set with envvar 'AWS_PROFILE'), however, no persisted profile with\\n\
that name can be found.${Color_Off} Invalid unique credentials are present in the environment.\\n\
You must use the '--profile {profile name}' with the aws commands until you select\\n\
a new profile/session${purge_env_phrase}"

	elif [[ "$env_aws_type" =~ ^(un)*ident-(baseprofile|session)$ ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		if [[ "$env_aws_type" =~ ^ident-(baseprofile|session)$ ]]; then

			echo -e "${Red}${On_Black}\
The in-env ${profile_prefix}profile '${ENV_AWS_PROFILE_IDENT}${ENV_AWS_SESSION_IDENT}'\\n\
with a detached reference to a persisted profile is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must use the '--profile {profile name}'\\n\
with the aws commands until you select a new profile/session${purge_env_phrase}"

		else 
			echo -e "${Red}${On_Black}\
The unidentified in-env ${profile_prefix}profile is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must use the '--profile {profile name}'\\n\
with the aws commands until you select a new profile/session${purge_env_phrase}"

		fi
	fi

	if [[ "$status_printed" == "false" ]] &&
		[[ "$env_selector_present" == "true" ||
		   "$env_secrets_present" == "true" ]]; then

		if [[ "$env_aws_status" == "unconfirmed" ]]; then

			echo -e "${Yellow}${On_Black}\
The status of the profile selected/present in the environment\\n\
(see the details above) could not be determined."
		fi

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
	local hits="0"
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
			hits="0"
		fi
	done
}

# adds a new property+value to the defined config file
# (why all these shenanigans you may ask.. a multi-line
# replace only by using the "LCD": the bash 3.2 builtins :-)
addConfigProp() {
	# $1 is the target file
	# $2 is the target file type
	# $3 is the target profile (the anchor; requires the label with a "profile_" prefix for non-default profiles in CONFFILE)
	# $4 is the property
	# $5 is the value
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function addConfigProp] target_file: $1, target_filetype: $2, target_profile: $3, property: $4, value: $5${Color_Off}"

	local target_file="$1"
	local target_filetype="$2"
	local target_profile="$3"  # this is the ident
	local new_property="$4"
	local new_value="$5"
	local target_anchor
	local replace_me
	local DATA
	local profile_prefix="false"
	local confs_profile_idx
	local replace_profile_transposed

	if [[ $target_file != "" ]] &&
		[[ ! -f "$target_file" ]]; then
		
		echo -e "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n"
		exit 1
	fi

	if [[ "$target_profile" != "default" ]] &&
		[[ "$target_filetype" == "conffile" ]]; then

		# use "_" in place of the separating space; this will
		# be removed in the end of the process
		replace_profile="profile_${target_profile}"

		# use profile prefix for non-default config profiles
		target_profile="profile $target_profile"

		# use transposed labels (because macOS's bash 3.x)
		profile_prefix="true"
	else
		# for 'default' use default; for non-config-file labels
		# use the profile label without the "profile" prefix
		replace_profile="${target_profile}"
	fi

	# replace other possible spaces in the label name
	# with the pattern '@@@'; the rationale: spaces are 
	# supported in the labels by AWS, however, the awk
	# replacement used by this multi-line-replace
	# process does not allow the source string to be
	# quoted (i.e. the replace_profile_transposed in 
	# the DATA string defined further below)
	replace_profile_transposed=$(sed -e ':loop' -e 's/\(\[[^[ ]*\) \([^]]*\]\)/\1@@@\2/' -e 't loop' <(echo $replace_profile))

	target_anchor=$(grep -E "\[$target_profile\]" "$target_file" 2>&1)

	# check for the anchor string in the target file
	# (no anchor, i.e. ident in the file -> add stub) 
	if [[ "$target_anchor" == "" ]]; then

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   no profile entry in file, adding..${Color_Off}"

		# no entry was found, add a stub
		# (use the possibly transposed string)
		echo -en "\\n">> "$target_file"
		echo "[${replace_profile_transposed}]" >> "$target_file"
	fi
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   target_profile: $target_profile${Color_Off}"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   replace_profile_transposed: $replace_profile_transposed${Color_Off}"

	# if the label has been transposed, use it in both in
	# the stub entry (above^^), and as the search point (below˅˅)
	replace_me="\\[${replace_profile_transposed}\\]"
	DATA="[${replace_profile_transposed}]\\n${new_property} = ${new_value}"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   replace_me: $replace_me${Color_Off}"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   DATA: $DATA${Color_Off}"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   transposing all labels..${Color_Off}"

	[[ "$profile_prefix" == "true" ]]
		sed -e 's/\[profile /\[profile_/g' -i.sedtmp "${target_file}"

	# transpose all spaces in all labels to restorable strings;
	# a kludgish construct in order to only use the builtins
	# while remaining bash 3.2 compatible (because macOS)
	sed -e ':loop' -e 's/\(\[[^[ ]*\) \([^]]*\]\)/\1@@@\2/' -e 't loop' -i.sedtmp "${target_file}"
	
	# with itself + the new property on the next line
	echo "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${target_file}")" > "${target_file}"
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   restoring normalcy in $target_file${Color_Off}"

	# restore normalcy
	sed -e ':loop' -e 's/\(\[[^[@]*\)@@@\([^]]*\]\)/\1 \2/' -e 't loop' -i.sedtmp "$target_file"

	[[ "$profile_prefix" == "true" ]]
		sed -e 's/\[profile_/\[profile /g' -i.sedtmp "${target_file}"

	# cleanup the sed backup file (a side effect of
	# the portable '-i.sedtmp')
	rm -f "${target_file}.sedtmp"
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

	if [[ $target_file != "" ]] &&
		[ ! -f "$target_file" ]; then
		
		echo -e "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n"
		exit 1
	fi

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
	
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function deleteConfigProp] target_file: $1, target_filetype: $2,target_profile: $3, prop_to_delete: $4${Color_Off}"

	local target_file="$1"
	local target_filetype="$2"
	local target_profile="$3"
	local prop_to_delete="$4"
	local TMPFILE
	local delete_active="false"
	local profile_ident

	if [[ $target_file != "" ]] &&
		[ ! -f "$target_file" ]; then
		
		echo -e "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n"
		exit 1
	fi

	if [[ "$target_profile" != "default" ]] &&
		[[ "$target_filetype" == "conffile" ]]; then

		target_profile="profile ${target_profile}"
	fi

	TMPFILE="$(mktemp "$HOME/tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")"

	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			profile_ident="${BASH_REMATCH[1]}"

			if [[ "$profile_ident" == "$target_profile" ]]; then
				# activate deletion for the matching profile
				delete_active="true"

			elif [[ "$profile_ident" != "" ]] &&
				[[ "$profile_ident" != "$target_profile" ]]; then

				# disable deletion when we're looking
				# at a non-matching profile label
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

# mark/unmark a profile invalid (both in ~/.aws/config and ~/.aws/credentials
# or in the custom files if custom defs are in effect) for intelligence
# in the quick mode
toggleInvalidProfile() {
	# $1 is the requested action (set/unset)
	# $2 is the profile (ident)

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function toggleInvalidProfile] this_ident: $1, operation: $2${Color_Off}"

	local action="$1"
	local this_ident="$2"

	local confs_idx
	local creds_idx
	local this_isodate=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

	# get idx for the current ident in confs
	idxLookup confs_idx confs_ident[@] "$this_ident"

	# get idx for the current ident in creds
	idxLookup creds_idx creds_ident_duplicate[@] "$this_ident"

	if [[ "$action" == "set" ]]; then

		# IN CONFFILE
		if [[ "${confs_invalid_as_of[$confs_idx]}" != "" ]]; then
			# profile previously marked invalid, update it with the current timestamp
			updateUniqueConfigPropValue "$CONFFILE" "${confs_invalid_as_of[$confs_idx]}" "$this_isodate"
		elif [[ "${confs_invalid_as_of[$confs_idx]}" == "" ]]; then
			# no invalid flag found; add one
			addConfigProp "$CONFFILE" "conffile" "${this_ident}" "invalid_as_of" "$this_isodate"
		fi

		# IN CREDFILE
		if [[ "${creds_invalid_as_of[$creds_idx]}" != "" ]]; then
			# profile previously marked invalid, update it with the current timestamp
			updateUniqueConfigPropValue "$CREDFILE" "${creds_invalid_as_of[$creds_idx]}" "$this_isodate"
		elif [[ "${creds_invalid_as_of[$creds_idx]}" == "" ]]; then
			# no invalid flag found; add one
			addConfigProp "$CREDFILE" "credfile" "${this_ident}" "invalid_as_of" "$this_isodate"
		fi

	elif [[ "$action" == "unset" ]]; then

		# unset invalid flag for the ident where present

		if [[ "$confs_idx" != "" && "${confs_invalid_as_of[$confs_idx]}" != "" ]]; then
			deleteConfigProp "$CONFFILE" "conffile" "${this_ident}" "invalid_as_of"
		fi

		if [[ "$creds_idx" != "" && "${creds_invalid_as_of[$creds_idx]}" != "" ]]; then
			deleteConfigProp "$CREDFILE" "credfile" "${this_ident}" "invalid_as_of"
		fi
	fi
}

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
			deleteConfigProp "$CONFFILE" "conffile" "$this_ident" "mfa_arn"
		elif [[ "$baseprofile_vmfad_arn" != "" ]]; then
			# add a vmfad entry (none exists previously)
			addConfigProp "$CONFFILE" "conffile" "$this_ident" "mfa_arn" "$baseprofile_vmfad_arn"
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
			addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_serial" "$this_mfa_serial"

		elif [[ "${this_mfa_serial}" == "erase" ]]; then  # "mfa_serial" is set to "erase" when the MFA requirement for a role has gone away
			# delete the existing mfa_serial property
			deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_serial"
		else
			# update the existing mfa_serial value (delete+add)
			# NOTE: we can't use updateUniqueConfigPropValue here because
			#       we can't be sure the profile wouldn't be duplicated under
			#       different labesls and/or, perhaps, vMFAd might be attached
			#       to multiple user accounts
			deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_serial"
			addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_serial" "$this_mfa_serial"
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
	# $3 is "baseprofile" or "role"
	# $4 (optional; used for chained sessions) restricted length: 
	#    if set to true "true" returns "3600" or a shorter value
	#    if so defined by sessmax

#todo: could root login be resolved here so that the default root session length could be returned?

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getMaxSessionDuration] profile_ident: $2, profile_type (optional): $3${Color_Off}"

	local getMaxSessionDuration_result
	local this_profile_ident="$2"
	local this_sessiontype="$3"
	local restricted_length="false"
	[[ "$4" == "true" ]] && restricted_length="true" 

	local idx
	local getMaxSessionDuration_result

	# look up a possible custom duration for the parent profile/role
	idxLookup idx merged_ident[@] "$this_profile_ident"

	# sessmax is dynamically defined in the role and auto-persisted
	# in the config where the user can override to a shorter value
	if [[ $idx != "" && "${merged_sessmax[$idx]}" != "" ]]; then

		getMaxSessionDuration_result="${merged_sessmax[$idx]}"
	else
		# sessmax is not being used; using the defaults

		if [[ "$this_sessiontype" == "baseprofile" ]]; then

			getMaxSessionDuration_result="$MFA_SESSION_LENGTH_IN_SECONDS"

		elif [[ "$this_sessiontype" == "role" ]]; then

			if [[ "${merged_role_chained_profile[$idx]}" == "true" ]]; then
				# chained role session length is limited to 3600 seconds
				getMaxSessionDuration_result="3600"
			else
				# the default AWS role session length is 3600; however this 
				# script sets the default internally.
				getMaxSessionDuration_result="$ROLE_SESSION_LENGTH_IN_SECONDS"
			fi
		fi
	fi

	if [[ "$restricted_length" == "true" ]] &&
		[[ "$getMaxSessionDuration_result" -gt "3600" ]]; then

		getMaxSessionDuration_result=3600
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
	local this_session_time
	local timestamp_format="invalid"
	local exp_time_format="seconds"  # seconds = seconds remaining, jit = seconds without slack (for JIT checks), datetime = expiration datetime, timestamp = expiration timestamp
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
		
		if [[ "$exp_time_format" != "jit" ]]; then

			# add time slack to non-JIT calcluations
			(( this_session_time=this_time+VALID_SESSION_TIME_SLACK ))
		else
			this_session_time="$this_time"
		fi

		if [[ $this_session_time -lt $expiration_timestamp ]]; then

			(( getRemaining_result=expiration_timestamp-this_time ))

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  this_session_time: $this_session_time, this_time: $this_time, VALID_SESSION_TIME_SLACK: $VALID_SESSION_TIME_SLACK, getRemaining_result: $getRemaining_result${Color_Off}"
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

checkGetRoleErrors() {
	# $1 is checkGetRoleErrors_result
	# $2 is the json data (supposedely)

	local getGetRoleErrors_result="none"
	local json_data="$2"

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function checkGetRoleErrors] json_data: $2${Color_Off}"
	
	if [[ "$json_data" =~ .*NoSuchEntity.* ]]; then
		
		# the role is not found; invalid
		# (either the source is wrong,
		# or the role doesn't exist)
		getGetRoleErrors_result="ERROR_NoSuchEntity"

	elif [[ "$json_data" =~ .*AccessDenied.* ]]; then

		# the source profile is not
		# authorized to run get-role
		# on the given role		
		getGetRoleErrors_result="ERROR_Unauthorized"

	elif [[ "$json_data" =~ .*The[[:space:]]config[[:space:]]profile.*could[[:space:]]not[[:space:]]be[[:space:]]found ]] ||
		[[ "$json_data" =~ .*InvalidClientTokenId.* ]] ||
		[[ "$json_data" =~ .*SignatureDoesNotMatch.* ]]; then
		
		# unconfigured source profile
		getGetRoleErrors_result="ERROR_BadSource"
	fi

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getGetRoleErrors_result}${Color_Off}"
	eval "$1=\"${getGetRoleErrors_result}\""
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
		echo -e "\\n${BIRed}${On_Black}${custom_error}The AWS Access Key ID does not exist!${Red}\\nCheck the ${profile_in_use} profile configuration including any 'AWS_*' environment variables.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'SignatureDoesNotMatch' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key does not match the Access Key ID!${Red}\\nCheck the ${profile_in_use} profile configuration including any 'AWS_*' environment variables.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'IncompleteSignature' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Incomplete signature!${Red}\\nCheck the Secret Access Key of the ${profile_in_use} for typos/completeness (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'MissingAuthenticationToken' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key is not present!${Red}\\nCheck the ${profile_in_use} profile configuration (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.*AssumeRole.* ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Access denied!\\n${Red}Could not assume role '${profile_in_use}'.\\nCheck the source profile and the MFA or validating source profile session status.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.*GetSessionToken.*MultiFactorAuthentication.*invalid[[:space:]]MFA[[:space:]]one[[:space:]]time[[:space:]]pass[[:space:]]code ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Invalid MFA one time pass code!\\n${Red}Are you sure you entered MFA pass code for profile '${profile_in_use}'?${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.* ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Access denied!\\n${Red}The operation could not be completed due to\\nincorrect credentials or restrictive access policy.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'AccessDeniedException' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Access denied!${Red}\\nThe effective MFA IAM policy may be too restrictive.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'AuthFailure' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Authentication failure!${Red}\\nCheck the credentials for the ${profile_in_use} profile (including any 'AWS_*' environment variables).${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'ServiceUnavailable' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Service unavailable!${Red}\\nThis is likely a temporary problem with AWS; wait for a moment and try again.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'ThrottlingException' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}Too many requests in too short amount of time!${Red}\\nWait for a few moments and try again.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'InvalidAction' ]] ||
		[[ "$aws_raw_return" =~ 'InvalidQueryParameter' ]] ||
		[[ "$aws_raw_return" =~ 'MalformedQueryString' ]] ||
		[[ "$aws_raw_return" =~ 'MissingAction' ]] ||
		[[ "$aws_raw_return" =~ 'ValidationError' ]] ||
		[[ "$aws_raw_return" =~ 'MissingParameter' ]] ||
		[[ "$aws_raw_return" =~ 'InvalidParameterValue' ]]; then
		
		echo -e "\\n${BIRed}${On_Black}${custom_error}AWS did not understand the request.${Red}\\nThis should never occur with this script. Maybe there was a glitch in\\nthe matrix (maybe the AWS API changed)?\\nRun the script with the '--debug' switch to see the exact error.${Color_Off}\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ 'InternalFailure' ]]; then
		echo -e "\\n${BIRed}${On_Black}${custom_error}An unspecified error occurred!${Red}\\n\"Internal Server Error 500\". Sorry I don't have more detail.${Color_Off}\\n"
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
	# $3 is the source profile (required for roles, otherwise optional)

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getAccountAlias] profile_ident: $2, source_profile: $3${Color_Off}"

	local getAccountAlias_result
	local local_profile_ident="$2"
	local source_profile="$3"
	[[ "${source_profile}" == "" ]] &&
		source_profile="$local_profile_ident"

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
			account_alias_result="$(aws --profile "$source_profile" iam list-account-aliases \
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
	local get_this_mfa_arn
	local get_this_role_arn
	local get_this_role_sessmax
	local get_this_role_mfa_req="false"
	local idx
	local notice_reprint="true"
	local jq_notice="true"
	local role_source_sel_error=""
	local source_profile_index
	local query_with_this
	declare -a cached_get_role_arr

	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "$notice_reprint" == "true" ]]; then
			echo -ne "${BIWhite}${On_Black}Please wait.${Color_Off}"
			notice_reprint="false"
		fi

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** dynamic augment for ident '${merged_ident[$idx]}' (${merged_type[$idx]})${Color_Off}"
		
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then  # BASEPROFILE AUGMENT ---------------------------------

			# get the user ARN; this should be always
			# available for valid profiles
			getProfileArn _ret "${merged_ident[$idx]}"

			if [[ "${_ret}" =~ ^arn:aws: ]]; then

				merged_baseprofile_arn[$idx]="${_ret}"

				# confirm that the profile isn't flagged invalid
				toggleInvalidProfile "unset" "${merged_ident[$idx]}"

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

				# flag the profile as invalid (for quick mode intelligence)
				toggleInvalidProfile "set" "${merged_ident[$idx]}"
			fi

		elif [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]]; then  # ROLE AUGMENT (no point augmenting invalid roles) -----------

			if [[ "${merged_role_source_baseprofile_ident[$idx]}" != "" ]]; then
				
				[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}   source baseprofile idx: $this_role_source_baseprofile_idx${Color_Off}"						

				getAccountAlias _ret "${merged_ident[$idx]}" "${merged_role_source_baseprofile_ident[$idx]}"

				if [[ ! "${_ret}" =~ 'could not be found' ]]; then
					merged_account_alias[$idx]="${_ret}"
				fi
			fi

			# 'jq' check and notice
			if [[ "${jq_notice}" == "true" ]]; then 

				jq_notice="false"

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
			fi  # end [[ "${jq_notice}" == "true" ]]

			# a role must have an existing source_profile defined
			if [[ "${merged_role_source_profile_ident[$idx]}" == "" ]] ||
				[[ "${merged_role_source_profile_absent[$idx]}" == "true" ]]; then

				notice_reprint="true"

				echo -e "\\n${BIRed}${On_Black}The role profile '${merged_ident[$idx]}' does not have a valid source_profile defined.${Color_Off}\\n"

				if [[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then
					echo -e "${BIRed}${On_Black}CURRENT INVALID SOURCE PROFILE: ${merged_role_source_profile_ident[$idx]}${Color_Off}\\n"
				fi

				echo -e "A role must have the means to authenticate, so select below the associated source profile:\\n"

				# prompt for source_profile selection for this role
				while :
				do
					echo -e "${BIWhite}${On_DGreen} AVAILABLE AWS BASEPROFILES: ${Color_Off}\\n"

					declare -a source_select
					source_sel_idx="1"

					for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
					do
						if [[ "${merged_type[$int_idx]}" == "baseprofile" ]]; then

							echo -e "${BIWhite}${On_Black}${source_sel_idx}: ${merged_ident[$int_idx]}${Color_Off}\\n"

							# save the reverse reference and increment the display index
							source_select[$source_sel_idx]="$int_idx"
							(( source_sel_idx++ ))
						fi
					done

					source_roles_available_count="0"
					source_role_selection_string=""
					for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
					do
						if [[ "${merged_type[$int_idx]}" == "role" ]]; then

							# do no show oneself, or a profile for whom oneself is 
							# a source profile (i.e. a circular reference is not allowed)
							if [[ "${merged_ident[$idx]}" != "${merged_ident[$int_idx]}" ]] &&
								[[ "${merged_ident[$idx]}" != "${merged_role_source_profile_ident[$int_idx]}" ]]; then

								source_role_selection_string+="${BIWhite}${On_Black}${source_sel_idx}: [ROLE] ${merged_ident[$int_idx]}${Color_Off}\\n"
								
								(( source_roles_available_count++ ))

								# save the reverse reference and increment the display index
								source_select[$source_sel_idx]="$int_idx"
								(( source_sel_idx++ ))
							fi
						fi
					done

					if [[ "$source_roles_available_count" -gt 0 ]]; then
					
						echo -e "\\n${BIWhite}${On_DGreen} AVAILABLE ROLE PROFILES (FOR ROLE CHAINING): ${Color_Off}\\n"

						echo -e "$source_role_selection_string"
					fi

					# print any error from the previous round
					if [[ "$role_source_sel_error" != "" ]]; then
						echo -e "$role_source_sel_error"

						role_source_sel_error=""
					fi

					# prompt for a baseprofile selection
					echo -en  "\\n\
NOTE: If you don't set a source profile, you can't use this role until you do so.\\n${BIYellow}${On_Black}\
SET THE SOURCE PROFILE FOR ROLE '${merged_ident[$idx]}'.\\n${BIWhite}\
Select the source profile by the ID and press Enter (or Enter by itself to skip):${Color_Off} "
					read -r role_sel_idx_selected
					echo

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}Source profile index selected: $role_sel_idx_selected${Color_Off}"

					if [[ "$role_sel_idx_selected" -gt 0 && "$role_sel_idx_selected" -le $source_sel_idx ]]; then
						# this is a profile selector for a valid role source_profile

						# get the corresponding source profile index
						source_profile_index="${source_select[$role_sel_idx_selected]}"

						[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   Actual corresponding source index: $source_profile_index${Color_Off}"

						# everybody with the EnforceMFA policy is allowed to query roles
						# without an active MFA session; try to use the selected profile
						# to query the role (we already know the role's Arn, so this is
						# just a reverse lookup to validate). If jq is available, this
						# will cache the result.
						# 
						# Acceptable choices are: baseprofile (by definition) or
						# another role profile which has a baseprofile defined
						if [[ "${merged_type[$source_profile_index]}" == "baseprofile" ]] ||
							[[ "${merged_role_source_baseprofile_ident[$source_profile_index]}" != "" ]]; then

							if [[ "${merged_type[$source_profile_index]}" == "baseprofile" ]]; then
								query_with_this="${merged_ident[$source_profile_index]}"
							else  # this is the source_profile of a chained role; use its baseprofile
								query_with_this="${merged_role_source_baseprofile_ident[$source_profile_index]}"
							fi

							if [[ "$jq_minimum_version_available" == "true" ]]; then

								cached_get_role_arr[$idx]="$(aws --profile "${query_with_this}" iam get-role \
									--role-name "${merged_role_name[$idx]}" \
									--output 'json' 2>&1)"

								[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${query_with_this}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --output 'json':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}"

								checkGetRoleErrors cached_get_role_error "${cached_get_role_arr[$idx]}"
								if [[ ! "$cached_get_role_error" =~ ^ERROR_ ]]; then
									get_this_role_arn="$(printf '\n%s\n' "${cached_get_role_arr[$idx]}" | jq -r '.Role.Arn')"
								else
									get_this_role_arn="$cached_get_role_error"
								fi

							else
								get_this_role_arn="$(aws --profile "${query_with_this}" iam get-role \
									--role-name "${merged_role_name[$idx]}" \
									--query 'Role.Arn' \
									--output 'text' 2>&1)"							

								[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${query_with_this}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.Arn' --output 'text':\\n${ICyan}${get_this_role_arn}${Color_Off}"

								checkGetRoleErrors get_this_role_arn_error "$get_this_role_arn"
								[[ "$get_this_role_arn_error" != "none" ]] &&
									get_this_role_arn="$get_this_role_arn_error"
							fi
						fi

						if [[ "$get_this_role_arn" == "${merged_role_arn[$idx]}" ]] ||
							[[ "${merged_role_chained_profile[$idx]}" == "true" ]]; then

							[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}Source profile selection approved${Color_Off}"

							echo -e "${Green}${On_Black}\
Using the profile '${merged_ident[$source_profile_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n"

							# the source_profile is confirmed working, so persist & save in the script state
							writeRoleSourceProfile "${merged_ident[$idx]}" "${merged_ident[$source_profile_index]}"

							# straight-up source_profile (baseprofile or not)
							merged_role_source_profile_ident[$idx]="${merged_ident[$source_profile_index]}"
							merged_role_source_profile_idx[$idx]="$source_profile_index"

							# get the final source baseprofile ident whether
							# it's the source_profile or further up the chain
							if [[ "${merged_type[$source_profile_index]}" == "baseprofile" ]]; then

								# it's a baseprofile - all is OK (use as-is)
								merged_role_source_baseprofile_ident[$idx]="${merged_ident[$source_profile_index]}"
								merged_role_source_baseprofile_idx[$idx]="$source_profile_index"

								merged_role_chained_profile[$idx]="false"
							else
								# it's a role - this is a chained role; find the upstream baseprofile
								getRoleChainBaseProfileIdent selected_source_baseprofile_ident ${merged_ident[$idx]}
								idxLookup this_role_source_baseprofile_idx merged_ident[@] "${selected_source_baseprofile_ident}"

								merged_role_source_baseprofile_ident[$idx]="$selected_source_baseprofile_ident"
								merged_role_source_baseprofile_idx[$idx]="$this_role_source_baseprofile_idx"

								merged_role_chained_profile[$idx]="true"
							fi
							
							# get account_id and account_alias from the baseprofile
							# (role profiles may or may not have it from augment since
							# this could be a two or more levels of chain in where
							# augment would not work normally)
							merged_account_id[$idx]="${merged_account_id[${merged_role_source_baseprofile_idx[$idx]}]}"
							merged_account_alias[$idx]="${merged_account_alias[${merged_role_source_baseprofile_idx[$idx]}]}"

							toggleInvalidProfile "unset" "${merged_ident[$idx]}"
							break

						elif [[ "$get_this_role_arn" == "ERROR_NoSuchEntity" ]]; then

							# the role doesn't exist or the source profile
							# is in a different account; the role is invalid

							role_source_sel_error="\\n${BIRed}${On_Black}\
Either the role '${merged_ident[$idx]}' is not associated with\\n\
the selected source profile '${merged_ident[$source_profile_index]}',\\n\
or the role doesn't exist. Select another profile?${Color_Off}"

							# this flows through, and thus reprints the base
							# profile list for re-selection

						else  # this includes ERROR_BadSource error condition as it is basically the same
							  # and also a source with that error should not be on the list to select from
							echo -e "${BIWhite}${On_Black}\
The selected profile '${merged_ident[$source_profile_index]}' could not be verified as\\n\
the source profile for the role '${merged_ident[$idx]}'. However,\\n\
this could be because of the selected profile's permissions.${Color_Off}\\n\\n
Do you want to keep the selection? ${BIWhite}${On_Black}Y/N${Color_Off}"

							yesNo _ret

							if [[ "${_ret}" == "yes" ]]; then

								echo -e "${Green}${On_Black}\
Using the profile '${merged_ident[$source_profile_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n"

								writeRoleSourceProfile "${merged_ident[$idx]}" "${merged_ident[$source_profile_index]}"
								merged_role_source_profile_ident[$idx]="${merged_ident[$source_profile_index]}"
								merged_role_source_profile_idx[$idx]="$source_profile_index"
								merged_account_id[$idx]="${merged_account_id[$source_profile_index]}"
								merged_account_alias[$idx]="${merged_account_alias[$source_profile_index]}"

								toggleInvalidProfile "unset" "${merged_ident[$idx]}"
								break
							fi
						fi

					elif [[ "$role_sel_idx_selected" =~ ^[[:space:]]*$ ]]; then
						# skip setting source_profile
						# (role remains unusable)
						echo -e "\\n${BIWhite}${On_Black}Skipped. Role remains unusable until a source profile is added to it.${Color_Off}\\n"

						# blank out the invalid merged_role_source_profile_ident
						# so that the rest of the script can't use/advertise it
						merged_role_source_profile_ident[$idx]=""

						# make sure the role is set to invalid
						toggleInvalidProfile "set" "${merged_ident[$idx]}"
						break
					else
						# an invalid entry

						echo -e "\\n${BIRed}${On_Black}\
Invalid selection.${Color_Off}\\n\
Try again, or just press Enter to skip setting source_profile\\n\
or vMFAd serial number for this role profile at this time.\\n"
					fi
				done

			else  # ------- ROLE ALREADY HAS source_profile

				# source_profile exists already, so just do 
				# a lookup and cache here if jq is enabled

				if [[ "$jq_minimum_version_available" == "true" ]]; then

					cached_get_role_arr[$idx]="$(aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--output 'json' 2>&1)"	

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --output 'json':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}"

					checkGetRoleErrors cached_get_role_error "${cached_get_role_arr[$idx]}"
					[[ "$cached_get_role_error" != "none" ]] &&
						cached_get_role_arr[$idx]="$cached_get_role_error"

					if [[ ! "${cached_get_role_arr[$idx]}" =~ ^ERROR_ ]]; then
						get_this_role_arn="$(printf '\n%s\n' "${cached_get_role_arr[$idx]}" | jq -r '.Role.Arn')"
					else
						# relay errors for analysis
						get_this_role_arn="${cached_get_role_arr[$idx]}"
					fi
				else
					get_this_role_arn="$(aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--query 'Role.Arn' \
						--output 'text' 2>&1)"	

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.Arn' --output 'text':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}"

					checkGetRoleErrors get_this_role_arn_error "$get_this_role_arn"
					[[ "$get_this_role_arn_error" != "none" ]] &&
						get_this_role_arn="$get_this_role_arn_error"
				fi

				if [[ "$get_this_role_arn" =~ ^ERROR_(NoSuchEntity|BadSource) ]]; then

					# the role is gone or the source profile is bad;
					# either way, the role is invalid
					toggleInvalidProfile "set" "${merged_ident[$idx]}"
				else
					toggleInvalidProfile "unset" "${merged_ident[$idx]}"
				fi
			fi

			# retry setting region and output now in case they weren't
			# available earlier (in the offline config) in the absence
			# of a defined source_profile
			#  
			# Note: this sets region for an already existing
			#       profile that has been read in; setessionOutputAndRegion
			#       imports this value to the output globals
			if [[ "${merged_region[$idx]}" == "" ]] &&   # the region is not set for this role
				[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&  # the source_profile is [now] defined
				[[ "${merged_region[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # and the source_profile has a region set

				merged_region[$idx]="${merged_region[${merged_role_source_profile_idx[$idx]}]}"

				# make the role region persistent
				aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}"
			fi

			# Note: this sets output for an already existing
			#       profile that has been read in; setessionOutputAndRegion
			#       imports this value to the output globals
			if [[ "${merged_output[$idx]}" == "" ]] &&   # the output format is not set for this role
				[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&  # the source_profile is [now] defined
				[[ "${merged_output[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # and the source_profile has a output set

				merged_output[$idx]="${merged_output[${merged_role_source_profile_idx[$idx]}]}"

				# make the role output persistent
				aws --profile "${merged_ident[$idx]}" configure set output "${merged_output[$idx]}"
			fi

			# execute the following only when a source profile
			# has been defined; since we give the option to 
			# skip setting for a missing source profile, this
			# is conditionalized
			if [[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then

				# role sessmax dynamic augment; get MaxSessionDuration from role 
				# if queriable, and write to the profile if 1) not blank, and 
				# 2) different from the default 3600
				if [[ "$jq_minimum_version_available" == "true" ]]; then
					# use the cached get-role to avoid
					# an extra lookup if jq is available
					if [[ ! "${cached_get_role_arr[$idx]}" =~ ^ERROR_ ]]; then
						get_this_role_sessmax="$(printf '\n%s\n' "${cached_get_role_arr[$idx]}" | jq -r '.Role.MaxSessionDuration')"
					fi
				else
					get_this_role_sessmax="$(aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--query 'Role.MaxSessionDuration' \
						--output 'text' 2>&1)"

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_profile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.MaxSessionDuration' --output 'text':\\n${ICyan}${get_this_role_sessmax}${Color_Off}"

					checkGetRoleErrors get_this_role_sessmax_error "$get_this_role_sessmax"
					[[ "$get_this_role_sessmax_error" != "none" ]] &&
						get_this_role_sessmax="$get_this_role_sessmax_error"
				fi

				# minimum acceptable sessmax value is 900 seconds,
				# hence at least three digits in the pattern below
				if [[ "$get_this_role_sessmax" =~ ^[[:space:]]*[[:digit:]][[:digit:]][[:digit:]]+[[:space:]]*$ ]]; then

					if [[ "$get_this_role_sessmax" != "${merged_sessmax[$idx]}" ]] &&
					
						[[ "$get_this_role_sessmax" -ge 900  &&
						   "$get_this_role_sessmax" -le 129600 ]] &&

						[[ "$get_this_role_sessmax" != "3600" ]]; then
						# set and persist get get_this_role_sessmax if it differs
						# from the existing value (do not set/persist the default
						# 3600, or an illegal value of <900 or >129600)

						merged_sessmax[$idx]="$get_this_role_sessmax"
						writeSessmax "${merged_ident[$idx]}" "$get_this_role_sessmax"

					elif [[ ( "$get_this_role_sessmax" == "" ||
							  "$get_this_role_sessmax" == "3600" ) &&
							  "${merged_sessmax[$idx]}" != "" ]] ||
						 [[ "${merged_sessmax[$idx]}" -lt "900" ||
						    "${merged_sessmax[$idx]}" -gt "129600" ]]; then
						 # set sessmax internally to the default 3600 if:
						 #  - the role doesn't define it (default 3600)
						 #  - the role explicitly defines the default 3600
						 #  - the persisted sessmax is outside the allowed range 900-129600

						merged_sessmax[$idx]="3600"

						# then erase the persisted sessmax since the default 3600 is used
						writeSessmax "${merged_ident[$idx]}" "erase"
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

					toggleInvalidProfile "unset" "${merged_ident[$idx]}"
					merged_session_status[$idx]="valid"
				else
					toggleInvalidProfile "set" "${merged_ident[$idx]}"
					merged_session_status[$idx]="invalid"
				fi
			fi
		fi

		if [[ "$notice_reprint" == "true" ]]; then
			echo -ne "${BIWhite}${On_Black}Please wait.${Color_Off}"
			notice_reprint="false"
		elif [[ "$DEBUG" != "true" ]]; then
			echo -en "${BIWhite}${On_Black}.${Color_Off}"
		fi

	done

	# phase II for things that have a depencency for a complete profile reference from PHASE I
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do

		if [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]] &&
			[[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then  # ROLE AUGMENT, PHASE II -------------------

			# add source_profile username to the merged_role_source_username array
			merged_role_source_username[$idx]=""
			if [[ "${merged_role_source_baseprofile_idx[$idx]}" != "" ]]; then

				# merged_username is now available for all baseprofiles
				# (since this comes after the first dynamic augment loop)
				merged_role_source_username[$idx]="${merged_username[${merged_role_source_baseprofile_idx[$idx]}]}"
			fi			

			# role_mfa requirement check (persist the associated 
			# source profile mfa_serial if avialable/changed)
			if [[ "$jq_minimum_version_available" == "true" ]]; then
				# use the cached get-role to avoid
				# an extra lookup if jq is available

				if [[ ! "${cached_get_role_arr[$idx]}" =~ ^ERROR_ ]]; then
					get_this_role_mfa_req="$(printf '%s' "${cached_get_role_arr[$idx]}" | jq -r '.Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"')"
				fi

			else

				get_this_role_mfa_req="$(aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
					--role-name "${merged_role_name[$idx]}" \
					--query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' \
					--output 'text' 2>&1)"

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws --profile \"${merged_role_source_profile_ident[$idx]}\" iam get-role --role-name \"${merged_ident[$idx]}\" --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' --output 'text':\\n${ICyan}${get_this_role_mfa_req}${Color_Off}"

				checkGetRoleErrors get_this_role_mfa_req_errors "$get_this_role_mfa_req"
				[[ "$get_this_role_mfa_req_errors" != "none" ]] &&
					get_this_role_mfa_req="$get_this_role_mfa_req_errors"

			fi

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}Checking MFA req for role name '${merged_role_name[$idx]}'. MFA is req'd (by policy): ${get_this_role_mfa_req}${Color_Off}"

			if [[ "$get_this_role_mfa_req" == "true" ]]; then

				merged_role_mfa_required[$idx]="true"

				this_source_mfa_arn="${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}"

				if [[ "$this_source_mfa_arn" == "" &&
					  "${merged_role_mfa_serial[$idx]}" != "" ]] ||

					# always remove MFA ARN from a chained profile if present
					[[ "${merged_role_mfa_serial[$idx]}" != "" &&
					   "${merged_role_chained_profile[$idx]}" == "true" ]]; then

					# A non-functional role: the role requires an MFA,
					# the role profile has a vMFAd configured, but the
					# source profile [no longer] has one configured
					#
					# OR this is a chained role; they authenticate with
					# the upstream role's existing role session, and never
					# with a MFA
					writeRoleMFASerialNumber "${merged_ident[$idx]}" "erase"

				elif [[ "$this_source_mfa_arn" != "" ]] &&
					[[ "${merged_role_mfa_serial[$idx]}" != "$this_source_mfa_arn" ]] &&
					[[ "${merged_role_chained_profile[$idx]}" != "true" ]]; then

					# the role requires an MFA, the source profile
					# has vMFAd available, and it differs from what
					# is currently configured (including blank)
					# 
					# Note: "blank to configured" is the most likely scenario
					# here since unless the role's source_profile changes
					# the vMFAd Arn doesn't change even if it gets reissued
					writeRoleMFASerialNumber "${merged_ident[$idx]}" "$this_source_mfa_arn"
				fi
			else

				merged_role_mfa_required[$idx]="false"

				# the role [no longer] requires an MFA
				# and one is currently configured, so remove it
				if [[ "${merged_role_mfa_serial[$idx]}" != "" ]]; then

					writeRoleMFASerialNumber "${merged_ident[$idx]}" "erase"
				fi
			fi
		fi

		[[ "$DEBUG" != "true" ]] &&
			echo -en "${BIWhite}${On_Black}.${Color_Off}"
 	done

	echo
	echo
}

# walks up the role chain to get
# the original baseprofile ident
getRoleChainBaseProfileIdent() {
	# $1 is getRoleChainBaseProfileIdent_result
	# $2 is the role ident for which the baseprofile is being looked up

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function getRoleChainBaseProfileIdent] ident: $2${Color_Off}"

	local this_ident="$2"
	local this_idx=""

	while :
	do
		idxLookup this_idx merged_ident[@] "$this_ident"
		if [[ "$this_idx" != "" ]]; then
			this_ident="${merged_ident[${merged_role_source_profile_idx[$this_idx]}]}"

			if [[ "${merged_type[${merged_role_source_profile_idx[$this_idx]}]}" == "baseprofile" ]]; then
				getRoleChainBaseProfileIdent_result="$this_ident"
				break
			fi
		else
			getRoleChainBaseProfileIdent_result=""
			break
		fi

	done

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}  ::: output: ${getRoleChainBaseProfileIdent_result}${Color_Off}"

	eval "$1=\"$getRoleChainBaseProfileIdent_result\""
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

## END FUNCTIONS ======================================================================================================

## MAIN ROUTINE START =================================================================================================
## PREREQUISITES CHECK

# Check OS for some supported platforms
if exists uname ; then
	OSr="$(uname -a)"

	if [[ "$OSr" =~ .*Linux.*Microsoft.* ]]; then

		OS="WSL_Linux"
		has_brew="false"

		# override BIBlue->BIBlack (grey) for WSL Linux
		# as blue is too dark to be seen in it
		BIBlue='\033[0;90m'

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

	if exists apt ; then
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
confdir="true"
# check for ~/.aws directory
# if the custom config defs aren't in effect
if [[ "$AWS_CONFIG_FILE" == "" ||
	  "$AWS_SHARED_CREDENTIALS_FILE" == "" ]] &&
	[[ ! -d "$HOME/.aws" ]]; then

	echo
	echo -e "${BIRed}${On_Black}\
AWSCLI configuration directory '$HOME/.aws' is not present.${Color_Off}\\n\
Make sure it exists, and that you have at least one profile configured\\n\
using the 'config' and/or 'credentials' files within that directory.\\n"
	filexit="true"
	confdir="false"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ -f "$AWS_CONFIG_FILE" ]]; then

	absolute_AWS_CONFIG_FILE="$(realpath "$AWS_CONFIG_FILE")"

	active_config_file="$absolute_AWS_CONFIG_FILE"
	echo -e "${BIYellow}${On_Black}\
NOTE: A custom configuration file defined with AWS_CONFIG_FILE\\n\
      envvar in effect: '$absolute_AWS_CONFIG_FILE'${Color_Off}\\n"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ ! -f "$absolute_AWS_CONFIG_FILE" ]]; then

	echo -e "${BIRed}${On_Black}\
The custom AWSCLI configuration file defined with AWS_CONFIG_FILE envvar,\\n\
'$absolute_AWS_CONFIG_FILE', was not found.${Color_Off}\\n\
Make sure it is present or purge the envvars with:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [[ -f "$CONFFILE" ]]; then

	active_config_file="$CONFFILE"

else
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

	absolute_AWS_SHARED_CREDENTIALS_FILE="$(realpath "$AWS_SHARED_CREDENTIALS_FILE")"

	active_credentials_file="$absolute_AWS_SHARED_CREDENTIALS_FILE"
	echo -e "${BIYellow}${On_Black}\
NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE\\n\
      envvar in effect: '$absolute_AWS_SHARED_CREDENTIALS_FILE'${Color_Off}\\n"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[[ ! -f "$absolute_AWS_SHARED_CREDENTIALS_FILE" ]]; then

	echo -e "${BIRed}${On_Black}\
The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar,\\n\
'$absolute_AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\n\
Make sure it is present, or purge the envvar.\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up."
	filexit="true"

elif [[ -f "$CREDFILE" ]]; then

	active_credentials_file="$CREDFILE"

elif [[ "$confdir" == "true" ]]; then
	# assume any existing creds are in $CONFFILE;
	# create a shared credentials file stub for session creds
    touch "$CREDFILE"
    chmod 600 "$CREDFILE"

	active_credentials_file="$CREDFILE"

	echo -e "\\n${BIWhite}${On_Black}\
NOTE: A shared credentials file ('~/.aws/credentials') was not found;\\n\
      assuming existing credentials are in the config file ('$CONFFILE').${Color_Off}\\n\\n\
NOTE: A blank shared credentials file ('~/.aws/credentials') was created\\n\
      as the session credentials will be stored in it."
else
	filexit="true"
fi

if [[ "$filexit" == "true" ]]; then

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Necessary config files not present; exiting!${Color_Off}"
	echo
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"

# make sure the selected CONFFILE has a linefeed in the end
LF_maybe="$(tail -c 1 "$CONFFILE")"

if [[ "$LF_maybe" != "" ]]; then

	echo "" >> "$CONFFILE"
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** Adding linefeed to '${CONFFILE}'${Color_Off}"
fi

# make sure the selected CREDFILE has a linefeed in the end
LF_maybe="$(tail -c 1 "$CREDFILE")"

if [[ "$LF_maybe" != "" ]]; then

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

		if [[ "$profile_ident" =~ (-mfasession|-rolesession)$ ]]; then

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
NOTE: One or more lines in '$CREDFILE' have illegal spaces\\n\
      (leading spaces or spaces between the label brackets and the label text);\\n\
      they are not allowed as AWSCLI cannot parse the file as it is!${Color_Off}\\n\
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
[ default ]  <- no leading/trailing spaces between brackets and the label!\\n\
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

	if [[ "$profile_ident" =~ (-mfasession|-rolesession)$ ]]; then

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
NOTE: One or more lines in '$CONFFILE' have illegal spaces\\n\
      (leading spaces or spaces between the label brackets and the label text);\\n\
      they are not allowed as AWSCLI cannot parse the file as it is!${Color_Off}
      Please edit the config file to remove the disallowed spaces and try again.\\n\\n\
Examples (OK):\\n\
--------------\\n\
[default]\\n\
region = us-east-1\\n\
\\n\
[profile some_other_profile]\\n\
region=us-east-1\\n\
\\n\
Examples (NOT OK):\\n\
------------------\\n\
[ default ]  <- no leading/trailing spaces between brackets and the label!\\n\
  region = us-east-1  <- no leading spaces!\\n\
\\n\
  [profile some_other_profile]  <- no leading spaces on the labels lines!\\n\
  region=us-east-1  <- no spaces on the property lines!\\n"

      exit 1
fi

if [[ "$illegal_defaultlabel_check" == "true" ]]; then

	echo -e "\\n${BIRed}${On_Black}\
NOTE: The default profile label in '$CONFFILE' has the keyword 'profile'\\n\
      in the beginning. This is not allowed in the AWSCLI config file.${Color_Off}\\n\
      Please edit the '$CONFFILE' to correct the error and try again!\\n\\n\
An example (OK):\\n\
----------------\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
An example (NOT OK):\\n\
--------------------\\n\
[profile default]\\n\
aws_access_key_id = AKIA...\\n"

      exit 1
fi

if [[ "$illegal_profilelabel_check" == "true" ]]; then

	echo -e "\\n${BIRed}${On_Black}\
NOTE: One or more of the profile labels in '$CONFFILE' are missing the keyword 'profile'\\n\
      from the beginning. While the standard in the credentials file, it is not allowed in the config file.${Color_Off}\\n\
      NOTE: The 'default' profile is an exception; it may NEVER have the 'profile' keyword).\\n\\n\
      Please edit the '$CONFFILE' to correct the error(s) and try again!\\n\\n\
Examples (OK):\\n\
--------------\\n\
[profile not_the_default_profile]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
[default]\\n\
aws_access_key_id = AKIA...\\n\
\\n\
Examples (NOT OK):\\n\
------------------\\n\
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
	echo -e "${BIRed}${On_Black}\
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
      aws configure set region \"us-east-1\"${Color_Off}\\n\
      ${BIYellow}${On_Black}Do NOT use '--profile default' switch when configuring the defaults!${Color_Off}"

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
      aws configure set output \"table\"${Color_Off}\\n\
      ${BIYellow}${On_Black}Do NOT use '--profile default' switch when configuring the defaults!${Color_Off}"

	fi

	## FUNCTIONAL PREREQS PASSED; PROCEED WITH CUSTOM CONFIGURATION/PROPERTY READ-IN ----------------------------------

	# define profiles arrays, variables
	declare -a creds_ident
	declare -a creds_aws_access_key_id
	declare -a creds_aws_secret_access_key
	declare -a creds_aws_session_token
	declare -a creds_aws_session_expiry
	declare -a creds_invalid_as_of
	declare -a creds_type
	persistent_MFA="false"
	profiles_init=0
	creds_iterator=0
	unset dupes

	# a hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}ITERATING CREDFILE ---${Color_Off}"
	while IFS='' read -r line || [[ -n "$line" ]]; do
		
		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}iterating credfile line: ${line}${Color_Off}"

		if [[ "$line" =~ ^\[(.*)\] ]]; then

			_ret="${BASH_REMATCH[1]}"

			# don't increment on first pass
			# (to use index 0 for the first item)
			if [[ "$profiles_init" -eq 0 ]]; then

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

			[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}   .. ${creds_type[$creds_iterator]}${Color_Off}"
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

		# invalid_as_of
		[[ "$line" =~ ^invalid_as_of[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			creds_invalid_as_of[$creds_iterator]="${BASH_REMATCH[1]}"

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
	# (the original array gets truncated during the merge)
	creds_ident_duplicate=("${creds_ident[@]}")

	# init arrays to hold profile configuration detail
	# (may also include credentials)
	declare -a confs_ident
	declare -a confs_aws_access_key_id
	declare -a confs_aws_secret_access_key
	declare -a confs_aws_session_token
	declare -a confs_aws_session_expiry
	declare -a confs_sessmax
	declare -a confs_invalid_as_of
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

	# read in the config file params
	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}ITERATING CONFFILE ---${line}${Color_Off}"
	while IFS='' read -r line || [[ -n "$line" ]]; do

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}iterating conffile line: ${line}${Color_Off}"

		if [[ "$line" =~ ^\[profile[[:space:]]+(.*)\] ]] ||
			[[ "$line" =~ ^\[(default)\] ]]; then

			_ret="${BASH_REMATCH[1]}"

			# don't increment on first pass
			# (to use index 0 for the first item)
			if [[ "$confs_init" -eq 0 ]]; then

				confs_ident[$confs_iterator]="${_ret}"
				confs_init=1

			elif [[ "${confs_ident[$confs_iterator]}" != "${_ret}" ]]; then

				((confs_iterator++))
				confs_ident[$confs_iterator]="${_ret}"
			fi

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}confs_iterator ${confs_iterator}: ${_ret}${Color_Off}"

			if [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -mfasession$ ]]; then

				confs_type[$confs_iterator]="mfasession"

			elif [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -rolesession$ ]]; then

				confs_type[$confs_iterator]="rolesession"
			else
				# assume baseprofile type for non-sessions; 
				# this will be overridden for roles
				confs_type[$confs_iterator]="baseprofile"
			fi
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

		# invalid_as_of
		[[ "$line" =~ ^invalid_as_of[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]] && 
			confs_invalid_as_of[$confs_iterator]="${BASH_REMATCH[1]}"

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
		if [[ "$line" =~ ^credential_source[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_credential_source[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		# (role) source_profile
		if [[ "$line" =~ ^source_profile[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_source_profile_ident[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		# (role) external_id
		if [[ "$line" =~ ^external_id[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_external_id[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		# (role) mfa_serial
		if [[ "$line" =~ ^mfa_serial[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_mfa_serial[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		# role_session_name 
		if [[ "$line" =~ ^role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_session_name[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}   .. ${confs_type[$confs_iterator]}${Color_Off}"

	done < "$CONFFILE"

	# UNIFIED ARRAYS (config + credentials, and more)
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
	declare -a merged_invalid_as_of  # optional marker for an invalid profile (persisted intelligence for the quick mode)
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
	declare -a merged_role_chained_profile  # true if source_profile is not a baseprofile
	declare -a merged_role_source_baseprofile_ident
	declare -a merged_role_source_profile_ident
	declare -a merged_role_source_profile_idx
	declare -a merged_role_source_profile_absent="false"  # set to true when the defined source_profile doesn't exist

	# DYNAMIC AUGMENT ARRAYS
	declare -a merged_baseprofile_arn  # based on get-caller-identity, this can be used as the validity indicator for the baseprofiles (combined with merged_session_status for the select_status)
	declare -a merged_baseprofile_operational_status  # ok/reqmfa/none/unknown based on 'iam get-access-key-last-used' (a 'valid' profile can be 'reqmfa' depending on policy; but shouldn't be 'none' or 'unknown' since 'sts get-caller-id' passed)
	declare -a merged_account_alias
	declare -a merged_account_id
	declare -a merged_username  # username derived from a baseprofile, or role name from a role profile
	declare -a merged_role_source_username  # username for a role's source profile, derived from the source_profile (if avl)
	declare -a merged_role_mfa_required  # if a role profile has a functional source_profile, this is derived from get-role and query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"'
										 # note: this is preliminarily set in offline augment based on MFA arn being present in the role config

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

		[[ "$creds_idx" != "" && "${creds_aws_access_key_id[$creds_idx]}" != "" ]] &&
			merged_aws_access_key_id[$itr]="${creds_aws_access_key_id[$creds_idx]}" ||
			merged_aws_access_key_id[$itr]="${confs_aws_access_key_id[$itr]}"

		[[ "$creds_idx" != "" && "${creds_aws_secret_access_key[$creds_idx]}" != "" ]] &&
			merged_aws_secret_access_key[$itr]="${creds_aws_secret_access_key[$creds_idx]}" ||
			merged_aws_secret_access_key[$itr]="${confs_aws_secret_access_key[$itr]}"

		[[ "$creds_idx" != "" && "${creds_aws_session_token[$creds_idx]}" != "" ]] &&
			merged_aws_session_token[$itr]="${creds_aws_session_token[$creds_idx]}" ||
			merged_aws_session_token[$itr]="${confs_aws_session_token[$itr]}"

		[[ "$creds_idx" != "" && "${creds_aws_session_expiry[$creds_idx]}" != "" ]] &&
			merged_aws_session_expiry[$itr]="${creds_aws_session_expiry[$creds_idx]}" ||
			merged_aws_session_expiry[$itr]="${confs_aws_session_expiry[$itr]}"

		if [[ "${confs_invalid_as_of[$itr]}" != "" ]]; then
			merged_invalid_as_of[$itr]="${confs_invalid_as_of[$itr]}"
		elif [[ "$creds_idx" != "" && "${creds_invalid_as_of[$creds_idx]}" != "" ]]; then
			merged_invalid_as_of[$itr]="${creds_invalid_as_of[$creds_idx]}"
		fi

		# confs_type knows more because creds cannot 
		# distinguish between baseprofiles and roles
		[[ "${confs_ident[$itr]}" != "" && "${confs_type[$itr]}" != "" ]] &&
			merged_type[$itr]="${confs_type[$itr]}" ||
			merged_type[$itr]="${creds_type[$creds_idx]}"

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
	# (awscli existence is already checked)
	aws_version_raw="$(aws --version)"
	aws_version_string="$(printf '%s' "$aws_version_raw" | awk '{ print $1 }')"

	aws_version_major=""
	aws_version_minor=""
	aws_version_patch=""
	if [[ "$aws_version_string" =~ ^aws-cli/([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)$ ]]; then
		aws_version_major="${BASH_REMATCH[1]}"
		aws_version_minor="${BASH_REMATCH[2]}"
		aws_version_patch="${BASH_REMATCH[3]}"
	fi

	if [[ ! "${aws_version_major}" =~ [[:digit:]]+ ]] ||
		[[ "${aws_version_major}" -lt 1 ]] ||
		[[ ! "${aws_version_minor}" =~ [[:digit:]]+ ]] ||
		[[ "${aws_version_minor}" -lt 16 ]]; then

		echo -e "${BIRed}${On_Black}\
Please upgrade your awscli to the latest version, then try again.${Color_Off}\\n\\n\
To upgrade, run:\\n\
${BIWhite}${On_Black}pip3 install --upgrade awscli${Color_Off}\\n"

		exit 1

	else
		echo -e "\\n\
The current awscli version is ${aws_version_major}.${aws_version_minor}.${aws_version_patch} ${BIGreen}${On_Black}✓${Color_Off}\\n"

	fi

	# check for jq, version
	if exists jq ; then
		jq_version_string="$(jq --version)"
		jq_available="false"
		jq_minimum_version_available="false"

		if [[ "$jq_version_string" =~ ^jq-.* ]]; then

			jq_available="true"	

			[[ "$jq_version_string" =~ ^jq-([[:digit:]]+)\.([[:digit:]]+)(.|-)* ]] &&
				jq_version_major="${BASH_REMATCH[1]}"
				jq_version_minor="${BASH_REMATCH[2]}"

			if [[ "${jq_version_major}" -ge 1 ]] &&
				[[ "${jq_version_minor}" -ge 5 ]]; then

				jq_minimum_version_available="true"

				echo -e "\
The current jq version is ${jq_version_major}.${jq_version_minor} ${BIGreen}${On_Black}✓${Color_Off}\\n"

			else

				echo -e "\
Please upgrade your jq to the latest version. ${BIRed}${On_Black}❌${Color_Off}\\n"

			fi
		else
			echo -e "${Yellow}${On_Black}\
Consider installing 'jq' for faster and more reliable operation.${Color_Off}\\n"

		fi
	else
		echo -e "${Yellow}${On_Black}\
Consider installing 'jq' for faster and more reliable operation.${Color_Off}\\n"
	fi


	## BEGIN OFFLINE AUGMENTATION: PHASE I ----------------------------------------------------------------------------

	if [[ "$DEBUG" == "true" ]]; then
		echo -e "\
MERGED INVENTORY\\n\
----------------\\n"

		for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
		do
			echo -e "$idx: ${merged_ident[$idx]}"
		done
	
		echo -e "\\n${BIYellow}${On_Black}** Offline augmentation: PHASE I${Color_Off}"
	fi

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
			if [[ ${merged_type[$idx]} == "role" ]] &&
				[[ "${merged_role_source_profile_ident[$idx]}" == "${merged_ident[$int_idx]}" ]]; then

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  found source profile for role index $idx: source index $int_idx${Color_Off}"
				merged_role_source_profile_idx[$idx]="$int_idx"
			fi
		done

		if [[ ${merged_type[$idx]} == "role" ]] &&
			[[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&
			[[ "${merged_role_source_profile_idx[$idx]}" == "" ]]; then

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}  role index $idx has an invalid source profile ident: ${merged_role_source_profile_ident[$idx]}${Color_Off}"
			merged_role_source_profile_absent[$idx]="true"
		fi

	done

	## BEGIN OFFLINE AUGMENTATION: PHASE II ---------------------------------------------------------------------------

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

		elif [[ "${merged_type[$idx]}" == "role" ]] &&									  # this is a role
																						  #  AND
			[[ "${merged_region[$idx]}" == "" ]] &&										  # a region has not been set for this role
																						  #  AND
			[[ ( "${merged_role_source_profile_idx[$idx]}" != "" &&						  # (the source_profile has been defined
			     "${merged_region[${merged_role_source_profile_idx[$idx]}]}" == "" ) ||   #  .. but it doesn't have a region set
																						  #  OR
			     "${merged_role_source_profile_idx[$idx]}" == "" ]] &&					  # the source_profile has not been defined)
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

			addConfigProp "$CONFFILE" "conffile" "${merged_ident[$idx]}" "role_session_name" "${merged_role_session_name[$idx]}" 
		fi

		# ROLE PROFILES: add role_name for easier get-role use
		if [[ "${merged_type[$idx]}" == "role" ]] && 		# this is a role
			[[ "${merged_role_arn[$idx]}" != "" ]] &&		# and it has an arn (if it doesn't, it's not a valid role profile)
			[[ "${merged_role_arn[$idx]}" =~ ^arn:aws:iam::([[:digit:]]+):role.*/([^/]+)$ ]]; then

			merged_account_id[$idx]="${BASH_REMATCH[1]}"
			merged_role_name[$idx]="${BASH_REMATCH[2]}"

			# also add merged_role_mfa_required based on presence of MFA arn in role config
			if [[ "${merged_role_mfa_serial[$idx]}" != "" ]]; then  # if the MFA serial is present, MFA will be required regardless of whether the role actually demands it

				merged_role_mfa_required[$idx]="true"

			else  # if the MFA serial is not present, we have no way to know without dynamic augment whether the role actually requires MFA (this is for quick mode)

				merged_role_mfa_required[$idx]="unknown"
			fi

			# the original source profile type and ident
			this_source_profile_type="${merged_type[${merged_role_source_profile_idx[$idx]}]}"
			this_source_profile_ident="${merged_ident[${merged_role_source_profile_idx[$idx]}]}"

			# get the final source baseprofile ident whether
			# it's the source_profile or further up the chain
			if [[ "$this_source_profile_type" == "baseprofile" ]]; then

				# it's a baseprofile - all is OK (use as-is)
				merged_role_source_baseprofile_ident[$idx]="$this_source_profile_ident"
				merged_role_source_baseprofile_idx[$idx]="${merged_role_source_profile_idx[$idx]}"

				merged_role_chained_profile[$idx]="false"
			else
				# it's a role - this is a chained role; find the upstream baseprofile
				getRoleChainBaseProfileIdent this_source_baseprofile_ident ${merged_ident[$idx]}
				idxLookup this_role_source_baseprofile_idx merged_ident[@] "$this_source_baseprofile_ident"

				merged_role_source_baseprofile_ident[$idx]="$this_source_baseprofile_ident"
				merged_role_source_baseprofile_idx[$idx]="$this_role_source_baseprofile_idx"
				
				merged_role_chained_profile[$idx]="true"
			fi

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}   source profile type: $this_source_profile_type${Color_Off}"						
			[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}   source profile ident: $this_source_profile_ident${Color_Off}"						
			[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}   source baseprofile ident: ${merged_role_source_baseprofile_ident[$idx]}${Color_Off}"						

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

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** starting dynamic augment${Color_Off}"
	dynamicAugment

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
	select_idx="0"
	baseprofile_count="0"
	valid_baseprofiles="0"
	invalid_baseprofiles="0"
	valid_baseprofiles_no_mfa="0"
	valid_baseprofiles_with_mfa="0"
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]}${Color_Off}"

			select_type[$select_idx]="baseprofile"
			(( baseprofile_count++ ))
			
			if [[ "${merged_baseprofile_arn[$idx]}" != "" ]]; then  # sts get-caller-identity had checked out ok for the baseprofile

				select_status[$select_idx]="valid"
				(( valid_baseprofiles++ ))

				if [[ "${merged_mfa_arn[$idx]}" == "" ]]; then
					(( valid_baseprofiles_no_mfa++ ))
				else
					(( valid_baseprofiles_with_mfa++ ))
				fi

			elif [[ "${merged_baseprofile_arn[$idx]}" == "" ]]; then  # sts get-caller-identity had not worked on the baseprofile

				select_status[$select_idx]="invalid"
				(( invalid_baseprofiles++ ))
			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"
			(( select_idx++ ))
		fi
	done

	# NOTE: select_idx is intentionally not
	#       reset before continuing below
	role_count="0"
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "role" ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"

			if [[ "$DEBUG" == "true" ]]; then
				echo -e "\\n\
${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]} (role)${Color_Off}\\n\\n
merged_ident: ${merged_ident[$idx]}\\n\
merged_role_source_profile_ident: ${merged_role_source_profile_ident[$idx]}\\n\
merged_type: ${merged_type[${merged_role_source_profile_idx[$idx]}]}
merged_role_source_baseprofile_ident: ${merged_role_source_baseprofile_ident[$idx]}\\n\
merged_baseprofile_arn: ${merged_baseprofile_arn[${merged_role_source_baseprofile_ident[$idx]}]}\\n\\n"
			fi

			select_type[$select_idx]="role"
			(( role_count++ ))

			if [[ "${merged_role_arn[$idx]}" == "" ]]; then  # does not have an arn
				
				select_status[$select_idx]="invalid"

			elif [[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then  # does not have a source_profile

				select_status[$select_idx]="invalid_nosource"

			elif [[ "${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_type[${merged_role_source_profile_idx[$idx]}]}" == "role" &&  # .. but it's a role..
					"${merged_role_source_baseprofile_ident[$idx]}" != "${merged_ident[${merged_role_source_profile_idx[$idx]}]}" &&  # .. and the source baseprofile ident doesn't equal source profile ident
					"${merged_baseprofile_arn[${merged_role_source_baseprofile_ident[$idx]}]}" != "" ]]; then  # and the source baseprofile has an Arn

				# chained profile with a [role] source profile
				# and a valid source baseprofile up the chain
				# (always requires role session to auth)
				if [[ "${merged_has_session[${merged_role_source_profile_idx[$idx]}]}" == "true" ]] &&
					# this index -> source_profile index -> source_profile's session index -> session status
					[[ ! "${merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$idx]}]}]}" =~ ^(expired|invalid)$ ]]; then
	
					select_status[$select_idx]="chained_source_valid"
				else
					select_status[$select_idx]="chained_source_invalid"
				fi

			elif [[ "${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_baseprofile_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then

				select_status[$select_idx]="invalid_source"

			elif [[ "${merged_role_mfa_required[$idx]}" == "false" ]]; then  # above OK + no MFA required (confirmed w/quick off)

				select_status[$select_idx]="valid"

			elif [[ "${merged_role_mfa_required[$idx]}" == "true" ]] &&  # MFA is required..
				 [[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # .. and the source_profile has a valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="valid"

			elif [[ "${merged_role_mfa_required[$idx]}" == "true" ]] &&  # MFA is required..
				 [[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then  # .. and the source_profile has no valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="invalid_mfa"

			fi

			select_merged_idx[$select_idx]="$idx"
			select_has_session[$select_idx]="${merged_has_session[$idx]}"
			select_merged_session_idx[$select_idx]="${merged_session_idx[$idx]}"
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

			echo -e "${BIWhite}${On_Black}You have one configured profile: ${select_ident[0]}${Color_Off} (IAM: ${merged_username[${select_merged_idx[0]}]}${pr_accn})"
			if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" == "true" ]]; then
				echo -en "${Green}${On_Black}.. and its virtual MFA device is already enabled"

				print_disablement_notice="false"
				if [[ "${select_has_session[0]}" == "true" ]] &&
					[[ "${merged_invalid_as_of[${select_merged_session_idx[0]}]}" == "" ]] &&
					[[ "${merged_aws_access_key_id[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_aws_secret_access_key[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_aws_session_token[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]]; then

					if [[ "${merged_session_remaining[${select_merged_session_idx[0]}]}" != "-1" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[0]}]}"

						echo -e "${Green}${On_Black}, and it has a session with $pr_remaining of validity remaining.\\n\\n${BIWhite}Do you want to disable its vMFAd? Y/N "
					else
						print_disablement_notice="true"
					fi
				else
					print_disablement_notice="true"
				fi

				if [[ "$print_disablement_notice" == "true" ]]; then

					echo -e ", but it has no session.\\n${BIYellow}${On_Black}\
An active MFA session is required to disable the vMFA device.${Color_Off}\\n\
Run ${BIWhite}${On_Black}awscli-mfa.sh${Color_Off} and start a session for the profile first,\\n\
then try again. If you no longer have access to the vMFA token\\n\
generator for this account, you need to either use the admin\\n\
credentials to disable the vMFAd, or if you don't have such,\\n\
contact ops/support to have it disabled.\\n\
\\n\
${BIRed}${On_Black}Cannot continue without an active session.${Color_Off}"

					exit 1
				fi

				yesNo _ret

				if [[ "${_ret}" == "yes" ]]; then
					selprofile="1"
				else
					echo -e "\\n\\nA vMFAd not disabled/detached. Exiting.\\n"
					exit 1
				fi

			else
				echo -en ".. but it doesn't have a virtual MFA device attached/enabled.\\n\\n${BIWhite}${On_Black}Do you want to attach/enable a vMFAd? Y/N${Color_Off} "

				yesNo _ret

				if [[ "${_ret}" == "yes" ]]; then
					selprofile="1"
				else
					echo -e "\\n\\nA vMFAd not attached/enabled. Exiting.\\n"
					exit 1
				fi
			fi

		else  # no baseprofiles in 'valid' status; bailing out

			echo -e "${BIRed}${On_Black}No valid baseprofiles found; please check your AWS configuration files.\\nCannot continue.${Color_Off}\\n\\n"
			exit 1
		fi

	# MULTI-PROFILE MENU
	elif [[ "${baseprofile_count}" -gt 1 ]]; then  # more than one baseprofile is present..								#3 - >1 BASEPROFILES (W/WO SESSION)

echo -e "${BIYellow}${On_Black}\\n\
NOTE: Role profiles are not displayed even if they exist\\n\
      because a role cannot have an attached vMFA device.${Color_Off}\\n"

		if [[ "$valid_baseprofiles_no_mfa" -gt 0 ]]; then

			# create the profile selections for "no vMFAd configured" and "vMFAd enabled"
			echo
			echo -e "${BIWhite}${On_Red} AWS PROFILES WITH NO ATTACHED/ENABLED VIRTUAL MFA DEVICE (\"vMFAd\"): ${Color_Off}\\n"
			echo -e "${BIWhite}${On_Black} Select a profile to which you want to attach/enable a vMFAd.${Color_Off}\\n A new vMFAd is created/initialized if one doesn't exist."
			echo

			# this may be different as this count will not include
			# the invalid, non-selectable profiles
			selectable_multiprofiles_count="0"
			display_idx="0"

			[[ "$DEBUG" == "true" ]] && echo -e "${BIYellow}${On_Black}Looking for valid profiles with no vMFAd${Color_Off}"
			for ((idx=0; idx<${#select_ident[@]}; ++idx))
			do
				[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}select_ident: ${select_ident[$idx]}, select_type: ${select_type[$idx]}, select_status: ${select_status[$idx]}${Color_Off}"

				if [[ "${select_type[$idx]}" == "baseprofile" ]] &&
					[[ "${select_status[$idx]}" == "valid" ]] &&
					[[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" == "" ]]; then

					# increment selectable_multiprofiles_count
					(( selectable_multiprofiles_count++ ))

					# make a more-human-friendly selector digit (starts from 1)
					(( display_idx++ ))

					# reference to the select_display array
					select_display[$display_idx]="$idx"

					pr_user="${merged_username[${select_merged_idx[$idx]}]}"

					if [[ "${merged_account_alias[${select_merged_idx[$idx]}]}" != "" ]]; then
						# account alias available
						pr_accn=" @${merged_account_alias[${select_merged_idx[$idx]}]}"
					elif [[ "${merged_account_id[${select_merged_idx[$idx]}]}" != "" ]]; then
						# use the AWS account number if no alias has been defined
						pr_accn=" @${merged_account_id[${select_merged_idx[$idx]}]}"
					fi

					if [[ "${merged_baseprofile_operational_status[${select_merged_idx[$idx]}]}" == "reqmfa" ]]; then
						mfa_enforced="; ${Yellow}${On_Black}MFA may be enforced${Color_Off}"
					else
						mfa_enforced=""
					fi

					# print the baseprofile entry
					echo -e "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_enforced})\\n"

				fi
			done
		fi

		if [[ "$valid_baseprofiles_with_mfa" -gt 0 ]]; then

			echo
			echo -e "${BIWhite}${On_DGreen} AWS PROFILES WITH ATTACHED/ENABLED VIRTUAL MFA DEVICE (\"vMFAd\"): ${Color_Off}\\n"
			echo -e "${BIWhite}${On_Black}\
 Select a profile whose vMFAd you want to detach/disable.${Color_Off}\\n\
 Once detached, you'll have the option to delete the vMFAd.\\n\
 \\n\
 NOTE: A profile must have an active MFA session to disable, or you must have\\n\
       another configured profile or a session which is authorized to disable\\n\
       the vMFAd of the selected profile. If the selected profiled doesn't have\\n\
       an active MFA session, you'll be presented with a list of the available\\n\
       baseprofiles and sessions to select from to authorize the vMFAd removal with.\\n"

			[[ "$DEBUG" == "true" ]] && echo -e "${BIYellow}${On_Black}Looking for valid profiles with vMFAd attached/enabled${Color_Off}"
			for ((idx=0; idx<${#select_ident[@]}; ++idx))
			do
				[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}select_ident: ${select_ident[$idx]}, select_type: ${select_type[$idx]}, select_status: ${select_status[$idx]}${Color_Off}"

				if [[ "${select_type[$idx]}" == "baseprofile" ]] &&
					[[ "${select_status[$idx]}" == "valid" ]] &&
					[[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" != "" ]]; then

					# increment selectable_multiprofiles_count
					(( selectable_multiprofiles_count++ ))

					# make a more-human-friendly selector digit (starts from 1)
					(( display_idx++ ))

					# reference to the select_display array
					select_display[$display_idx]="$idx"

					pr_user="${merged_username[${select_merged_idx[$idx]}]}"

					if [[ "${merged_account_alias[${select_merged_idx[$idx]}]}" != "" ]]; then
						# account alias available
						pr_accn=" @${merged_account_alias[${select_merged_idx[$idx]}]}"
					elif [[ "${merged_account_id[${select_merged_idx[$idx]}]}" != "" ]]; then
						# use the AWS account number if no alias has been defined
						pr_accn=" @${merged_account_id[${select_merged_idx[$idx]}]}"
					fi

					if [[ "${merged_baseprofile_operational_status[${select_merged_idx[$idx]}]}" == "reqmfa" ]]; then
						mfa_enforced="; ${Yellow}${On_Black}MFA may be enforced${Color_Off}"
					else
						mfa_enforced=""
					fi

					# print the baseprofile entry
					echo -en "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_enforced}"

					# print an associated session entry if one exist and is valid
					if [[ "${select_has_session[$idx]}" == "true" ]] &&
						[[ "${merged_invalid_as_of[${select_merged_session_idx[$idx]}]}" == "" ]] &&
						[[ "${merged_aws_access_key_id[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_secret_access_key[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_session_token[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" == "valid" ]]; then

						if [[ "${merged_session_remaining[${select_merged_session_idx[$idx]}]}" != "-1" ]]; then

							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"
							echo -e "; ${BIPurple}${On_Black}has an MFA session with ${pr_remaining} remaining)${Color_Off}\\n"
						else
							echo -e ")${Color_Off}\\n"
						fi
					else
						echo -e ")${Color_Off}\\n"
					fi
				fi
			done
		fi

		if [[ "$invalid_baseprofiles" -gt 0 ]]; then

			echo
			echo -e "${BIWhite}${On_Blue} INVALID PROFILES (shown for reference only): ${Color_Off}\\n"

			[[ "$DEBUG" == "true" ]] && echo -e "${BIYellow}${On_Black}Looking for invalid profiles (for display only)${Color_Off}"
			for ((idx=0; idx<${#select_ident[@]}; ++idx))
			do
				[[ "$DEBUG" == "true" ]] && echo -e "${Yellow}${On_Black}select_ident: ${select_ident[$idx]}, select_type: ${select_type[$idx]}, select_status: ${select_status[$idx]}${Color_Off}"

				if [[ "${select_type[$idx]}" == "baseprofile" ]] &&
					[[ "${select_status[$idx]}" != "valid" ]]; then

					# print the baseprofile entry
					echo -e "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (credentials have no access)\\n"
				fi
			done
		fi

	else
		echo -e "\\n${BIRed}${On_Black}No valid baseprofiles present. Cannot continue.${Color_Off}"
		exit 1
	fi

	if [[ "${valid_baseprofiles}" -gt 0 ]]; then

#todo: if the selected profile has no profile and valid_baseprofiles = 1 -> exit

		# prompt for profile selection
		echo -en  "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE NUMBER:${Color_Off} "
		read -r selprofile
	fi

	# PROCESS THE SELECTION -------------------------------------------------------------------------------------------

	if [[ "$selprofile" != "" ]]; then

		[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** selection received: ${selprofile}${Color_Off}"

		# check for a valid selection pattern
		if [[ ! "$selprofile" =~ ^[[:digit:]]+$ ]]; then

			# non-acceptable characters were present in the selection -> exit
			echo -e "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n"
			exit 1
		fi

		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_selval="${BASH_REMATCH[1]}"
		
		if [[ "$selprofile_selval" != "" ]]; then
			# if the numeric selection was found, 
			# translate it to the array index and validate

			(( adjusted_display_idx=selprofile_selval-1 ))

			# first check that the selection is in range:
			# does the selected profile exist? (this includes baseprofiles/roleprofiles);
			if [[ $adjusted_display_idx -ge $selectable_multiprofiles_count ||
				$adjusted_display_idx -lt 0 ]] &&
			
				[[ "$single_profile" == "false" ]]; then

				# a selection outside of the existing range was specified -> exit
				echo -e "${BIRed}${On_Black}There is no profile '${selprofile_selval}'. Cannot continue.${Color_Off}\\n"
				exit 1
			fi

			# look up select index by the selected display index
			selprofile_idx="${select_display[$selprofile_selval]}"
			selected_merged_idx="${select_merged_idx[$selprofile_idx]}"
			selected_merged_ident="${merged_ident[$selected_merged_idx]}"

			aws_account_id="${merged_account_id[$selected_merged_idx]}"
			aws_iam_user="${merged_username[$selected_merged_idx]}"

			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** selprofile_idx: ${selprofile_idx}${Color_Off}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** display index in select array: ${selprofile} (${select_ident[$selprofile_idx]})${Color_Off}"
			[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}** corresponding merged index/ident: ${selected_merged_idx} (${merged_ident[${selected_merged_idx}]})${Color_Off}"

			echo -en "\\n[Preparing to "

			if [[ "${merged_mfa_arn[$selected_merged_idx]}" == "" ]]; then
				echo -e "enable the vMFAd for the profile ${BIWhite}${On_Black}${merged_ident[${selected_merged_idx}]}${Color_Off}]\\n"

# --- begin code import

				available_user_vmfad=$(aws iam list-virtual-mfa-devices \
					--profile "${selected_merged_ident}" \
					--assignment-status Unassigned \
					--output text \
					--query 'VirtualMFADevices[?SerialNumber==`arn:aws:iam::'"${aws_account_id}"':mfa/'"${aws_iam_user}"'`].SerialNumber' 2>&1)

				if [[ "$DEBUG" == "true" ]]; then
					echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-virtual-mfa-devices --profile \"${selected_merged_ident}\" --assignment-status Unassigned --query 'VirtualMFADevices[?SerialNumber==´arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}´].SerialNumber' --output text':\\n${ICyan}${available_user_vmfad}${Color_Off}\\n\\n"
				fi

				existing_mfa_deleted="false"

				if [[ "$available_user_vmfad" =~ 'error occurred' ]]; then

					echo -e "${BIRed}${On_Black}Could not execute list-virtual-mfa-devices. Cannot continue.${Color_Off}\\n"
					exit 1

				elif [[ "$available_user_vmfad" != "" ]]; then
					unassigned_vmfad_preexisted="true"

					echo -e "${Green}${On_Black}Unassigned vMFAd found for the profile:\\n${BIGreen}$available_user_vmfad${Color_Off}\\n"
					echo -en "${BIWhite}${On_Black}\
Do you have access to the above vMFAd on your GA/Authy device?${Color_Off}\\n\
\\n\
'No' will delete the vMFAd and create a new one thus\\n\
voiding the possible existing GA/Authy entry.\\n\
Make your choice: ${BIWhite}${On_Black}Y/N${Color_Off} "

					while :
					do	
						read -s -n 1 -r
						if [[ $REPLY =~ ^[Yy]$ ]]; then
							echo
							break;

						elif [[ $REPLY =~ ^[Nn]$ ]]; then
							mfa_deletion_result=$(aws iam delete-virtual-mfa-device \
								--profile "${selected_merged_ident}" \
								--serial-number "${available_user_vmfad}" 2>&1)

							if [[ "$DEBUG" == "true" ]]; then
								echo -e "\\n${Cyan}${On_Black}result for: 'aws iam delete-virtual-mfa-device --profile \"${selected_merged_ident}\" --serial-number \"${available_user_vmfad}\"':\\n${ICyan}${mfa_deletion_result}${Color_Off}\\n\\n"
							fi

							# this bails out on errors
							checkAWSErrors _is_error "true" "$mfa_deletion_result" "$selected_merged_ident" "Could not delete the inaccessible vMFAd. Cannot continue!"

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

					bootstrap_method="QRCodePNG"
					unassigned_vmfad_preexisted="false"
					
					vmfad_secret_file_name="${selected_merged_ident}_vMFAd_QRCode.png"
					
					# replace possible spaces in the profile name with underscores
					vmfad_secret_file_name="${vmfad_secret_file_name// /_}"

					if [[ "$OS" == "macOS" ]]; then

						qr_location_phrase="on your DESKTOP"
						secret_target_filepath="${HOME}/Desktop/${vmfad_secret_file_name}"

					elif [[ "$OS" == "WSL_Linux" ]]; then

						win_temp_path="$(cmd.exe /c echo %tmp%)"

						if [[ "${win_temp_path}" =~ ^([[:alpha:]]:\\Users\\[[:alpha:]]+)\\ ]]; then
							win_secret_target_path="${BASH_REMATCH[1]}"
							qr_location_phrase="in your WINDOWS HOME DIRECTORY (${win_secret_target_path}\\)"
						else
							win_secret_target_path="$win_temp_path"
							qr_location_phrase="in your WINDOWS TEMP DIRECTORY (${win_secret_target_path}\\)"
						fi						

						win_secret_target_filepath="${win_secret_target_path}\\${vmfad_secret_file_name}"
						win_secret_target_path_linux="$(wslpath -a "$win_secret_target_path")"
						win_secret_target_filepath_linux="${win_secret_target_path_linux}/${vmfad_secret_file_name}"
						secret_target_filepath="${HOME}/${vmfad_secret_file_name}"

					else  # Linux
						echo "Are you able to view image files on this system? "

						yesNo _ret
						if [[ "${_ret}" == "yes" ]]; then
							
							if [[ -d $HOME/Desktop ]]; then
								secret_target_filepath="${HOME}/Desktop/${vmfad_secret_file_name}"
								qr_location_phrase="on your DESKTOP"
							else
								secret_target_filepath="${HOME}/${vmfad_secret_file_name}"
								qr_location_phrase="in your HOME DIRECTORY ($HOME)"
							fi

						else  # seed string instead of QRcode

							bootstrap_method="Base32StringSeed"
							secret_target_filepath="$(mktemp "$HOME/tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")"
						fi
					fi

					echo -e "No available vMFAd found; creating new...\\n"

					vmfad_creation_status=$(aws iam create-virtual-mfa-device \
						--profile "${selected_merged_ident}" \
						--virtual-mfa-device-name "${aws_iam_user}" \
						--outfile "${secret_target_filepath}" \
						--bootstrap-method ${bootstrap_method} 2>&1)

					if [[ "$DEBUG" == "true" ]]; then
						echo -e "\\n${Cyan}${On_Black}result for: 'aws iam create-virtual-mfa-device --profile \"${selected_merged_ident}\" --virtual-mfa-device-name \"${aws_iam_user}\" --outfile \"${secret_target_filepath}\" --bootstrap-method QRCodePNG':\\n${ICyan}${vmfad_creation_status}${Color_Off}\\n\\n"
					fi

					# this bails out on errors
					checkAWSErrors _is_error "true" "$vmfad_creation_status" "$selected_merged_ident" "Could not execute create-virtual-mfa-device. No virtual MFA device to enable. Cannot continue!"

					# we didn't bail out; continuing...
					if [[ "$bootstrap_method" == "QRCodePNG" ]]; then

						# auto-open the QRCode on Mac, Windows
						auto_open_phrase=""
						if [[ "$OS" == "macOS" ]]; then

							sleep 2
							open "$secret_target_filepath"
							auto_open_phrase="      The QRCode has been opened for you.\\n"

						elif [[ "$OS" == "WSL_Linux" ]]; then

							cp "$secret_target_filepath" "$win_secret_target_filepath_linux"
							sleep 2
							cmd.exe /c start "$win_secret_target_filepath"
							auto_open_phrase="      The QRCode has been opened for you.\\n"
						fi

						echo -e "${BIGreen}${On_Black}\
A new vMFAd has been created.\\n${BIWhite}\
Please scan the QRCode with GA/Authy to\\n\
add the vMFAd on your portable device.${Color_Off}\\n\
\\n${BIYellow}${On_Black}\
NOTE: The QRCode file, ${BIWhite}\"${vmfad_secret_file_name}\",${BIYellow} is $qr_location_phrase!${Color_Off}\\n\
${auto_open_phrase}\\n${BIWhite}${On_Black}\
Press 'x' to proceed once you have scanned the QRCode.${Color_Off}"
						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Xx]$ ]]; then
								break;
							fi
						done

						echo -en "\\n${BIYellow}${On_Black}\
NOTE: Anyone who gains possession of the QRCode file can\\n\
      initialize the vMFDd like you just did, so optimally\\n\
      it should not be kept around.\\n${BIWhite}${On_Black}\

Do you want to delete the QRCode securely? Y/N${Color_Off} "

						while :
						do	
							read -s -n 1 -r

							if [[ $REPLY =~ ^[Yy]$ ]]; then

								if [[ "$OS" == "macOS" ]]; then
									rm -fP "${secret_target_filepath}"

								elif [[ "$OS" == "Linux" ]]; then
									shred -zu -n 5 "${secret_target_filepath}"
									
								elif [[ "$OS" == "WSL_Linux" ]]; then
									shred -zu -n 5 "${secret_target_filepath}"
									rm -f "$win_secret_target_filepath_linux"
								fi

								echo -e "\\n\\n${Green}${On_Black}QRCode file deleted securely.${Color_Off}"
								break;

							elif [[ $REPLY =~ ^[Nn]$ ]]; then

								echo -e "\\n\\n${BIYellow}${On_Black}\
You chose not to delete the vMFAd initializer QRCode;\\n
please store it securely as if it were a password!${Color_Off}"
								break;
							fi
						done
						echo

					else  # text-string vMFAd instead of QRcode

						vmfad_seed_string="$(cat $secret_target_filepath)"
						vmfad_seed_string_spaced="$(printf '%s' ${vmfad_seed_string} | sed 's/.\{4\}/& /g')"
						shred -zu -n 5 "${secret_target_filepath}"

						echo -e "${BIGreen}${On_Black}\
A new vMFAd has been created. ${BIWhite}${On_Black}Please enter the following string\\n\
into your Authy app to add the vMFAd on your portable device.${Color_Off}\\n\
\\n\
In Authy, select from the \"three dots\" menu:\\n\
'Add Account' -> 'ENTER KEY MANUALLY', then\\n\
enter the string below without spaces.\\n\\n"
						echo -e "${BIYellow}${On_Black}$vmfad_seed_string_spaced${Color_Off}\\n\\n"
						echo -e "Below the same as above but without spaces (for cut-and-pasting):\\n\\n$vmfad_seed_string\\n\\n"

						echo -e "${BIWhite}${On_Black}Press 'x' to proceed once you have finished entering the code.${Color_Off}"
						while :
						do	
							read -s -n 1 -r
							if [[ $REPLY =~ ^[Xx]$ ]]; then
								break;
							fi
						done

						echo -en "\\n${BIYellow}${On_Black}\
NOTE: Anyone who gains possession of the above seed string\\n\
      can initialize the vMFDd for this account like you just\\n\
      did, so if you choose to keep it around, save it securely\\n\
      as if it were a password.${Color_Off}\\n"

					fi

					available_user_vmfad=$(aws iam list-virtual-mfa-devices \
						--profile "${selected_merged_ident}" \
						--assignment-status Unassigned \
						--output text \
						--query 'VirtualMFADevices[?SerialNumber==`arn:aws:iam::'"${aws_account_id}"':mfa/'"${aws_iam_user}"'`].SerialNumber' 2>&1)
						
					if [[ "$DEBUG" == "true" ]]; then
						echo -e "\\n${Cyan}${On_Black}result for: 'aws iam list-virtual-mfa-devices --profile \"${selected_merged_ident}\" --assignment-status Unassigned --query 'VirtualMFADevices[?SerialNumber==´arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}´].SerialNumber' --output text':\\n${ICyan}${available_user_vmfad}${Color_Off}\\n\\n"
					fi

					# this bails out on errors
					checkAWSErrors _is_error "true" "$available_user_vmfad" "$selected_merged_ident" "Could not execute list-virtual-mfa-devices. Cannot continue!"

					# we didn't bail out; continuing...
				fi

				if [[ "$available_user_vmfad" == "" ]]; then
					# no vMFAd existed, none could be created
					echo -e "\\n${BIRed}${On_Black}No virtual MFA device to enable. Cannot continue.${Color_Off}"
					exit 1
				else
					[[ "$unassigned_vmfad_preexisted" == "true" ]] && vmfad_source="existing" || vmfad_source="newly created"
					echo -e "\\nNow enabling the $vmfad_source virtual MFA device:\\n$available_user_vmfad"
				fi

				echo
				echo -e "${BIWhite}${On_Black}\
Please enter two consecutively generated authcodes\\n\
from your GA/Authy app for this profile.${Color_Off}\\n\
Enter the two six-digit codes separated by a space\\n\
(e.g. 123456 456789), then press enter to complete the process.\\n"

				while :
				do	
					echo -en "${BIWhite}${On_Black}"
					read -p ">>> " -r authcodes
					echo -en "${Color_Off}"
					if [[ $authcodes =~ ^([[:digit:]]{6})[[:space:]]+([[:digit:]]{6})$ ]]; then
						authcode1="${BASH_REMATCH[1]}"
						authcode2="${BASH_REMATCH[2]}"
						break;
					elif [[ $authcodes =~ ^[[:digit:]]+$ ]]; then
						echo -e "${BIRed}${On_Black}Only one code entered.${Color_Off} Please enter ${BIWhite}${On_Black}two${Color_Off} consecutively generated six-digit numbers separated by a space."
					else
						echo -e "${BIRed}${On_Black}Bad authcodes.${Color_Off} Please enter two consecutively generated six-digit numbers separated by a space."
					fi
				done

				echo

				vmfad_enablement_status=$(aws iam enable-mfa-device \
					--profile "${selected_merged_ident}" \
					--user-name "${aws_iam_user}" \
					--serial-number "${available_user_vmfad}" \
					--authentication-code-1 "${authcode1}" \
					--authentication-code-2 "${authcode2}"  2>&1)

				if [[ "$DEBUG" == "true" ]]; then
					echo -e "\\n${Cyan}${On_Black}result for: 'aws iam enable-mfa-device --profile \"${selected_merged_ident}\" --user-name \"${aws_iam_user}\" --serial-number \"${available_user_vmfad}\" --authentication-code-1 \"${authcode1}\" --authentication-code-2 \"${authcode2}\"':\\n${ICyan}${vmfad_enablement_status}${Color_Off}\\n\\n"
				fi

				# this bails out on errors
				checkAWSErrors _is_error "true" "$vmfad_enablement_status" "$selected_merged_ident" "Could not enable vMFAd. Cannot continue.\\n${Red}Mistyped authcodes, or wrong/old vMFAd?"

				# we didn't bail out; continuing...
				echo -e "${BIGreen}${On_Black}vMFAd successfully enabled for the profile '${selected_merged_ident}' ${Green}(IAM user name '$aws_iam_user').${Color_Off}"
				echo -e "${BIGreen}${On_Black}You can now use the 'awscli-mfa.sh' script to start an MFA session for this profile!${Color_Off}"
				echo

#todo: write the vMFA arn to config for the profile, associated roles w/mfareq

			# A vMFA IS PRESENT -- DISABLE IT ---------------------------------------------------------------------------------
			else  # MFA arn is present -- disable

				echo -en "disable the vMFAd for the profile ${BIWhite}${On_Black}${merged_ident[${selected_merged_idx}]}${Color_Off}]\\n\\nChecking for the MFA session... "

#todo: in-env only?
				if [[ "${select_has_session[$selprofile_idx]}" == "true" ]] &&
					[[ "${merged_session_status[${select_merged_session_idx[$selprofile_idx]}]}" == "valid" ]]; then

					getRemaining jit_remaining_time "${merged_aws_session_expiry[${select_merged_session_idx[$selprofile_idx]}]}" "jit"
					if [[ "$jit_remaining_time" -lt 10 ]]; then
						echo -e "${BIRed}${On_Black}❌ NO VALID SESSION\\n${Red}The selected profile's required MFA session expired while waiting. Cannot continue.${Color_Off}\\n"
#todo: select another profile for auth or exit
						exit 1
					fi

					echo -e "${BIGreen}${On_Black}✓ SESSION VERIFIED${Color_Off}\\n"
				else

					echo -e "${BIRed}${On_Black}\
❌ NO VALID SESSION${Color_Off}\\n\\n${Red}\
The profile whose vMFAd you wish to detach/disable must have an active MFA session. Cannot continue.${Color_Off}\\n"
#todo: select another profile for auth or exit
					exit 1
				fi

				vmfad_deactivation_result=$(aws iam deactivate-mfa-device \
					--profile "${selected_merged_ident}-mfasession" \
					--user-name "${aws_iam_user}" \
					--serial-number "arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}" 2>&1)

				[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam deactivate-mfa-device --profile \"${selected_merged_ident}-mfasession\" --user-name \"${aws_iam_user}\" --serial-number \"arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\"':\\n${ICyan}${vmfad_deactivation_result}${Color_Off}\\n\\n"

				# this bails out on errors
				checkAWSErrors _is_error "false" "$vmfad_deactivation_result" "$selected_merged_ident" "Could not disable/detach vMFAd for the profile '${selected_merged_ident}'. Cannot continue!"

#todo: offer to select another profile

				if [[ "${_is_error}" == "true" ]]; then
					print_mfa_notice
					exit 1
				fi

				# we didn't bail out; continuing...
				echo -e "${BIGreen}${On_Black}vMFAd disabled/detached for the profile '${selected_merged_ident}'.${Color_Off}\\n"

				echo -en "${BIYellow}${On_Black}\
Do you want to ${BIRed}DELETE${BIYellow} the disabled/detached vMFAd?${Color_Off}\\n\
Once deleted, the vMFA entry in your GA/Authy app becomes invalid, and\\n\
you need to re-add the vMFAd to your app when you want to re-enable it.\\n\
Note that configured but detached vMFA's may be culled periodically, so\\n\
if you leave it detached for some amount of time, you may need to re-add\\n\
it anyway. So, should we delete it? ${BIWhite}${On_Black}Y/N${Color_Off} "

				yesNo _ret

				if [[ "${_ret}" == "yes" ]]; then
					vmfad_delete_result=$(aws iam delete-virtual-mfa-device \
						--profile "${selected_merged_ident}" \
						--serial-number "arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}")

					[[ "$DEBUG" == "true" ]] && echo -e "\\n${Cyan}${On_Black}result for: 'aws iam delete-virtual-mfa-device --profile \"${selected_merged_ident}\" --serial-number \"arn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\"':\\n${ICyan}${vmfad_delete_result}${Color_Off}\\n\\n"

					# this bails out on errors
					checkAWSErrors _is_error "true" "$vmfad_delete_result" "$selected_merged_ident" "Could not delete vMFAd for the profile '${selected_merged_ident}'. Cannot continue!"

					# we didn't bail out; continuing...
					echo -e "\\n\\n${Green}${On_Black}\
vMFAd deleted for the profile '${selected_merged_ident}'.${Color_Off}\\n\
\\n\
To set up a new vMFAd, run this script again.\\n"

				else
					echo -e "\\n\\n${BIWhite}${On_Black}The following vMFAd was disabled/detached, but not deleted:${Color_Off}\\narn:aws:iam::${aws_account_id}:mfa/${aws_iam_user}\\n\\nNOTE: Detached vMFAd's may be automatically deleted after some time.\\n"
					exit 0
				fi

#todo: delete the vMFA arn off of the profile's config & from the assoc roles

			fi  # closes [[ "${merged_mfa_arn[$selected_merged_idx]}" != "" ]]

		else
			# no numeric part in selection
			echo -e "\\n${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}"
			echo
			exit 1
		fi
	else
		# empty selection
		echo -e "\\n${BIRed}${On_Black}You didn't choose a profile. Cannot continue.${Color_Off}"
		echo
		exit 1
	fi
fi
