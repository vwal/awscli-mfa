#!/usr/bin/env bash

################################################################################
# RELEASE: 19 November 2019 - MIT license
  script_version="2.7.6"  # < use valid semver only; see https://semver.org
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

# quick_mode="true" -- skip dynamic profile checks (faster but no validity checks or profile intelligence)
# quick_mode="false" -- do full profile checks every time (slower but with validity checks and full profile intelligence)
#
# override quick_mode="false" -> "true" with '-q' or '--quick' param
# override quick_mode="true" -> "false" with '-f' or '--full' param
#
# set the default mode
quick_mode="false"

# set monochrome mode off
monochrome="false"

# translate long command line args to short
reset="true"
for arg in "$@"
do
	if [ -n "$reset" ]; then
		unset reset
		set --  # this resets the "$@" array so we can rebuild it
	fi
	case "$arg" in
		--help)			set -- "$@" -h ;;
		--quick)		set -- "$@" -q ;;
		--full)			set -- "$@" -f ;;
		--monochrome)	set -- "$@" -m ;;
		--debug)		set -- "$@" -d ;;
		# pass through anything else
		*)			set -- "$@" "$arg" ;;
	esac
done
# process with getopts
OPTIND="1"
while getopts "qfmdh" opt; do
    case $opt in
        "q")  quick_mode="true" ;;
        "f")  quick_mode="false" ;;
        "m")  monochrome="true" ;;
        "d")  DEBUG="true" ;;
        "h"|\?) printf "Usage: awscli-mfa.sh [-q/--quick] [-f/--full] [-m/--monochrome] [-d/--debug]\\n\\n"; exit 1;;
    esac
done
shift $((OPTIND-1))

printf "Starting...\\n\\n"

# Set the global MFA session length in seconds below; note that this only sets
# the client-side duration for the MFA session token! The maximum length of a
# valid session is enforced by the IAM policy and is unaffected by this value
# (if this duration is set to a longer value than the enforcing value in the
# IAM policy, the token will stop working before it expires on the client side).
# Matching this value with the enforcing IAM policy provides you with accurate
# detail about how long a token will continue to be valid.
#
# Unlike for the role sessions, AWS doesn't natively provide a way to broadcast
# the maximum session length to the clients. For this reason, you want to match
# the below value with what you set for the maximum MFA session length in your
# MFA enforcement policy. However, the script also allows you to set an AWS Systems
# Manager Parameter Store parameter "/unencrypted/mfa/session_length" to override
# the below default. This way, you can easily modify the maximum MFA session
# length after you have deployed this script in your organization. You can also
# set the maximum session length for each AWS account if you utilize multiple
# accounts (such as master account + subaccounts). See the README.md for further
# details.
#
# THIS VALUE CAN BE OPTIONALLY OVERRIDDEN PER EACH BASE PROFILE BY ADDING
# A "sessmax" ENTRY FOR A BASE PROFILE IN ~/.aws/config
#
# The AWS-side IAM policy may be set to session lengths between 900 seconds
# (15 minutes) and 129600 seconds (36 hours). The example value below is set
# to 32400 seconds, or 9 hours (you'll find the matching example value in the
# example MFA policies located in the 'example-mfa-policies' folder).
MFA_SESSION_LENGTH_IN_SECONDS="32400"

# ** NOTE: The below override default changed as of release 2.7.1 on 2019-11-03 **
# 
# Because the IAM accounts are global, because the profiles are considered
# valid even without a region defined, and because the AWS Secrets Manager
# Parameter Store (SSM) is region-specific, it makes sense to standardize on
# a singular region to hold the MFA session length detail as well as the cross-
# account role details. This both simplifies the management of this information
# and ensures that the information is accessible (when defined) even if a
# profile omits the region definition. In case you have compartmentalized the
# SSM access of the IAM users in your AWS account to specific regions with
# policies and thus maintain this information in multiple regions, you should
# clear the variables below so that profile-specific region will take effect
# (like before release 2.7.1). Also, if this script is in multi-org use and/or
# you have no control over the region(s) the MFA session length and/or the
# cross-account# role details are being advertised, you may want to blank the
# two variables below to rely on each profile's region definition. Furthermore,
# if you primarily operate in some other region besides us-east-1 (and/or don't
# want to keep the SSM details in this region), you can change this lookup
# aggregation region to a region of your choice.

# This parameter causes all account MFA session lookups from SSM to occur
# in us-east-1. Blank this variable to use the profile-specific region, or
# set a different region for the aggregated SSM lookups.
MFA_SESSION_LENGTH_LOOKUP_REGION_OVERRIDE="us-east-1"

# (Read the above rationale for now defined aggregate lookup region!)
# 
# Similarly, as with the above override, this parameter sets the region where
# all the cross-account role property SSM lookups will take place. Blank this
# variable to use instead the region defined in each authorized base profile
# (i.e., in the profiles used to assume the cross-account roles).
XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE="us-east-1"

# Set the global ROLE session length in seconds below; this value is used when
# the enforcing IAM policy disallows retrieval of the maximum role session
# length (when a live value is available, such as when the attached example MFA
# policies or their derivatives are used, it always takes precedence over this
# value). However, in such cases, this value can still be effective for third
# party roles.
#
# The default role session length set by AWS for CLI access is 3600 seconds,
# or 1 hour. This length can be altered in the role policy to range from 900
# seconds (15 minutes) to 129600 seconds (36 hours).
#
# Note that just like the maximum session length for the MFA sessions set above,
# this value only sets the client-side maximum duration for the role session
# token! Changing this value does not affect the session length enforced by the
# policy, however, unlike with the MFA sessions (where an incorrect duration
# simply results in an incorrect validity period indication), if the role
# duration is set to a greater value than the enforcing value in the role's IAM
# policy (often it is 3600 seconds when a role session length hasn't been
# explicitly defined in the policy), the role session token request WILL FAIL.
#
# Furthermore, this value can also be optionally overridden per each role
# profile by adding a "sessmax" entry for a role in ~/.aws/config (this can be
# useful in situations where the maximum session length isn't available from
# AWS, such as when assuming a role at a third-party AWS account whose policy
# disallows access to this information). A profile-specific sessmax entry can
# be set to a shorter period than the role's defined maximum session length or
# to a longer period than the default below (assuming the role's policy allows
# it).
#
# As a final note, a role session longer than 3600 seconds (1h) is only
# allowed (assuming it's allowed by the role policy) when the role session
# being initiated is the primary/initial session (i.e. either assumed using
# the source/parent baseprofile credentials, or authorized directly using the
# baseprofile's vMFA device). A "chained role", i.e. using an existing role
# session to assume a new role, or using an existing persisted baseprofile MFA
# session, automatically limits the session length to 3600 seconds regardless
# of the maximum allowed length by the role policy, or regardless of the
# setting below, or regardless of a role profile "sessmax" value (this script
# automatically truncates the session length to 3600 seconds to avoid failed
# session initialization that otherwise would follow).
ROLE_SESSION_LENGTH_IN_SECONDS="3600"

# Define the standard locations for the AWS credentials and config files;
# these can be statically overridden with AWS_SHARED_CREDENTIALS_FILE and
# AWS_CONFIG_FILE envvars
CONFFILE="$HOME/.aws/config"
CREDFILE="$HOME/.aws/credentials"

# The minimum time required (in seconds) remaining in an MFA or a role session
# for it to be considered valid
VALID_SESSION_TIME_SLACK="300"

# COLOR DEFINITIONS ===================================================================================================

if [[ "$monochrome" == "false" ]]; then

	# Reset
	Color_Off='\033[0m'       # Color reset

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

else  # monochrome == "true"

	# Reset
	Color_Off=''    # Color reset

	# Regular Colors
	Black=''        # Black
	Red=''          # Red
	Green=''        # Green
	Yellow=''       # Yellow
	Blue=''         # Blue
	Purple=''       # Purple
	Cyan=''         # Cyan
	White=''        # White

	# Bold
	BBlack=''       # Black
	BRed=''         # Red
	BGreen=''       # Green
	BYellow=''      # Yellow
	BBlue=''        # Blue
	BPurple=''      # Purple
	BCyan=''        # Cyan
	BWhite=''       # White

	# Underline
	UBlack=''       # Black
	URed=''         # Red
	UGreen=''       # Green
	UYellow=''      # Yellow
	UBlue=''        # Blue
	UPurple=''      # Purple
	UCyan=''        # Cyan
	UWhite=''       # White

	# Background
	On_Black=''     # Black
	On_Red=''       # Red
	On_Green=''     # Green
	On_Yellow=''    # Yellow
	On_Blue=''      # Blue
	On_Purple=''    # Purple
	On_Cyan=''      # Cyan
	On_White=''     # White

	# High Intensity
	IBlack=''       # Black
	IRed=''         # Red
	IGreen=''       # Green
	IYellow=''      # Yellow
	IBlue=''        # Blue
	IPurple=''      # Purple
	ICyan=''        # Cyan
	IWhite=''       # White

	# Bold High Intensity
	BIBlack=''      # Black
	BIRed=''        # Red
	BIGreen=''      # Green
	BIYellow=''     # Yellow
	BIBlue=''       # Blue
	BIPurple=''     # Purple
	BICyan=''       # Cyan
	BIWhite=''      # White

	# High Intensity backgrounds
	On_IBlack=''   # Black
	On_IRed=''     # Red
	On_IGreen=''   # Green
	On_DGreen=''   # Dark Green
	On_IYellow=''  # Yellow
	On_IBlue=''    # Blue
	On_IPurple=''  # Purple
	On_ICyan=''    # Cyan
	On_IWhite=''   # White

fi

# DEBUG MODE WARNING & BASH VERSION ===================================================================================

if [[ "$DEBUG" == "true" ]]; then
	printf "\\n${BIWhite}${On_Red} DEBUG MODE ACTIVE ${Color_Off}\\n\\n${BIRed}${On_Black}NOTE: Debug output may include secrets!!!${Color_Off}\\n\\n\\n"
	printf "Using bash version $BASH_VERSION\\n\\n\\n"
fi

# QUICK MODE / FULL MODE NOTICE =======================================================================================

if [[ "$quick_mode" == "false" ]]; then
	printf "\
Tip: Use the quick mode ('--quick') to bypass the profile status checks\\n\
     for faster operation, especially if you have several profiles!${Color_Off}\\n\\n"
else
	printf "\
Tip: Use the full mode ('--full' or no option) to validate the profiles and to get more status information!${Color_Off}\\n\\n"
fi

# FUNCTIONS ===========================================================================================================

# 'exists' for commands
exists() {
	# $1 is the command being checked

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function exists] command: ${1}${Color_Off}\\n"

	# returns a boolean
	command -v "$1" >/dev/null 2>&1
}

# prompt for a selection: 'yes' or 'no'
yesNo() {
	# $1 is yesNo_result

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function yesNo]${Color_Off}\\n"

	local yesNo_result
	local old_stty_cfg

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	yesNo_result="$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )"
	stty "$old_stty_cfg"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: yesNo_result: ${yesNo_result}${Color_Off}\\n"

	if printf "$yesNo_result" | grep -iq "^n" ; then
		yesNo_result="no"
	else
		yesNo_result="yes"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${yesNo_result}${Color_Off}\\n"

	eval "$1=\"${yesNo_result}\""
}

# prompt for a selection: '1' or '2'
oneOrTwo() {
	# $1 is oneOrTwo_result

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function oneOrTwo]${Color_Off}\\n"

	local oneOrTwo_result
	local old_stty_cfg

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	oneOrTwo_result="$( while ! head -c 1 | grep -i '[12]' ;do true ;done )"
	stty "$old_stty_cfg"

	if printf "$oneOrTwo_result" | grep -iq "^1" ; then
		oneOrTwo_result="1"
	else
		oneOrTwo_result="2"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: oneOrTwo_result: ${oneOrTwo_result}${Color_Off}\\n"

	eval "$1=\"${oneOrTwo_result}\""
}

getLatestRelease() {
	# $1 is the repository name to check (e.g., 'vwal/awscli-mfa')

	curl --silent "https://api.github.com/repos/$1/releases/latest" |
	grep '"tag_name":' |
	sed -E 's/.*"([^"]+)".*/\1/'
}

# this function from StackOverflow
# https://stackoverflow.com/a/4025065/134536
versionCompare () {
	# $1 is the first semantic version string to compare
	# $2 is the second semantic version string to compare

	if [[ $1 == $2 ]]; then
		return 0
	fi
	local IFS=.
	local i ver1=($1) ver2=($2)
	# fill empty fields in ver1 with zeros
	for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
	do
		ver1[i]="0"
	done
	for ((i=0; i<${#ver1[@]}; i++))
	do
		if [[ -z ${ver2[i]} ]]; then
			# fill empty fields in ver2 with zeros
			ver2[i]="0"
		fi
		if ((10#${ver1[i]} > 10#${ver2[i]})); then
			return 1
		fi
		if ((10#${ver1[i]} < 10#${ver2[i]})); then
			return 2
		fi
	done
	return 0
}

# precheck envvars for existing/stale session definitions
env_aws_status="unknown"  # unknown until status is actually known, even if it is 'none'
env_aws_type=""
checkInEnvCredentials() {

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function checkInEnvCredentials]${Color_Off}\\n"

	local _ret
	local this_session_expired="unknown"	# marker for AWS_SESSION_EXPIRY ('unknown' remains only if absent or corrupt)
	local active_env="false"				# any AWS_ envvars present in the environment
	local env_selector_present="false"		# AWS_DEFAULT_PROFILE present? (we don't care about AWS_PROFILE since awscli doesn't honor it)
	local env_secrets_present="false"		# are [any] in-env secrets present?
	local active_env_session="false"		# an apparent AWS session (mfa or role) present in the env (a token is present)
	local expired_word=""
	local profile_prefix=""

	# COLLECT THE AWS_ ENVVAR DATA

	ENV_AWS_DEFAULT_PROFILE="$(env | grep '^AWS_DEFAULT_PROFILE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_DEFAULT_PROFILE" =~ ^AWS_DEFAULT_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_PROFILE="${BASH_REMATCH[1]}"
		active_env="true"
		env_selector_present="true"
	else
		unset ENV_AWS_DEFAULT_PROFILE
	fi

	ENV_AWS_PROFILE="$(env | grep '^AWS_PROFILE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_PROFILE" =~ ^AWS_PROFILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_PROFILE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_PROFILE
	fi

	ENV_AWS_PROFILE_IDENT="$(env | grep '^AWS_PROFILE_IDENT[[:space:]]*=.*')"
	if [[ "$ENV_AWS_PROFILE_IDENT" =~ ^AWS_PROFILE_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_PROFILE_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_PROFILE_IDENT
	fi

	ENV_AWS_SESSION_IDENT="$(env | grep '^AWS_SESSION_IDENT[[:space:]]*=.*')"
	if [[ "$ENV_AWS_SESSION_IDENT" =~ ^AWS_SESSION_IDENT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_IDENT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SESSION_IDENT
	fi

	ENV_AWS_ACCESS_KEY_ID="$(env | grep '^AWS_ACCESS_KEY_ID[[:space:]]*=.*')"
	if [[ "$ENV_AWS_ACCESS_KEY_ID" =~ ^AWS_ACCESS_KEY_ID[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_ACCESS_KEY_ID="${BASH_REMATCH[1]}"
		active_env="true"
		env_secrets_present="true"
	else
		unset ENV_AWS_ACCESS_KEY_ID
	fi

	ENV_AWS_SECRET_ACCESS_KEY="$(env | grep '^AWS_SECRET_ACCESS_KEY[[:space:]]*=.*')"
	if [[ "$ENV_AWS_SECRET_ACCESS_KEY" =~ ^AWS_SECRET_ACCESS_KEY[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SECRET_ACCESS_KEY="${BASH_REMATCH[1]}"
		ENV_AWS_SECRET_ACCESS_KEY_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
	else
		unset ENV_AWS_SECRET_ACCESS_KEY
	fi

	ENV_AWS_SESSION_TOKEN="$(env | grep '^AWS_SESSION_TOKEN[[:space:]]*=.*')"
	if [[ "$ENV_AWS_SESSION_TOKEN" =~ ^AWS_SESSION_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TOKEN="${BASH_REMATCH[1]}"
		ENV_AWS_SESSION_TOKEN_PR="[REDACTED]"
		active_env="true"
		env_secrets_present="true"
		active_env_session="true"
	else
		unset ENV_AWS_SESSION_TOKEN
	fi

	ENV_AWS_SESSION_TYPE="$(env | grep '^AWS_SESSION_TYPE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_SESSION_TYPE" =~ ^AWS_SESSION_TYPE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SESSION_TYPE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SESSION_TYPE
	fi

	ENV_AWS_SESSION_EXPIRY="$(env | grep '^AWS_SESSION_EXPIRY[[:space:]]*=.*')"
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

	ENV_AWS_DEFAULT_REGION="$(env | grep '^AWS_DEFAULT_REGION[[:space:]]*=.*')"
	if [[ "$ENV_AWS_DEFAULT_REGION" =~ ^AWS_DEFAULT_REGION[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_REGION="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_DEFAULT_REGION
	fi

	ENV_AWS_DEFAULT_OUTPUT="$(env | grep '^AWS_DEFAULT_OUTPUT[[:space:]]*=.*')"
	if [[ "$ENV_AWS_DEFAULT_OUTPUT" =~ ^AWS_DEFAULT_OUTPUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_DEFAULT_OUTPUT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_DEFAULT_OUTPUT
	fi

	ENV_AWS_CA_BUNDLE="$(env | grep '^AWS_CA_BUNDLE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_CA_BUNDLE" =~ ^AWS_CA_BUNDLE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CA_BUNDLE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_CA_BUNDLE
	fi

	ENV_AWS_SHARED_CREDENTIALS_FILE="$(env | grep '^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_SHARED_CREDENTIALS_FILE" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_SHARED_CREDENTIALS_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_SHARED_CREDENTIALS_FILE
	fi

	ENV_AWS_CONFIG_FILE="$(env | grep '^AWS_CONFIG_FILE[[:space:]]*=.*')"
	if [[ "$ENV_AWS_CONFIG_FILE" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_CONFIG_FILE="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_CONFIG_FILE
	fi

	ENV_AWS_METADATA_SERVICE_TIMEOUT="$(env | grep '^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=.*')"
	if [[ "$ENV_AWS_METADATA_SERVICE_TIMEOUT" =~ ^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=[[:space:]]*(.*)$ ]]; then
		ENV_AWS_METADATA_SERVICE_TIMEOUT="${BASH_REMATCH[1]}"
		active_env="true"
	else
		unset ENV_AWS_METADATA_SERVICE_TIMEOUT
	fi

	ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS="$(env | grep '^AWS_METADATA_SERVICE_NUM_ATTEMPTS[[:space:]]*=.*')"
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
	# 5a. INVALID in-env session profile (AWS_DEFAULT_PROFILE points to a non-existent persisted profile)
	# 5b. INVALID in-env baseprofile (AWS_DEFAULT_PROFILE points to a non-existent persisted profile)
	# 5c. INVALID in-env selector only (AWS_DEFAULT_PROFILE points to a non-existent persisted profile)
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
			#  (when AWS_DEFAULT_PROFILE is defined, a persisted session profile of
			#  the same name *must* exist)
			idxLookup env_profile_idx merged_ident[@] "$ENV_AWS_DEFAULT_PROFILE"

			if [[ "$env_profile_idx" != "" ]] &&
				[[ "$env_secrets_present" == "false" ]]; then  # a named profile select only

				if [[ "${merged_type[$env_profile_idx]}" =~ ^(baseprofile|root)$ ]]; then  # can also be a root profile
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
				[[ "$env_secrets_present" == "true" ]]; then  # detected: a named profile select w/secrets (a persisted AWS_DEFAULT_PROFILE + secrets)

				if [[ "$ENV_AWS_ACCESS_KEY_ID" == "${merged_aws_access_key_id[$env_profile_idx]}" ]]; then  # secrets are mirrored

					if [[ "${merged_type[$env_profile_idx]}" =~ ^(baseprofile|root)$ ]]; then
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

					env_aws_type="select-diff-session"

					# mark expired named in-env session invalid
					if [[ "$this_session_expired" == "true" ]]; then  # 3a: the named, diff in-env session has expired (cannot use differing persisted profile data)
						env_aws_status="invalid"

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
							fi

						else  # 3e: quick mode is active; assume valid since the session
							  #  hasn't expired; the session type is not known
							env_aws_status="valid"
						fi
					fi

					# NAMED IN-ENV SESSIONS, TYPE DETERMINED; ADD A REFERENCE MARKER IF IN-ENV SESSION IS NEWER

					if [[ "$env_aws_status" == "valid" ]] &&
						[[ "$quick_mode" == "false" ]]; then

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
					[[ "$ENV_AWS_SESSION_TOKEN" == "" ]]; then  #  could be rotated or second credentials stored in-env only

					# get Arn for the named in-env baseprofile
					getProfileArn _ret

					if [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]] ||
						[[ "${_ret}" =~ [[:digit:]]+:(root)$ ]]; then

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

				if [[ "$active_env_session" == "true" ]]; then  # 5a: a complete in-env session profile with an invalid AWS_DEFAULT_PROFILE
					env_aws_type="named-session-orphan"
				elif [[ "$env_secrets_present" == "true" ]]; then  # 5b: a complete in-env baseprofile with an invalid AWS_DEFAULT_PROFILE
					env_aws_type="named-baseprofile-orphan"
				else  # 5c: AWS_DEFAULT_PROFILE selector only, pointing to a non-existent persisted profile
					env_aws_type="named-select-orphan"
				fi
			fi

		# BEGIN IDENT/UNIDENT (BUT UNNAMED, i.e. NO AWS_DEFAULT_PROFILE) IN-ENV PROFILES

		elif [[ "$env_selector_present" == "false" ]] &&
			[[ "$env_secrets_present" == "true" ]] &&
			[[ "$active_env_session" == "false" ]]; then

			# THIS IS AN UNNAMED BASEPROFILE

			# is the referential ident present?
			if [[ "$ENV_AWS_PROFILE_IDENT" != "" ]]; then
				env_aws_type="ident-baseprofile"
			else
				env_aws_type="unident-baseprofile"
			fi

			if [[ "$quick_mode" == "false" ]]; then

				# get Arn for the ident/unident in-env baseprofile
				getProfileArn _ret

				if [[ "${_ret}" =~ ^arn:aws:iam::[[:digit:]]+:user/([^/]+) ]] ||  # valid 6a: an ident/unident, valid baseprofile
					[[ "${_ret}" =~ [[:digit:]]+:(root)$ ]]; then

					this_iam_name="${BASH_REMATCH[1]}"
					env_aws_status="valid"

				else  # 6b: an invalid ident/unident baseprofile
					env_aws_status="invalid"
				fi

			else  # 6c: a valid ident/unident baseprofile (quick mode is active; status unconfirmed)
				env_aws_status="unconfirmed"
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

				if [[ "$quick_mode" == "false" ]]; then

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

				else  # 6g: quick mode is active; assume valid since the session
					  #  hasn't expired. the session type is not known
					env_aws_status="valid"

				fi
			fi
		fi

	else  # 7: no in-env AWS_ variables

		env_aws_status="none"
	fi

	# detect and print an informative notice of
	# the effective AWS envvars
	if [[ "${AWS_PROFILE}" != "" ]] ||
		[[ "${AWS_DEFAULT_PROFILE}" != "" ]] ||
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

			printf "${BIWhite}${On_Black}THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE PRESENT:${Color_Off}\\n"
			printf "\\n"
			[[ "$ENV_AWS_PROFILE" != "" ]] && printf "   AWS_PROFILE: ${ENV_AWS_PROFILE}\\n"
			[[ "$ENV_AWS_DEFAULT_PROFILE" != "" ]] && printf "   AWS_DEFAULT_PROFILE: ${ENV_AWS_DEFAULT_PROFILE}\\n"
			[[ "$ENV_AWS_PROFILE_IDENT" != "" ]] && printf "   AWS_PROFILE_IDENT: ${ENV_AWS_PROFILE_IDENT}\\n"
			[[ "$ENV_AWS_SESSION_IDENT" != "" ]] && printf "   AWS_SESSION_IDENT: ${ENV_AWS_SESSION_IDENT}\\n"
			[[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] && printf "   AWS_ACCESS_KEY_ID: $ENV_AWS_ACCESS_KEY_ID\\n"
			[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]] && printf "   AWS_SECRET_ACCESS_KEY: $ENV_AWS_SECRET_ACCESS_KEY_PR\\n"
			[[ "$ENV_AWS_SESSION_TOKEN" != "" ]] && printf "   AWS_SESSION_TOKEN: $ENV_AWS_SESSION_TOKEN_PR\\n"
			if [[ "$ENV_AWS_SESSION_EXPIRY" != "" ]]; then
				getRemaining env_seconds_remaining "${ENV_AWS_SESSION_EXPIRY}"
				getPrintableTimeRemaining env_session_remaining_pr "${env_seconds_remaining}"
				printf "   AWS_SESSION_EXPIRY: $ENV_AWS_SESSION_EXPIRY (${env_session_remaining_pr})\\n"
			fi
			[[ "$ENV_AWS_SESSION_TYPE" != "" ]] && printf "   AWS_SESSION_TYPE: $ENV_AWS_SESSION_TYPE\\n"
			[[ "$ENV_AWS_DEFAULT_REGION" != "" ]] && printf "   AWS_DEFAULT_REGION: $ENV_AWS_DEFAULT_REGION\\n"
			[[ "$ENV_AWS_DEFAULT_OUTPUT" != "" ]] && printf "   AWS_DEFAULT_OUTPUT: $ENV_AWS_DEFAULT_OUTPUT\\n"
			[[ "$ENV_AWS_CONFIG_FILE" != "" ]] && printf "   AWS_CONFIG_FILE: $ENV_AWS_CONFIG_FILE\\n"
			[[ "$ENV_AWS_SHARED_CREDENTIALS_FILE" != "" ]] && printf "   AWS_SHARED_CREDENTIALS_FILE: $ENV_AWS_SHARED_CREDENTIALS_FILE\\n"
			[[ "$ENV_AWS_CA_BUNDLE" != "" ]] && printf "   AWS_CA_BUNDLE: $ENV_AWS_CA_BUNDLE\\n"
			[[ "$ENV_AWS_METADATA_SERVICE_TIMEOUT" != "" ]] && printf "   AWS_METADATA_SERVICE_TIMEOUT: $ENV_AWS_METADATA_SERVICE_TIMEOUT\\n"
			[[ "$ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS" != "" ]] && printf "   AWS_METADATA_SERVICE_NUM_ATTEMPTS: $ENV_AWS_METADATA_SERVICE_NUM_ATTEMPTS\\n"
			printf "\\n"

#todo: effective profile here!

	else

		printf "No AWS environment variables present at this time.\\n\\n"

		if [[ "$valid_default_exists" == "true" ]]; then
			printf "${Green}${On_Black}CURRENTLY EFFECTIVE PROFILE: 'default'${Color_Off}\\n\\n"
		else
			printf "${Red}${On_Black}\
The default profile not defined; no AWS profile in effect.\\n\
Select an existing profile, start a new session, or use\\n\
the '--profile {profile name}' aws command argument.${Color_Off}\\n\\n"
		fi
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

	# OUTPUT A NOTIFICATION OF AN INVALID PROFILE
	#
	# AWS_DEFAULT_PROFILE must be empty or refer to *any* profile in ~/.aws/{credentials|config}
	# (Even if all the values are overridden by AWS_* envvars they won't work if the
	# AWS_DEFAULT_PROFILE is set to point to a non-existent persistent profile!)
	if [[ $env_aws_status == "invalid" ]]; then
		# In-env AWS credentials (session or baseprofile) are not valid;
		# commands without an explicitly selected profile with the prefix
		# 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ;' present will fail

		if [[ "$env_aws_type" =~ baseprofile$ ]]; then

			printf "${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE CURRENTLY SELECTED/CONFIGURED\\n\
      IN THE ENVIRONMENT IS INVALID.\\n${Color_Off}\\n"

		elif [[ "$env_aws_type" =~ session$ ]]; then

			printf "${BIRed}${On_Black}\
NOTE: THE AWS SESSION CURRENTLY SELECTED/CONFIGURED\\n\
      IN THE ENVIRONMENT IS "

			if [[ "${this_session_expired}" == "true" ]]; then
				printf "EXPIRED (SEE ABOVE).\\n${Color_Off}\\n"
			else
				printf "INVALID (SEE ABOVE).\\n${Color_Off}\\n"
			fi

		elif [[ "$env_aws_type" == "named-baseprofile-orphan" ]]; then

			printf "${BIRed}${On_Black}\
NOTE: THE AWS BASEPROFILE SELECTED IN THE ENVIRONMENT\\n\
      (SEE ABOVE) DOES NOT EXIST.\\n${Color_Off}\\n"

		elif [[ "$env_aws_type" == "named-session-orphan" ]]; then

			printf "${BIRed}${On_Black}\
NOTE: THE AWS SESSION CURRENTLY SELECTED IN THE ENVIRONMENT\\n\
      (SEE ABOVE) DOES NOT EXIST.\\n${Color_Off}\\n"

		elif [[ "$env_aws_type" == "named-select-orphan" ]]; then

			printf "${BIRed}${On_Black}\
NOTE: THE AWS PROFILE SELECTED IN THE ENVIRONMENT (SEE ABOVE)\\n\
      DOES NOT EXIST.\\n${Color_Off}\\n"

		fi
	fi

	status_printed="false"
	print_purge_select_notice="false"

	[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}env_aws_type: $env_aws_type, env_aws_status: $env_aws_status\\n${Color_Off}\\n"

	if [[ "$env_aws_type" =~ ^select-only- ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		printf "${Green}${On_Black}\
The selected persisted ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' is valid.${Color_Off}\\n\
No credentials are present in the environment.\\n"

	elif [[ "$env_aws_type" =~ ^select-mirrored- ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		printf "${Green}${On_Black}\
The mirrored persisted ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' is valid.${Color_Off}\\n\
Valid mirrored credentials are present in the environment.\\n"

	elif [[ "$env_aws_type" =~ ^select-diff-.*session ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		printf "${Green}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' with\\n\
a persisted reference (maybe to an older session?) is valid.${Color_Off}\\n\
Valid unique credentials are present in the environment.\\n"

	elif [[ "$env_aws_type" =~ ^select-diff-.*-baseprofile ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		printf "${BIYellow}${On_Black}\
NOTE: The valid in-env baseprofile '$ENV_AWS_DEFAULT_PROFILE' has different credentials\\n\
      than its persisted counterpart! Are you using a second API key, or have you\\n\
      rotated the key? Be sure to save it before you replace the environment with\\n\
      the output of this script!${Color_Off} Valid unique credentials are present\\n\
      in the environment.\\n"

	elif [[ "$env_aws_type" =~ ^(un)*ident-(baseprofile|session|rolesession|mfasession)$ ]] &&
		[[ "$env_aws_status" == "valid" ]]; then

		status_printed="true"

		if [[ "$env_aws_type" =~ ^ident-(baseprofile|session|rolesession|mfasession)$ ]]; then

			printf "${Green}${On_Black}\
The in-env ${profile_prefix}profile '${ENV_AWS_PROFILE_IDENT}${ENV_AWS_SESSION_IDENT}'\\n\
with a detached reference to a persisted profile is valid.${Color_Off}\\n\
Valid credentials are present in the environment.\\n"

		else

			printf "${Green}${On_Black}\
The unidentified in-env ${profile_prefix}profile is valid.${Color_Off}\\n\
Valid credentials are present in the environment.\\n"

		fi

	elif [[ "$env_aws_type" =~ ^select-only- ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		printf "${Red}${On_Black}\
The selected persisted ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' is invalid${expired_word}.${Color_Off}\\n\
No credentials are present in the environment. You must unset AWS_DEFAULT_PROFILE\\n"

		if [[ "$valid_default_exists" == "true" ]]; then
			printf "\
to use the default profile from your config, or redefine AWS_DEFAULT_PROFILE\\n\
(or use the '--profile' switch) to use another profile.\\n"
		else
			printf "\
and redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another\\n\
profile as you have no persisted default profile in your configuration.\\n"
		fi

		printf "\\nNOTE: You can select a new profile with this script.\\n"

	elif [[ "$env_aws_type" =~ ^select-mirrored- ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		printf "${Red}${On_Black}\
The mirrored persisted ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must purge the AWS_* envvars\\n"

		if [[ "$valid_default_exists" == "true" ]]; then
			printf "\
to use the default profile, or purge the AWS_* envvars and then redefine\\n\
AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another profile.\\n"
		else
			printf "\
and then redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch)\\n\
to use another profile as you have no persisted default profile in your\\n\
configuration.\\n"
		fi

		print_purge_select_notice="true"

	elif [[ "$env_aws_type" =~ ^select-diff-.*session ||
		    "$env_aws_type" =~ ^select-diff-baseprofile ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		printf "${Red}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_PROFILE' with a persisted reference\\n\
is invalid${expired_word}.${Color_Off} Invalid unique credentials are present in the\\n\
environment. You must purge the AWS_* envvars"

		if [[ "$valid_default_exists" == "true" ]]; then
			printf "\\n\
to use the default profile, or purge the AWS_* envvars and then redefine\\n\
AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another profile.\\n"
		else
			printf "\\n\
and then redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch)\\n\
to use another profile as you have no persisted default profile in your\\n\
configuration.\\n"
		fi

		print_purge_select_notice="true"

	elif [[ "$env_aws_type" =~ -orphan$ ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		printf "${Red}${On_Black}\
The in-env ${profile_prefix}profile '$ENV_AWS_DEFAULT_PROFILE' refers to a persisted profile\\n\
of the same name (set with envvar 'AWS_DEFAULT_PROFILE'), however, no persisted profile with\\n\
that name can be found.${Color_Off} Invalid unique credentials are present in the environment.\\n\
You must purge the AWS_* envvars "

		if [[ "$valid_default_exists" == "true" ]]; then
			printf "\
to use the default profile, or purge the AWS_* envvars and then\\n\
redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another profile.\\n"
		else
			printf "\
and then redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch)\\n\
to use another profile as you have no persisted default profile in your configuration.\\n"
		fi

		print_purge_select_notice="true"

	elif [[ "$env_aws_type" =~ ^(un)*ident-(baseprofile|session)$ ]] &&
		[[ "$env_aws_status" == "invalid" ]]; then

		status_printed="true"

		if [[ "$env_aws_type" =~ ^ident-(baseprofile|session)$ ]]; then

			printf "${Red}${On_Black}\
The in-env ${profile_prefix}profile '${ENV_AWS_PROFILE_IDENT}${ENV_AWS_SESSION_IDENT}'\\n\
with a detached reference to a persisted profile is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must purge the AWS_* envvars\\n"

			if [[ "$valid_default_exists" == "true" ]]; then
				printf "\\n\
to use the default profile, or purge the AWS_* envvars and then\\n\
redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another profile.\\n"
			else
				printf "\\n\
and then redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch)\\n\
to use another profile as you have no persisted default profile in your configuration.\\n"
			fi

			print_purge_select_notice="true"

		else  # unindentified..

			printf "${Red}${On_Black}\
The unidentified in-env ${profile_prefix}profile is invalid${expired_word}.${Color_Off}\\n\
Invalid credentials are present in the environment. You must purge the AWS_* envvars\\n"

			if [[ "$valid_default_exists" == "true" ]]; then
				printf "\\n\
to use the default profile, or purge the AWS_* envvars and then\\n\
redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch) to use another profile.\\n"
			else
				printf "\\n\
and then redefine AWS_DEFAULT_PROFILE (or use the '--profile' switch)\\n\
to use another profile as you have no persisted default profile in your configuration.\\n"
			fi

			print_purge_select_notice="true"
		fi
	fi

	if [[ "$print_purge_select_notice" == "true" ]]; then

		printf "\\n\
NOTE: You can purge the AWS_* envvars with:\\n\
      source ./source-this-to-clear-AWS-envvars.sh\\n"
		printf "\\n\
NOTE: You can purge the envvars and select a new profile\\n\
      by continuing this script.\\n"

	fi

	if [[ "$status_printed" == "false" ]] &&
		[[ "$env_selector_present" == "true" ||
		   "$env_secrets_present" == "true" ]]; then

		if [[ "$env_aws_type" =~ baseprofile$ ]] &&
			[[ "$env_aws_status" == "unconfirmed" ]]; then

			printf "${Yellow}${On_Black}\
The status of the baseprofile selected/present in the environment\\n\
(see the details above) could not be confirmed because of the quick mode.\\n"

		elif [[ "$env_aws_type" =~ session$ ]] &&
			[[ "$env_aws_status" == "unconfirmed" ]]; then

			printf "${Yellow}${On_Black}\
The status of the session profile selected/present in the environment\\n\
(see the details above) could not be confirmed because of the quick mode\\n\
and a missing expiration timestamp.\\n"

		else

			printf "${Yellow}${On_Black}\
The status of the profile selected/present in the environment\\n\
(see the details above) could not be determined.\\n"
		fi

	fi
}

# workaround function for lack of macOS bash's (3.2) assoc arrays
idxLookup() {
	# $1 is idxLookup_result (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function idxLookup] looking up '${3}'${Color_Off}\\n"

	local idxLookup_result
	declare -a arr=("${!2}")
	local key="$3"
 	local idxLookup_result=""
 	local maxIndex

 	maxIndex="${#arr[@]}"
 	((maxIndex--))

	for ((i=0; i<=maxIndex; i++))
	do
		if [[ "${arr[$i]}" == "$key" ]]; then
			idxLookup_result="$i"
			break
		fi
	done

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${idxLookup_result}${Color_Off}\\n"
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

			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** checking for $source_file dupes for '${profile_ident_hold}'..${Color_Off}\\n"

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
					this_prop="$(printf "$this_prop" | xargs echo -n)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  adding to the dupes array for $profile_ident_hold: '${this_prop}'${Color_Off}\\n"
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

	local dupes_to_check=("${!1}")
	local ident="$2"
	local checktype="$3"
	local itr_outer
	local itr_inner
	local hits="0"
	local last_hit

	if [[ "$DEBUG" == "true" ]]; then
		printf "\\n${BIYellow}${On_Black}[function exitOnArrDupes] checking dupes for ${3} @${2}${Color_Off}\\nArray has:\\n\\n"
		printf '%s\n' "${dupes_to_check[@]}"
	fi

	for ((itr_outer=0; itr_outer<${#dupes_to_check[@]}; ++itr_outer))
	do
		for ((itr_inner=0; itr_inner<${#dupes_to_check[@]}; ++itr_inner))
		do
			if [[ "${dupes_to_check[${itr_outer}]}" == "${dupes_to_check[${itr_inner}]}" ]]; then
				(( hits++ ))
				last_hit="${dupes_to_check[${itr_inner}]}"
			fi
		done
		if [[ $hits -gt 1 ]]; then
			if [[ "$checktype" == "props" ]]; then
				printf "\\n${BIRed}${On_Black}A duplicate property '${last_hit}' found in the profile '${ident}'. Cannot continue.${Color_Off}\\n\\n\\n"
			elif [[ "$checktype" == "conffile" ]]; then
				printf "\\n${BIRed}${On_Black}A duplicate profile label '[${last_hit}]' found in the config file '${ident}'. Cannot continue.${Color_Off}\\n\\n\\n"
			elif [[ "$checktype" == "credfile" ]]; then
				printf "\\n${BIRed}${On_Black}A duplicate profile label '[${last_hit}]' found in the credentials file '${ident}'. Cannot continue.${Color_Off}\\n\\n\\n"
			fi
			exit 1
		else
			hits="0"
		fi
	done
	unset dupes_to_check
}

# adds a new property+value to the defined config file
# (why all these shenanigans you may ask.. a multi-line
# replace only by using the "LCD": the bash 3.2 builtins :-)
addConfigProp() {
	# $1 is the target file
	# $2 is the target file type
	# $3 is the target profile (the anchor)
	# $4 is the property
	# $5 is the value

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function addConfigProp] target_file: $1, target_filetype: $2, target_profile: $3, property: $4, value: $5${Color_Off}\\n"

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

		printf "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n\\n"
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
	replace_profile_transposed="$(sed -e ':loop' -e 's/\(\[[^[ ]*\) \([^]]*\]\)/\1@@@\2/' -e 't loop' <(printf "$replace_profile"))"

	target_anchor="$(grep -E "\[$target_profile\]" "$target_file" 2>&1)"

	# check for the anchor string in the target file
	# (no anchor, i.e. ident in the file -> add stub)
	if [[ "$target_anchor" == "" ]]; then

		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   no profile entry in file, adding..${Color_Off}\\n"

		# no entry was found, add a stub
		# (use the possibly transposed string)
		printf "\\n" >> "$target_file"
		printf "[${replace_profile_transposed}]\\n" >> "$target_file"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   target_profile: $target_profile${Color_Off}\\n"
	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   replace_profile_transposed: $replace_profile_transposed${Color_Off}\\n"

	# if the label has been transposed, use it in both in
	# the stub entry (above^^), and as the search point (below˅˅)
	replace_me="\\[${replace_profile_transposed}\\]"
	DATA="[${replace_profile_transposed}]\\n${new_property} = ${new_value}"

	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   replace_me: $replace_me${Color_Off}\\n"
	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   DATA: $DATA${Color_Off}\\n"
	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   transposing all labels..${Color_Off}\\n"

	[[ "$profile_prefix" == "true" ]]
		sed -e 's/\[profile /\[profile_/g' -i.sedtmp "${target_file}"

	# transpose all spaces in all labels to restorable strings;
	# a kludgish construct in order to only use the builtins
	# while remaining bash 3.2 compatible (because macOS)
	sed -e ':loop' -e 's/\(\[[^[ ]*\) \([^]]*\]\)/\1@@@\2/' -e 't loop' -i.sedtmp "${target_file}"

	# with itself + the new property on the next line
	printf "$(awk -v var="${DATA//$'\n'/\\n}" '{sub(/'${replace_me}'/,var)}1' "${target_file}")" > "${target_file}"

	[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   restoring normalcy in $target_file${Color_Off}\\n"

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

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function updateUniqueConfigPropValue] target_file: $1, old_property_value: $2, new_property_value: $3${Color_Off}\\n"

	local target_file="$1"
	local old_value="$2"
	local new_value="$3"

	if [[ $target_file != "" ]] &&
		[ ! -f "$target_file" ]; then

		printf "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n\\n"
		exit 1
	fi

	if [[ "$OS" == "macOS" ]]; then

		# BSD sed path hardcoded to avoid gnu-sed/gsed that is usually not present on macOS
		/usr/bin/sed -i '' -e "s/${old_value}/${new_value}/g" "$target_file"
	else
		# standard Gnu sed location on Linux
		/bin/sed -i -e "s/${old_value}/${new_value}/g" "$target_file"
	fi
}

# deletes an existing property value in the defined config file
deleteConfigProp() {
	# $1 is target file
	# $2 is the target profile
	# $3 is the prop name to be deleted

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function deleteConfigProp] target_file: $1, target_filetype: $2,target_profile: $3, prop_to_delete: $4${Color_Off}\\n"

	local target_file="$1"
	local target_filetype="$2"
	local target_profile="$3"
	local prop_to_delete="$4"
	local TMPFILE
	local delete_active="false"
	local profile_ident

	if [[ $target_file != "" ]] &&
		[ ! -f "$target_file" ]; then

		printf "\\n${BIRed}${On_Black}The designated configuration file '$target_file' does not exist. Cannot continue.${Color_Off}\\n\\n\\n"
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

			printf "$line\\n" >> "$TMPFILE"
		else
			[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}Deleting property '$prop_to_delete' in profile '$profile_ident'.${Color_Off}\\n"
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

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function writeSessionExpTime] this_ident: $1, new_session_expiration_timestamp: $2${Color_Off}\\n"

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
		addConfigProp "$CREDFILE" "credfile" "${this_ident}" "aws_session_expiry" "$new_session_expiration_timestamp"
	fi
}

# saves the role xaccn status for quick mode
# intellingence in ~/.aws/config
writeRoleXaccn() {
	# $1 is the merged_idx
	# $2 is the state ('true' sets, 'false' clears)

	local this_merged_idx="$1"
	local xaccn_state="$2"
	local this_ident="${merged_ident[$this_merged_idx]}"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function writeRoleXaccn] this_ident: $this_ident (idx $this_merged_idx), state: $2, existing persisted value: ${confs_role_xaccn[$itr]}${Color_Off}\\n"

	# is xaccn currently set?
	# note: not using merged_role_xaccn[$idx] because
	# it may have been [re]set by the augment processes

	if [[ "$xaccn_state" == "true" ]]; then

		# IN CONFFILE
		if [[ "${confs_role_xaccn[$this_merged_idx]}" != "true" ]] &&
			[[ "${confs_role_xaccn[$this_merged_idx]}" != "" ]]; then

			# this should never occur, but is provided in case user
			deleteConfigProp "$CONFFILE" "conffile" "${this_ident}" "role_xaccn"
			addConfigProp "$CONFFILE" "conffile" "${this_ident}" "role_xaccn" "true"

		elif [[ "${confs_role_xaccn[$this_merged_idx]}" == "" ]] ; then

			# no xaccn flag, so add one
			addConfigProp "$CONFFILE" "conffile" "${this_ident}" "role_xaccn" "true"
		fi

	elif [[ "$xaccn_state" == "false" ]]; then

		if [[ "${confs_role_xaccn[$this_merged_idx]}" != "" ]]; then

			deleteConfigProp "$CONFFILE" "conffile" "${this_ident}" "role_xaccn"
		fi
	fi
}

# mark/unmark a profile invalid (both in ~/.aws/config and ~/.aws/credentials
# or in the custom files if custom defs are in effect) for intelligence
# in the quick mode
toggleInvalidProfile() {
	# $1 is the requested action (set/unset)
	# $2 is the profile (ident)

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function toggleInvalidProfile] this_ident: $1, operation: $2${Color_Off}\\n"

	local action="$1"
	local this_ident="$2"

	local confs_idx
	local creds_idx
	local merged_idx
	local this_isodate="$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")"

	# get idx for the current ident in merged
	idxLookup merged_idx merged_ident[@] "$this_ident"

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

		# role profiles don't exist in the credfile; only set
		# baseprofiles and session profiles invalid there
		if [[ "${merged_type[$merged_idx]}" != "role" ]]; then
			# IN CREDFILE
			if [[ "${creds_invalid_as_of[$creds_idx]}" != "" ]]; then
				# profile previously marked invalid, update it with the current timestamp
				updateUniqueConfigPropValue "$CREDFILE" "${creds_invalid_as_of[$creds_idx]}" "$this_isodate"
			elif [[ "${creds_invalid_as_of[$creds_idx]}" == "" ]]; then
				# no invalid flag found; add one
				addConfigProp "$CREDFILE" "credfile" "${this_ident}" "invalid_as_of" "$this_isodate"
			fi
		fi

		# set the marker for this run
		merged_invalid_as_of[$merged_idx]="$this_isodate"

	elif [[ "$action" == "unset" ]]; then

		# unset invalid flag for the ident where present

		if [[ "$confs_idx" != "" && "${confs_invalid_as_of[$confs_idx]}" != "" ]]; then
			deleteConfigProp "$CONFFILE" "conffile" "${this_ident}" "invalid_as_of"
		fi

		if [[ "$creds_idx" != "" && "${creds_invalid_as_of[$creds_idx]}" != "" ]]; then
			deleteConfigProp "$CREDFILE" "credfile" "${this_ident}" "invalid_as_of"
		fi

		# clear the marker for this run
		merged_invalid_as_of[$merged_idx]=""

	fi
}

writeSessmax() {
	# $1 is the target ident (role)
	# $2 is the sessmax value

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function writeSessmax] target_ident: $1, sessmax_value: $2${Color_Off}\\n"

	local this_target_ident="$1"
	local this_sessmax="$2"
	local local_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	if [[ "${merged_sessmax[$local_idx]}" == "" ]]; then

		# add the sessmax property
		addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "sessmax" "$this_sessmax"

	elif [[ "${this_sessmax}" == "erase" ]]; then

		# delete the existing sessmax property
		deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "sessmax"
	else
		# update the existing sessmax value (delete+add)
		# NOTE: we can't use updateUniqueConfigPropValue here because
		#       the same [old] sessmax value could be used in different
		#       profiles
		deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "sessmax"
		addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "sessmax" "$this_sessmax"
	fi
}

writeRoleSourceProfile() {
	# $1 is the target profile ident to add source_profile to
	# $2 is the source profile ident

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function writeRoleSourceProfile] target_ident: $1, source_profile_ident: $2${Color_Off}\\n"

	local target_ident="$1"
	local source_profile_ident="$2"
	local target_idx
	local source_idx
	local existing_source_profile_ident

	# check whether the target profile
	# has a source profile entry
	existing_source_profile_ident="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "$target_ident" configure get source_profile 2>&1)"

	# double-check that this is a role, and that this has no
	# source profile as of yet; then add on a new line after
	# the existing header "[${target_ident}]"
	idxLookup target_idx merged_ident[@] "$target_ident"
	idxLookup source_idx merged_ident[@] "$source_profile_ident"

	if [[ "$target_idx" != "" && "$source_idx" != "" ]]; then

		if [[ "${merged_type[$source_idx]}" == "baseprofile" ]]; then

			if [[ "${merged_role_source_profile_ident[$target_idx]}" == "" ]]; then

				addConfigProp "$CONFFILE" "conffile" "$target_ident" "source_profile" "$source_profile_ident"
			else
				updateUniqueConfigPropValue "$CONFFILE" "$existing_source_profile_ident" "$source_profile_ident"
			fi

		elif [[ "${merged_type[$source_idx]}" == "role" ]] &&
			[[ "${merged_role_source_baseprofile_ident[$source_idx]}" != "" ]]; then  # a source_profile role must have access to a valid baseprofile

			if [[ "${merged_role_source_profile_ident[$target_idx]}" == "" ]]; then

				addConfigProp "$CONFFILE" "conffile" "$target_ident" "source_profile" "$source_profile_ident"
			else
				updateUniqueConfigPropValue "$CONFFILE" "$existing_source_profile_ident" "$source_profile_ident"
			fi

		else
			printf "\\n${BIRed}${On_Black}Cannot set source profile for ident $target_ident. Cannot continue.${Color_Off}\\n\\n\\n"
			exit 1
		fi
	else
		printf "\\n${BIRed}${On_Black}Cannot set source profile for ident $target_ident. Cannot continue.${Color_Off}\\n\\n\\n"
		exit 1
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

# persist the baseprofile's vMFAd Arn in the conffile (usually ~/.aws/config)
# if a vMFAd has been configured/attached; update if the value exists, or
# delete if "erase" flag has been set
writeProfileMfaArn() {
	# $1 is the target profile ident to add mfa_arn to
	# $2 is the mfa_arn

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function writeProfileMfaArn] target_profile: $1, mfa_arn: $2${Color_Off}\\n"

	local this_target_ident="$1"
	local this_mfa_arn="$2"
	local local_idx
	local delete_idx
	local add_idx

	idxLookup local_idx merged_ident[@] "$this_target_ident"

	# available for baseprofiles, role profiles, and root profiles
	if [[ ! "${merged_type[$local_idx]}" =~ session$ ]]; then

		if [[ "${merged_mfa_arn[$local_idx]}" == "" ]]; then
			# add the mfa_arn property
			addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_arn" "$this_mfa_arn"

			if [[ "${merged_type[$local_idx]}" != "role" ]]; then  # only allow for baseprofiles and root profiles

				# also add the assigned vMFA to the associated roles which require MFA
				for ((add_idx=0; add_idx<${#merged_ident[@]}; ++add_idx))  # iterate all profiles
				do
					if [[ "${merged_type[$add_idx]}" == "role" ]] &&
						[[ "${merged_role_source_baseprofile_ident[$add_idx]}" == "$this_target_ident" ]] &&
						[[ "${merged_role_mfa_required[$add_idx]}" == "true" ]]; then

						writeProfileMfaArn "${merged_ident[$add_idx]}" "$this_mfa_arn"
					fi
				done
			fi

		elif [[ "${this_mfa_arn}" == "erase" ]]; then  # "mfa_arn" is set to "erase" when the MFA requirement for a role has gone away
			# delete the existing mfa_arn property
			deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_arn"

			if [[ "${merged_type[$local_idx]}" != "role" ]]; then  # only allow for baseprofiles and root profiles

				# also remove the deleted vMFA off of the associated roles which have it
				for ((delete_idx=0; delete_idx<${#merged_ident[@]}; ++delete_idx))  # iterate all profiles
				do
					if [[ "${merged_type[$delete_idx]}" == "role" ]] &&
						[[ "${merged_role_source_baseprofile_ident[$delete_idx]}" == "$this_target_ident" ]] &&
						[[ "${merged_mfa_arn[$delete_idx]}" != "" ]]; then

						writeProfileMfaArn "${merged_ident[$delete_idx]}" "erase"
					fi
				done
			fi
		else
			# update the existing mfa_arn value (delete+add)
			# NOTE: we can't use updateUniqueConfigPropValue here because
			#       we can't be sure the profile wouldn't be duplicated under
			#       different labesls and/or, perhaps, vMFAd might be attached
			#       to multiple user accounts
			deleteConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_arn"
			addConfigProp "$CONFFILE" "conffile" "$this_target_ident" "mfa_arn" "$this_mfa_arn"
		fi
	fi
}

# return the session expiry time for
# the given role/mfa session profile
getSessionExpiry() {
	# $1 is getSessionExpiry_result
	# $2 is the profile ident

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getSessionExpiry] profile_ident: '${2}'${Color_Off}\\n"

	local getSessionExpiry_result
	local this_ident="$2"

	local idx
	local getSessionExpiry_result

	# find the profile's init/expiry time entry if one exists
	idxLookup idx merged_ident[@] "$this_ident"

	getSessionExpiry_result="${merged_aws_session_expiry[$idx]}"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getSessionExpiry_result}${Color_Off}\\n"
	eval "$1=\"${getSessionExpiry_result}\""
}

getMaxSessionDuration() {
	# $1 is getMaxSessionDuration_result
	# $2 is the profile ident
	# $3 is "baseprofile" or "role"
	# $4 (optional; used for chained sessions) restricted length:
	#    if set to true "true" returns "3600" or a shorter value
	#    if so defined by sessmax

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getMaxSessionDuration] profile_ident: $2, profile_type (optional): $3${Color_Off}\\n"

	local getMaxSessionDuration_result
	local this_profile_ident="$2"
	local this_sessiontype="$3"
	local restricted_length="false"
	local idx
	local getMaxSessionDuration_result

	# look up a possible custom duration for the parent profile/role
	idxLookup idx merged_ident[@] "$this_profile_ident"

	# limit session length to 3600 seconds or sessmax
	# (if it is defined and is less than 3600 seconds)
	if [[ "$4" == "true" ]] ||
		[[ "${merged_type[$idx]}" == "root" ]]; then

		restricted_length="true"
	fi

	# sessmax is dynamically defined in the role and auto-persisted
	# in the config where the user can override to a shorter value
	if [[ $idx != "" && "${merged_sessmax[$idx]}" != "" ]]; then

		getMaxSessionDuration_result="${merged_sessmax[$idx]}"
	else
		# sessmax is not being used; using the defaults

		if [[ "$this_sessiontype" =~ ^(baseprofile|root)$ ]]; then

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

		getMaxSessionDuration_result="3600"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getMaxSessionDuration_result}${Color_Off}\\n"

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
	local this_time="$(/bin/date "+%s")"
	local getRemaining_result="0"
	local this_session_time
	local timestamp_format="invalid"
	local exp_time_format="seconds"  # seconds = seconds remaining, jit = seconds without slack (for JIT checks), datetime = expiration datetime, timestamp = expiration timestamp
	[[ "$3" != "" ]] && exp_time_format="$3"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getRemaining] expiration_timestamp: $2, expiration time format (output): ${exp_time_format}${Color_Off}\\n"

	if [[ "${expiration_timestamp}" =~ ^[[:digit:]]{10}$ ]]; then
		timestamp_format="timestamp"

		if [[ "$OS" == "macOS" ]]; then
			expiration_date="$(/bin/date -jur $expiration_timestamp '+%Y-%m-%d %H:%M (UTC)')"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  macOS epoch->date conversion result: ${expiration_date}${Color_Off}\\n"
		elif [[ "$OS" =~ Linux$ ]]; then
			expiration_date="$(/bin/date -d "@$expiration_timestamp" '+%Y-%m-%d %H:%M (UTC)')"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  Linux epoch->date conversion result: ${expiration_date}${Color_Off}\\n"
		else
			timestamp_format="invalid"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  Could not convert to datetime (unknown OS)${Color_Off}\\n"
		fi

	elif [[ "${expiration_timestamp}" =~ ^[[:digit:]]{4}-[[:digit:]]{2}-[[:digit:]]{2}T[[:digit:]]{2}:[[:digit:]]{2}:[[:digit:]]{2}(Z|\+00:00)$ ]]; then
		timestamp_format="date"
		expiration_date="$expiration_timestamp"

		if [[ "$OS" == "macOS" ]]; then
			expiration_timestamp="$(/bin/date -juf "%Y-%m-%dT%H:%M:%SZ" "$expiration_timestamp" "+%s")"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  macOS date->epoch conversion result: ${expiration_timestamp}${Color_Off}\\n"
		elif [[ "$OS" =~ Linux$ ]]; then
			expiration_timestamp="$(/bin/date -u -d"$expiration_timestamp" "+%s")"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  Linux date->epoch conversion result: ${expiration_timestamp}${Color_Off}\\n"
		else
			timestamp_format="invalid"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  Could not convert to epoch (unknown OS)${Color_Off}\\n"
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

			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  this_session_time: $this_session_time, this_time: $this_time, VALID_SESSION_TIME_SLACK: $VALID_SESSION_TIME_SLACK, getRemaining_result: $getRemaining_result${Color_Off}\\n"
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

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getRemaining_result}${Color_Off}\\n"
	eval "$1=\"${getRemaining_result}\""
}

# return printable output for given 'remaining' timestamp
# (must be pre-incremented with profile duration,
# such as getRemaining() datestamp output)
getPrintableTimeRemaining() {
	# $1 is getPrintableTimeRemaining_result
	# $2 is the time_in_seconds

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getPrintableTimeRemaining] time_in_seconds: $2${Color_Off}\\n"

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

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getPrintableTimeRemaining_result}${Color_Off}\\n"
	eval "$1=\"${getPrintableTimeRemaining_result}\""
}

checkGetRoleErrors() {
	# $1 is checkGetRoleErrors_result
	# $2 is the json data (supposedly)

	local getGetRoleErrors_result="none"
	local json_data="$2"

    json_data=${json_data//[$'\t\r\n']} && json_data=${json_data%%*( )}

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function checkGetRoleErrors] json_data: ${json_data}${Color_Off}\\n"

	if [[ "$json_data" =~ .*NoSuchEntity.* ]]; then

		# the role is not found; invalid (either the
		# source is wrong, or the role doesn't exist)
		getGetRoleErrors_result="ERROR_NoSuchEntity"

	elif [[ "$json_data" =~ .*validation[[:space:]]failed.* ]]; then

		# bad parameters; bad profile definition
		getGetRoleErrors_result="ERROR_BadProfile"

	elif [[ "$json_data" =~ .*AccessDenied.* ]]; then

		# the source profile is not authorized to run
		# get-role on the given role
		getGetRoleErrors_result="ERROR_Unauthorized"

	elif [[ "$json_data" =~ .*The[[:space:]]config[[:space:]]profile.*could[[:space:]]not[[:space:]]be[[:space:]]found ]] ||
		[[ "$json_data" =~ .*Unable[[:space:]]to[[:space:]]locate[[:space:]]credentials.* ]] ||
		[[ "$json_data" =~ .*InvalidClientTokenId.* ]] ||
		[[ "$json_data" =~ .*SignatureDoesNotMatch.* ]]; then

		# unconfigured source profile
		getGetRoleErrors_result="ERROR_BadSource"

	elif [[ "$json_data" =~ .*Could[[:space:]]not[[:space:]]connect[[:space:]]to[[:space:]]the[[:space:]]endpoint[[:space:]]URL ]]; then
		# always bail out if connectivity problems
		# start mid-operation
		printf "\\n${BIRed}${On_Black}${custom_error}AWS API endpoint not reachable (connectivity problems)! Cannot continue.${Color_Off}\\n\\n"
		is_error="true"
		exit 1

	fi

	# Finally, if no other errors occurred, validate JSON
	if [[ "${getGetRoleErrors_result}" == "none" ]]; then
		
		printf "$json_data" | jq empty >/dev/null 2>&1

		if [[ "$?" -ne 0 ]]; then

			# json data is bad
			getGetRoleErrors_result="ERROR_BadJSON"
		fi
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getGetRoleErrors_result}${Color_Off}\\n"
	eval "$1=\"${getGetRoleErrors_result}\""
}

getProfileArn() {
	# $1 is getProfileArn_result
	# $2 is the ident

	local getProfileArn_result
	local this_ident="$2"
	local this_profile_arn

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getProfileArn] this_ident: $2${Color_Off}\\n"

	if [[ "$this_ident" == "" ]] &&						# if ident is not provided and
		[[ "$ENV_AWS_ACCESS_KEY_ID" != "" ]] &&			# env_aws_access_key_id is present
		[[ "$ENV_AWS_SECRET_ACCESS_KEY" != "" ]]; then	# env_aws_secret_access_key is present
														# env_aws_session_token may or may not be present; if it is, it is used automagically

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** no ident provided; testing in-env profile${Color_Off}\\n"

		# in-env secrets present, profile not defined here: using in-env secrets
		this_profile_arn="$(aws sts get-caller-identity \
			--query 'Arn' \
			--output text 2>&1)"

		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}(in-env credentials present) result for: 'aws sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${this_profile_arn}${Color_Off}\\n"

	elif [[ "$this_ident" != "" ]]; then

		# using the defined persisted profile
		this_profile_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "$this_ident" sts get-caller-identity \
			--query 'Arn' \
			--output text 2>&1)"

		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"$this_ident\" sts get-caller-identity --query 'Arn' --output text':\\n${ICyan}${this_profile_arn}${Color_Off}\\n"

	else
		printf "\\n${BIRed}${On_Black}Ident not provided and no in-env profile. Cannot continue (program error).${Color_Off}\\n\\n"
		exit 1

	fi

	if [[ "$this_profile_arn" =~ ^arn:aws: ]] &&
		[[ ! "$this_profile_arn" =~ 'error occurred' ]]; then

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Arn found; valid profile${Color_Off}\\n"
		getProfileArn_result="$this_profile_arn"

	elif [[ "$this_profile_arn" =~ .*Could[[:space:]]not[[:space:]]connect[[:space:]]to[[:space:]]the[[:space:]]endpoint[[:space:]]URL ]]; then

		# bail out if connectivity problems start mid-operation
		printf "\\n${BIRed}${On_Black}AWS API endpoint not reachable (connectivity problems)! Cannot continue.${Color_Off}\\n\\n"
		exit 1

	else
		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** No Arn found; invalid profile${Color_Off}\\n"
		getProfileArn_result=""
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getProfileArn_result}${Color_Off}\\n"
	eval "$1=\"${getProfileArn_result}\""
}

isProfileValid() {
	# $1 is isProfileValid_result
	# $2 is the ident

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function isProfileValid] this_ident: $2${Color_Off}\\n"

	local isProfileValid_result
	local this_ident="$2"
	local this_profile_arn

	getProfileArn _ret "$this_ident"

	if [[ "${_ret}" =~ ^arn:aws: ]]; then
		isProfileValid_result="true"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}The profile '$this_ident' exists and is valid.${Color_Off}\\n"
	else
		isProfileValid_result="false"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}The profile '$this_ident' not present or invalid.${Color_Off}\\n"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${isProfileValid_result}${Color_Off}\\n"
	eval "$1=\"${isProfileValid_result}\""
}

profileCheck() {
	# $1 is profileCheck_result
	# $2 is the ident

	local this_ident="${2}"
	local _ret
	local this_idx
	local get_this_mfa_arn
	local profileCheck_result

	idxLookup this_idx merged_ident[@] "$this_ident"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function profileCheck] this_ident: $2, this_idx: $this_idx${Color_Off}\\n"

	getProfileArn _ret "${this_ident}"

	if [[ "${_ret}" =~ ^arn:aws: ]]; then

		merged_baseprofile_arn[$this_idx]="${_ret}"

		# confirm that the profile isn't flagged invalid
		toggleInvalidProfile "unset" "${merged_ident[$this_idx]}"

		# get the actual username (may be different
		# from the arbitrary profile ident)
		if [[ "${_ret}" =~ ([[:digit:]]+):user.*/([^/]+)$ ]]; then
			merged_account_id[$this_idx]="${BASH_REMATCH[1]}"
			merged_username[$this_idx]="${BASH_REMATCH[2]}"

		elif [[ "${_ret}" =~ ([[:digit:]]+):root$ ]]; then
			merged_account_id[$this_idx]="${BASH_REMATCH[1]}"
			merged_username[$this_idx]="root"
			merged_type[$this_idx]="root"  # overwrite type to root
		fi

		# Check to see if this profile has access currently. Assuming
		# the provided MFA policies are utilized, this query determines
		# positively whether an MFA session is required for access (while
		# 'sts get-caller-identity' above verified that the creds are valid)

		profile_check="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$this_idx]}" iam get-access-key-last-used \
			--access-key-id ${merged_aws_access_key_id[$this_idx]} \
			--query 'AccessKeyLastUsed.LastUsedDate' \
			--output text 2>&1)"

		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$this_idx]}\" iam get-access-key-last-used --access-key-id ${merged_aws_access_key_id[$this_idx]} --query 'AccessKeyLastUsed.LastUsedDate' --output text':\\n${ICyan}${profile_check}${Color_Off}\\n"

		if [[ "$profile_check" =~ ^[[:digit:]]{4} ]]; then  # access available as permissioned

			merged_baseprofile_operational_status[$this_idx]="ok"

		elif [[ "$profile_check" =~ 'AccessDenied' ]]; then  # requires an MFA session (or bad policy)

			merged_baseprofile_operational_status[$this_idx]="reqmfa"

		elif [[ "$profile_check" =~ 'could not be found' ]]; then  # should not happen since 'sts get-caller-id' test passed

			merged_baseprofile_operational_status[$this_idx]="none"

		else  # catch-all; should not happen since 'sts get-caller-id' test passed
			merged_baseprofile_operational_status[$this_idx]="unknown"
		fi

		# get the account alias (if any)
		# for the user/profile
		getAccountAlias _ret "${merged_ident[$this_idx]}"
		if [[ ! "${_ret}" =~ 'could not be found' ]]; then

			merged_account_alias[$this_idx]="${_ret}"
		fi

		if [[ "${merged_type[$this_idx]}" != "root" ]]; then

			# get vMFA device ARN if available (obviously not available
			# if a vMFAd hasn't been configured for the profile)
			get_this_mfa_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$this_idx]}" iam list-mfa-devices \
				--user-name "${merged_username[$this_idx]}" \
				--output text \
				--query 'MFADevices[].SerialNumber' 2>&1)"

			[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$this_idx]}\" iam list-mfa-devices --user-name \"${merged_username[$this_idx]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${get_this_mfa_arn}${Color_Off}\\n"

		else  # this is a root profile

			get_this_mfa_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$this_idx]}" iam list-mfa-devices \
				--output text \
				--query 'MFADevices[].SerialNumber' 2>&1)"

			[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$this_idx]}\" iam list-mfa-devices --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${get_this_mfa_arn}${Color_Off}\\n"
		fi

		if [[ "$get_this_mfa_arn" =~ ^arn:aws: ]]; then
			if [[ "$get_this_mfa_arn" != "${merged_mfa_arn[$this_idx]}" ]]; then
				# persist MFA Arn in the config..
				writeProfileMfaArn "${merged_ident[$this_idx]}" "$get_this_mfa_arn"

				# ..and update in this script state
				merged_mfa_arn[$this_idx]="$get_this_mfa_arn"
			fi

		elif [[ "$get_this_mfa_arn" == "" ]]; then
			# empty result, no error: no vMFAd confgured currently

			if [[ "${merged_mfa_arn[$this_idx]}" != "" ]]; then
				# erase the existing persisted vMFAd Arn from the
				# profile since one remains in the config currently
				writeProfileMfaArn "${merged_ident[$idx]}" "erase"

				merged_mfa_arn[$idx]=""
			fi

		else  # (error conditions such as NoSuchEntity or Access Denied)

			# we do not delete the persisted Arn in case a policy
			# is blocking 'iam list-mfa-devices'; user has the option
			# to add a "mfa_arn" manually to the baseprofile config
			# to facilitate associated role session requests that
			# require MFA, even when 'iam list-mfa-devices' isn't
			# allowed.

			merged_mfa_arn[$this_idx]=""
		fi

		profileCheck_result="true"

	else
		# must be a bad profile
		merged_baseprofile_arn[$this_idx]=""

		# flag the profile as invalid (for quick mode intelligence)
		toggleInvalidProfile "set" "${merged_ident[$this_idx]}"

		profileCheck_result="false"
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${profileCheck_result}${Color_Off}\\n"
	eval "$1=\"${profileCheck_result}\""
}

mfaSessionLengthOverrideCheck() {
	# $1 is the ident

	local this_ident="${1}"
	local this_idx
	local get_mfa_maxlength
	local _ret
	local current_sessmax_pr
	local allowed_sessmax_pr

	idxLookup this_idx merged_ident[@] "$this_ident"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function mfaSessionLengthOverrideCheck] this_ident: ${1}${Color_Off}\\n"

	# use override region or the profile's defined region for the query
	if 	[[ "$MFA_SESSION_LENGTH_LOOKUP_REGION_OVERRIDE" != "" ]]; then
		query_region="--region $MFA_SESSION_LENGTH_LOOKUP_REGION_OVERRIDE"
	else
		query_region="--region ${merged_region[$idx]}"
	fi

	get_mfa_maxlength="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$this_idx]}" $query_region ssm get-parameter \
		--name '/unencrypted/mfa/session_length' \
		--output text \
		--query 'Parameter.Value' 2>&1)"

	[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$this_idx]}\" $query_region ssm get-parameter --name '/unencrypted/mfa/session_length' --query 'Parameter.Value' --output 'text':\\n${ICyan}${get_mfa_maxlength}${Color_Off}\\n"

	if [[ "$get_mfa_maxlength" =~ ^[[:digit:]][[:digit:]][[:digit:]]+$ ]] &&

		# get_mfa_maxlength is always valid since it's the advertised value
		[[ "$get_mfa_maxlength" != "$MFA_SESSION_LENGTH_IN_SECONDS" ]]; then

			MFA_SESSION_LENGTH_IN_SECONDS="$get_mfa_maxlength"

		if [[ "${merged_sessmax[$this_idx]}" -gt "$get_mfa_maxlength" ]]; then

			getPrintableTimeRemaining current_sessmax_pr "${merged_sessmax[$this_idx]}"
			getPrintableTimeRemaining allowed_sessmax_pr "$get_mfa_maxlength"

			printf "${BIYellow}${On_Black}\
NOTE: The maximum allowed session length for this profile has been\\n\
      reduced from ${current_sessmax_pr} to ${allowed_sessmax_pr}.${Color_Off}\\n\\n"

			merged_sessmax[$this_idx]="$get_mfa_maxlength"
			# persist sessmax for the profile (for quick mode)
			# since the currently persisted value exceeds the
			# maximum allowed
			writeSessmax "${merged_ident[$this_idx]}" "$get_mfa_maxlength"

		elif [[ "${merged_sessmax[$this_idx]}" -gt 0 &&
				"${merged_sessmax[$this_idx]}" -lt "$get_mfa_maxlength" ]] ||

			[[ ( "${merged_sessmax[$this_idx]}" == "" || "${merged_sessmax[$this_idx]}" == "0" ) &&
				 "$get_mfa_maxlength" != "" ]]; then

			getPrintableTimeRemaining current_sessmax_pr "${merged_sessmax[$this_idx]}"
			getPrintableTimeRemaining allowed_sessmax_pr "$get_mfa_maxlength"

			if [[ "${merged_sessmax[$this_idx]}" == "" || "${merged_sessmax[$this_idx]}" == "0" ]]; then

				# accept by default if no sessmax was previously defined
				_ret="yes"

				printf "${BIYellow}${On_Black}\
NOTE: The maximum allowed session length for this profile\\n\
      has been set to ${allowed_sessmax_pr}.${Color_Off}\\n"

			else
				printf "${BIYellow}${On_Black}\
A longer session length than what is currently defined\\n\
for the profile using the 'sessmax' value is allowed. ${Color_Off}\\n\\n\
Currently defined in the profile with 'sessmax': ${BIWhite}${On_Black}${current_sessmax_pr}${Color_Off}\\n\
Allowed maximum session length for this account: ${BIWhite}${On_Black}${allowed_sessmax_pr}${Color_Off}\\n\\n\
Do you want to use the maximum allowed session length? ${BIWhite}${On_Black}Y/N${Color_Off} "

				yesNo _ret
			fi

			if [[ "${_ret}" == "yes" ]]; then

				merged_sessmax[$this_idx]="$get_mfa_maxlength"
				# persist the updated sessmax for the profile (for quick mode)
				writeSessmax "${merged_ident[$this_idx]}" "$get_mfa_maxlength"
			fi
			printf "\\n\\n"
		fi

	elif [[ "${merged_sessmax[$this_idx]}" != "" ]] &&
		[[ "${merged_sessmax[$this_idx]}" -lt "$MFA_SESSION_LENGTH_IN_SECONDS" ]]; then
		# if there is no advertised 'session_length' value in the SSM param store,
		# there is no way to know whether a profile-specific sessmax is accurate
		# or not as it would then be based on info communicated outside of this
		# script, however, we don't want to prompt user for a decision every time
		# as it may be a third party account with a different maximum session
		# length, for example, so just pring a notice instead

		getPrintableTimeRemaining merged_sessmax_pr "${merged_sessmax[$this_idx]}"
		getPrintableTimeRemaining script_default_max_pr "$MFA_SESSION_LENGTH_IN_SECONDS"

		printf "\
NOTE: This profile's 'sessmax' property currently limits this session length\\n\
      to ${BIWhite}${On_Black}${merged_sessmax_pr}${Color_Off}, a period shorter than the script default of ${BIWhite}${On_Black}${script_default_max_pr}${Color_Off}.\\n\
      However, this may be intentional and as such does not require action.\\n\\n"

	elif [[ "${merged_sessmax[$this_idx]}" != "" ]] &&
		[[ "${merged_sessmax[$this_idx]}" -gt "$MFA_SESSION_LENGTH_IN_SECONDS" ]]; then

		getPrintableTimeRemaining merged_sessmax_pr "${merged_sessmax[$this_idx]}"
		getPrintableTimeRemaining script_default_max_pr "$MFA_SESSION_LENGTH_IN_SECONDS"

		printf "\
NOTE: This profile's 'sessmax' property currently sets the session length\\n\
      to ${BIWhite}${On_Black}${merged_sessmax_pr}${Color_Off}, a period longer than the script default of ${BIWhite}${On_Black}${script_default_max_pr}${Color_Off}.\\n\
      However, this may be intentional and as such does not require action.\\n\\n"

	else

		getPrintableTimeRemaining script_default_max_pr "$MFA_SESSION_LENGTH_IN_SECONDS"

		printf "\
NOTE: The 'sessmax' property has not been defined for the profile and a custom\\n\
      session length is not advertised. Using the script default of ${BIWhite}${On_Black}${script_default_max_pr}${Color_Off}.\\n\\n"

	fi
}

checkAWSErrors() {
	# $1 is checkAWSErros_result
	# $2 is exit_on_error (true/false)
	# $3 is the AWS return (may be good or bad)
	# $4 is the profile name (if present) AWS command was run against
	# $5 is the custom message (if present);
	#    only used when $4 is positively present
	#    (such as with a MFA token request)

	local exit_on_error="${2}"
	local aws_raw_return="${3}"
	local profile_in_use
	local custom_error
	[[ "${4}" == "" ]] && profile_in_use="selected" || profile_in_use="${4}"
	[[ "${5}" == "" ]] && custom_error="" || custom_error="${5}\\n"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function checkAWSErrors] aws_raw_return: ${Yellow}${On_Black}$2${BIYellow}${On_Black}, profile_in_use: $profile_in_use, custom_error: $4 ${Color_Off}\\n\\n"

	local is_error="false"
	if [[ "$aws_raw_return" =~ InvalidClientTokenId ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}The AWS Access Key ID does not exist!${Red}\\nCheck the profile '${profile_in_use}' configuration including any 'AWS_*' environment variables.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ SignatureDoesNotMatch ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key does not match the Access Key ID!${Red}\\nCheck the profile '${profile_in_use}' configuration including any 'AWS_*' environment variables.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ IncompleteSignature ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Incomplete signature!${Red}\\nCheck the Secret Access Key of the profile '${profile_in_use}' for typos/completeness (including any 'AWS_*' environment variables).${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ Unable[[:space:]]to[[:space:]]locate[[:space:]]credentials.* ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Credentials missing!${Red}\\nCredentials for the profile '${profile_in_use}' are missing! Add credentials for the profile in the credentials file ($CREDFILE) and try again.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ MissingAuthenticationToken ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}The Secret Access Key is not present!${Red}\\nCheck the '${profile_in_use}' profile configuration (including any 'AWS_*' environment variables).${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.*AssumeRole.* ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Access denied!\\n${Red}Could not assume role '${profile_in_use}'.\\nCheck the source profile and the MFA or validating source profile session status.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.*GetSessionToken.*MultiFactorAuthentication.*invalid[[:space:]]MFA[[:space:]]one[[:space:]]time[[:space:]]pass[[:space:]]code ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Invalid MFA one time pass code!\\n${Red}Are you sure you entered MFA pass code for profile '${profile_in_use}'?${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*AccessDenied.* ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Access denied!\\n${Red}The operation could not be completed due to\\nincorrect credentials or restrictive access policy.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*InvalidAuthenticationCode.* ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Invalid authentication code!\\n${Red}Mistyped authcodes, or wrong/old vMFAd?${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ AccessDeniedException ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Access denied!${Red}\\nThe effective MFA IAM policy may be too restrictive.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ AuthFailure ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Authentication failure!${Red}\\nCheck the credentials for the profile '${profile_in_use}' (including any 'AWS_*' environment variables).${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ ServiceUnavailable ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Service unavailable!${Red}\\nThis is likely a temporary problem with AWS; wait for a moment and try again.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ ThrottlingException ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}Too many requests in too short amount of time!${Red}\\nWait for a few moments and try again.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ InvalidAction ]] ||
		[[ "$aws_raw_return" =~ InvalidQueryParameter ]] ||
		[[ "$aws_raw_return" =~ MalformedQueryString ]] ||
		[[ "$aws_raw_return" =~ MissingAction ]] ||
		[[ "$aws_raw_return" =~ ValidationError ]] ||
		[[ "$aws_raw_return" =~ MissingParameter ]] ||
		[[ "$aws_raw_return" =~ InvalidParameterValue ]]; then

		printf "\\n${BIRed}${On_Black}${custom_error}AWS did not understand the request.${Red}\\nThis should never occur with this script. Maybe there was a glitch in\\nthe matrix (maybe the AWS API changed)?\\nRun the script with the '--debug' switch to see the exact error.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ InternalFailure ]]; then
		printf "\\n${BIRed}${On_Black}${custom_error}An unspecified error occurred!${Red}\\n\"Internal Server Error 500\". Sorry I don't have more detail.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ error[[:space:]]occurred ]]; then
		printf "${BIRed}${On_Black}${custom_error}An unspecified error occurred!${Red}\\nCheck the profile '${profile_in_use}' (including any 'AWS_*' environment variables).\\nRun the script with the '--debug' switch to see the exact error.${Color_Off}\\n\\n"
		is_error="true"
	elif [[ "$aws_raw_return" =~ .*Could[[:space:]]not[[:space:]]connect[[:space:]]to[[:space:]]the[[:space:]]endpoint[[:space:]]URL ]]; then
		# always bail out if connectivity problems start mid-operation
		printf "\\n${BIRed}${On_Black}${custom_error}AWS API endpoint not reachable (connectivity problems)! Cannot continue.${Color_Off}\\n\\n"
		is_error="true"
		exit 1
	fi

	if [[ "$is_error" == "true" ]] &&
		[[ "$exit_on_error" == "true" ]]; then

			exit 1

	elif [[ "$is_error" == "true" ]] &&
		[[ "$exit_on_error" == "false" ]]; then

		eval "$1=\"true\""

	elif [[ "$is_error" == "false" ]]; then

		eval "$1=\"false\""
	fi
}

declare -a account_alias_cache_table_ident
declare -a account_alias_cache_table_result
getAccountAlias() {
	# $1 is getAccountAlias_result (returns the account alias if found)
	# $2 is the profile_ident
	# $3 is the source profile (required for roles, otherwise optional)

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getAccountAlias] profile_ident: $2, source_profile: $3${Color_Off}\\n"

	local getAccountAlias_result
	local local_profile_ident="$2"
	local source_profile="$3"
	[[ "${source_profile}" == "" ]] &&
		source_profile="$local_profile_ident"

	local account_alias_result
	local cache_hit="false"
	local cache_idx
	local itr
	local this_idx

	if [[ "$local_profile_ident" == "" ]]; then
		# no input, return blank result
		getAccountAlias_result=""
	else

		idxLookup this_idx merged_ident[@] "$local_profile_ident"

		for ((itr=0; itr<${#account_alias_cache_table_ident[@]}; ++itr))
		do
			if [[ "${account_alias_cache_table_ident[$itr]}" == "$local_profile_ident" ]]; then
				result="${account_alias_cache_table_result[$itr]}"
				cache_hit="true"
				[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}Account alias found from cache for profile ident: '$local_profile_ident'\\n${ICyan}${account_alias_result}${Color_Off}\\n"
			fi
		done

		if  [[ "$cache_hit" == "false" ]]; then

			if [[ "${merged_role_xaccn[$this_idx]}" != "true" ]]; then

				# get the account alias (if any) for the profile
				account_alias_result="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "$source_profile" iam list-account-aliases \
					--output text \
					--query 'AccountAliases' 2>&1)"

				[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"$source_profile\" iam list-account-aliases --query 'AccountAliases' --output text':\\n${ICyan}${account_alias_result}${Color_Off}\\n"

				if [[ "$account_alias_result" =~ 'error occurred' ]]; then
					# no access to list account aliases
					# for this profile or other error
					getAccountAlias_result=""

				else  # return the result & add to the local cache
					getAccountAlias_result="$account_alias_result"
					cache_idx="${#account_alias_cache_table_ident[@]}"
					account_alias_cache_table_ident[$cache_idx]="$local_profile_ident"
					account_alias_cache_table_result[$cache_idx]="$account_alias_result"
				fi

			else  # xaccn roles

				# use override region or role source profile region for the query
				if [[ "$XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE" != "" ]]; then
					query_region="--region $XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE"
				else
					query_region="--region ${merged_region[${merged_role_source_profile_idx[$this_idx]}]}"
				fi

				# get the account alias (if any) for the profile
				# if one is defined in the local (to baseprofile) ssm
				account_alias_result="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "$source_profile" $query_region ssm get-parameter \
					--name "/unencrypted/roles/${merged_account_id[$this_idx]}/alias" \
					--output text \
					--query 'Parameter.Value' 2>&1)"

				[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"$source_profile\" $query_region ssm get-parameter --name \"/unencrypted/roles/${merged_account_id[$this_idx]}/alias\" --output text --query 'Parameter.Value':\\n${ICyan}${account_alias_result}${Color_Off}\\n"

				if [[ "$account_alias_result" =~ 'error occurred' ]] ||
					[[ "$account_alias_result" == "" ]] ; then

					# no alias for the given profile in the local SSM, or no
					# access to list account aliases for this profile or other error
					getAccountAlias_result=""

				else  # return the result & add to the local cache
					getAccountAlias_result="$account_alias_result"
					cache_idx="${#account_alias_cache_table_ident[@]}"
					account_alias_cache_table_ident[$cache_idx]="$local_profile_ident"
					account_alias_cache_table_result[$cache_idx]="$account_alias_result"
				fi
			fi
		fi
	fi
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getAccountAlias_result}${Color_Off}\\n"
	eval "$1=\"$getAccountAlias_result\""
}

dynamicAugment() {

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function dynamicAugment]${Color_Off}\\n"

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
			printf "${BIWhite}${On_Black}Please wait.${Color_Off}"
			notice_reprint="false"
		fi

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** dynamic augment for ident '${merged_ident[$idx]}' (${merged_type[$idx]})${Color_Off}\\n"

		if [[ "${merged_type[$idx]}" == "baseprofile" ]]; then  # BASEPROFILE AUGMENT (includes root profiles) --------

			# this has been abstracted so that it can
			# also be used for JIT check after select
			profileCheck profile_validity_check "${merged_ident[$idx]}"

		elif [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]]; then  # ROLE AUGMENT (no point augmenting invalid roles) -----------

			# 'jq' check and notice
			if [[ "${jq_notice}" == "true" ]]; then

				jq_notice="false"

				if [[ "$jq_available" == "false" ]]; then
					printf "\\n${BIWhite}${On_Black}\
Since you are using roles, consider installing 'jq'.${Color_Off}\\n
It will speed up some role-related operations and\\n\
make it possible to automatically import roles that\\n\
are initialized outside of this script.\\n\\n"

					if [[ "$OS" == "macOS" ]] &&
						[[ "$has_brew" == "true" ]]; then

						printf "Install with: 'brew install jq'\\n\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "apt" ]]; then

						printf "Install with:\\nsudo apt update && sudo apt -y install jq\\n\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "yum" ]]; then

						printf "Install with:\\nsudo yum install -y epel-release && sudo yum install -y jq\\n\\n"

					else
						printf "Install 'jq' with your operating system's package manager.\\n\\n"
					fi

				elif [[ "$jq_minimum_version" == "false" ]]; then
					printf "\\n${BIWhite}${On_Black}\
Please upgrade your 'jq' installation (minimum required version is 1.5).${Color_Off}\\n\\n"

					if [[ "$OS" == "macOS" ]] &&
						[[ "$has_brew" == "true" ]]; then

						printf "Upgrade with: 'brew upgrade jq'\\n\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "apt" ]]; then

						printf "Upgrade with:\\nsudo apt update && sudo apt -y upgrade jq\\n\\n"

					elif [[ "$OS" =~ Linux$ ]] &&
						[[ "$install_command" == "yum" ]]; then

						printf "Upgrade with: 'sudo yum upgrade -y jq'\\n\\n"

					else
						printf "Upgrade 'jq' with your package manager.\\n\\n"
					fi
				fi
			fi  # end [[ "${jq_notice}" == "true" ]]

			# a role must have an existing source_profile defined
			if [[ "${merged_role_source_profile_ident[$idx]}" == "" ]] ||
				[[ "${merged_role_source_profile_absent[$idx]}" == "true" ]]; then

				notice_reprint="true"

				printf "\\n\\n${BIRed}${On_Black}The role profile '${merged_ident[$idx]}' does not have a valid source_profile defined.${Color_Off}\\n\\n"

				if [[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then
					printf "${BIRed}${On_Black}CURRENT INVALID SOURCE PROFILE: ${merged_role_source_profile_ident[$idx]}${Color_Off}\\n\\n"
				fi

				printf "A role must have the means to authenticate, so select below the associated source profile:\\n\\n"

				# prompt for source_profile selection for this role
				while :
				do
					printf "${BIWhite}${On_DGreen} AVAILABLE AWS BASEPROFILES: ${Color_Off}\\n\\n"

					declare -a source_select
					source_sel_idx="1"

					for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))
					do
						if [[ "${merged_type[$int_idx]}" == "baseprofile" ]]; then

							printf "${BIWhite}${On_Black}${source_sel_idx}: ${merged_ident[$int_idx]}${Color_Off}\\n\\n"

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

						printf "\\n${BIWhite}${On_DGreen} AVAILABLE ROLE PROFILES (FOR ROLE CHAINING): ${Color_Off}\\n\\n"

						printf "$source_role_selection_string\\n"
					fi

					# print any error from the previous round
					if [[ "$role_source_sel_error" != "" ]]; then
						printf "$role_source_sel_error\\n"

						role_source_sel_error=""
					fi

					# prompt for a baseprofile selection
					printf "\\n\
NOTE: If you don't set a source profile, you can't use this role until you do so.\\n${BIYellow}${On_Black}\
SET THE SOURCE PROFILE FOR ROLE '${merged_ident[$idx]}'.\\n${BIWhite}\
Select the source profile by the ID and press Enter (or Enter by itself to skip): "
					read -r role_sel_idx_selected
					printf "${Color_Off}\\n"

					[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}Source profile index selected: ${role_sel_idx_selected}${Color_Off}\\n"

					if [[ "$role_sel_idx_selected" -gt 0 && "$role_sel_idx_selected" -le $source_sel_idx ]]; then
						# this is a profile selector for a valid role source_profile

						# get the corresponding source profile index
						source_profile_index="${source_select[$role_sel_idx_selected]}"

						[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   Actual corresponding source index: ${source_profile_index}${Color_Off}\\n"

						# everybody with the EnforceMFA policy is allowed to query roles
						# without an active MFA session; try to use the selected profile
						# to query the role (we already know the role's Arn, so this is
						# just a reverse lookup to validate). If jq is available, this
						# will cache the result.
						#
						# Acceptable choices are: baseprofile (by definition) or
						# another role profile which has a baseprofile defined
						#
						# NOTE: This will *only* work with profiles residing in the
						#       same account as the source profile! Cross-account
						#       roles cannot be validated and are considered the same
						#       as third party roles.
						local_role="true"
						if [[ "${merged_type[$source_profile_index]}" == "baseprofile" ]] ||
							[[ "${merged_role_source_baseprofile_ident[$source_profile_index]}" != "" ]]; then

							# the account ID of the source profile and the role
							# must match for the check to be meaningful; the role
							# details aren't queriable for delegated xaccount roles
							if [[ "${merged_account_id[$source_profile_index]}" == "${merged_account_id[$idx]}" ]]; then

								if [[ "${merged_type[$source_profile_index]}" == "baseprofile" ]]; then

									query_with_this="${merged_ident[$source_profile_index]}"
								else  # this is the source_profile of a chained role; use its baseprofile

									query_with_this="${merged_role_source_baseprofile_ident[$source_profile_index]}"
								fi

								if [[ "$jq_minimum_version_available" == "true" ]]; then

									cached_get_role_arr[$idx]="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${query_with_this}" iam get-role \
										--role-name "${merged_role_name[$idx]}" \
										--output 'json' 2>&1)"

									[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${query_with_this}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --output 'json':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}\\n"

									checkGetRoleErrors cached_get_role_error "${cached_get_role_arr[$idx]}"

									if [[ ! "$cached_get_role_error" =~ ^ERROR_ ]]; then
										get_this_role_arn="$(printf '\n%s\n' "${cached_get_role_arr[$idx]}" | jq -r '.Role.Arn')"
									else
										get_this_role_arn="$cached_get_role_error"
									fi

								else

									get_this_role_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${query_with_this}" iam get-role \
										--role-name "${merged_role_name[$idx]}" \
										--query 'Role.Arn' \
										--output 'text' 2>&1)"

									[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${query_with_this}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.Arn' --output 'text':\\n${ICyan}${get_this_role_arn}${Color_Off}\\n"

									checkGetRoleErrors get_this_role_arn_error "$get_this_role_arn"

									[[ "$get_this_role_arn_error" != "none" ]] &&
										get_this_role_arn="$get_this_role_arn_error"
								fi
							else
								local_role="false"
							fi
						fi

						if [[ "$get_this_role_arn" == "${merged_role_arn[$idx]}" ]] ||
							[[ "${merged_role_chained_profile[$idx]}" == "true" ]] ||
							[[ "${local_role}" == "false" ]]; then

							[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}Source profile selection approved${Color_Off}\\n"

							[[ "$DEBUG" == "true" ]] && printf "${Green}${On_Black}\
Using the profile '${merged_ident[$source_profile_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n\\n"

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
							# NOTE: does not apply to delegated roles

							role_source_sel_error="\\n${BIRed}${On_Black}\
Either the role '${merged_ident[$idx]}' is not associated with\\n\
the selected source profile '${merged_ident[$source_profile_index]}',\\n\
or the role doesn't exist. Select another profile?${Color_Off}"

							# this flows through, and thus reprints the base
							# profile list for re-selection

						elif [[ "$get_this_role_arn" == "ERROR_BadProfile" ]]; then

							# something is wrong with the role profile configuration;
							# check the profile Arn for corrent format

							role_source_sel_error="\\n${BIRed}${On_Black}\
Something is wrong with the role configuration! To start with, make sure\\n\
the role Arn is of the correct format! The role Arn in question:\\n\
${merged_role_arn[$idx]}\\n\
The general valid role Arn format:
arn:aws:iam::{aws_account_number}:role/{role_name}${Color_Off}"

							toggleInvalidProfile "set" "${merged_ident[$idx]}"
							break

						elif [[ "$get_this_role_arn" == "ERROR_BadJSON" ]]; then

							# something went wrong with the query; bad profile config?

							role_source_sel_error="\\n${BIRed}${On_Black}\
An unspecified error occurred; the profile could not be selected!\\n\
Please verify your profile configuration and try again.\\n${Color_Off}"

							toggleInvalidProfile "set" "${merged_ident[$idx]}"
							break

						else  # this includes ERROR_BadSource error condition as it is basically the same
							  # and also a source with that error should not be on the list to select from
							printf "${BIWhite}${On_Black}\
The selected profile '${merged_ident[$source_profile_index]}' could not be verified as\\n\
the source profile for the role '${merged_ident[$idx]}'. However,\\n\
this could be because of the selected profile's permissions.${Color_Off}\\n\\n
Do you want to keep the selection? ${BIWhite}${On_Black}Y/N${Color_Off} "

							yesNo _ret

							if [[ "${_ret}" == "yes" ]]; then

								printf "${Green}${On_Black}\
Using the profile '${merged_ident[$source_profile_index]}' as the source profile for the role '${merged_ident[$idx]}'${Color_Off}\\n\\n"

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
						printf "\\n${BIWhite}${On_Black}Skipped. Role remains unusable until a source profile is added to it.${Color_Off}\\n\\n"

						# blank out the invalid merged_role_source_profile_ident
						# so that the rest of the script can't use/advertise it
						merged_role_source_profile_ident[$idx]=""

						# make sure the role is set to invalid

						toggleInvalidProfile "set" "${merged_ident[$idx]}"
						break
					else
						# an invalid entry

						printf "\\n${BIRed}${On_Black}\
Invalid selection.${Color_Off}\\n\
Try again, or just press Enter to skip setting source_profile\\n\
or vMFAd serial number for this role profile at this time.\\n\\n"
					fi
				done

			else  # ------- ROLE ALREADY HAS source_profile

				# source_profile exists already, so just do
				# a lookup and cache here if jq is enabled
				if [[ "$jq_minimum_version_available" == "true" ]]; then

					cached_get_role_arr[$idx]="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--output 'json' 2>&1)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --output 'json':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}\\n"

					checkGetRoleErrors cached_get_role_error "${cached_get_role_arr[$idx]}"

					[[ "$cached_get_role_error" != "none" ]] &&
						cached_get_role_arr[$idx]="$cached_get_role_error"

					if [[ ! "${cached_get_role_error}" =~ ^ERROR_ ]]; then

						get_this_role_arn="$(printf '\n%s\n' "${cached_get_role_arr[$idx]}" | jq -r '.Role.Arn')"
						toggleInvalidProfile "unset" "${merged_ident[$idx]}"

					else
						# relay errors for analysis
						get_this_role_arn="${cached_get_role_arr[$idx]}"

					fi

				else # no jq

					get_this_role_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--query 'Role.Arn' \
						--output 'text' 2>&1)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.Arn' --output 'text':\\n${ICyan}${cached_get_role_arr[$idx]}${Color_Off}\\n"

					checkGetRoleErrors get_this_role_arn_error "$get_this_role_arn"

					if [[ "$get_this_role_arn_error" != "none" ]]; then

						get_this_role_arn="$get_this_role_arn_error"
						toggleInvalidProfile "unset" "${merged_ident[$idx]}"
					fi
				fi

				if [[ "$get_this_role_arn" =~ ^ERROR_(NoSuchEntity|BadSource|BadProfile|BadJSON) ]]; then

					# potentially invalidate the profile, but wait
					# until the xaccn status has been determined as
					# xaccn roles cannot be invalidated
					merged_deferred_profile_state[$idx]="set"
				else
					merged_deferred_profile_state[$idx]="unset"
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
				(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}")
			fi

			# Note: this sets output for an already existing
			#       profile that has been read in; setessionOutputAndRegion
			#       imports this value to the output globals
			if [[ "${merged_output[$idx]}" == "" ]] &&   # the output format is not set for this role
				[[ "${merged_role_source_profile_idx[$idx]}" != "" ]] &&  # the source_profile is [now] defined
				[[ "${merged_output[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # and the source_profile has a output set

				merged_output[$idx]="${merged_output[${merged_role_source_profile_idx[$idx]}]}"

				# make the role output persistent
				(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$idx]}" configure set output "${merged_output[$idx]}")
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
					get_this_role_sessmax="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" iam get-role \
						--role-name "${merged_role_name[$idx]}" \
						--query 'Role.MaxSessionDuration' \
						--output 'text' 2>&1)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.MaxSessionDuration' --output 'text':\\n${ICyan}${get_this_role_sessmax}${Color_Off}\\n"

					checkGetRoleErrors get_this_role_sessmax_error "$get_this_role_sessmax"

					[[ "$get_this_role_sessmax_error" != "none" ]] &&
						get_this_role_sessmax="$get_this_role_sessmax_error"
				fi

				# minimum acceptable sessmax value is 900 seconds,
				# hence at least three digits in the pattern below
				if [[ "$get_this_role_sessmax" =~ ^[[:space:]]*[[:digit:]][[:digit:]][[:digit:]]+[[:space:]]*$ ]]; then

					if [[ "${merged_sessmax[$idx]}" != "" ]]; then

						if [[ "$get_this_role_sessmax" == "$ROLE_SESSION_LENGTH_IN_SECONDS" ]] ||

							[[ "${merged_sessmax[$idx]}" -lt "900" ||
							   "${merged_sessmax[$idx]}" -gt "129600" ]]; then

							# set sessmax internally to the default if:
							#  - the role's def is the same as the script def (usually 3600)
							#  - the persisted sessmax is outside the allowed range 900-129600

							merged_sessmax[$idx]="$ROLE_SESSION_LENGTH_IN_SECONDS"

							# then erase the persisted sessmax since the default is used
							writeSessmax "${merged_ident[$idx]}" "erase"

						elif [[ "${merged_sessmax[$idx]}" -gt "$get_this_role_sessmax" ]]; then

							#  The persisted sessmax is greater than the maximum length defined
							#  in the role policy, so we truncate to maximum allowed
							merged_sessmax[$idx]="$get_this_role_sessmax"

							# then erase the persisted sessmax since the default is used
							writeSessmax "${merged_ident[$idx]}" "$get_this_role_sessmax"
						fi

					else  # local sessmax for the profile hasn't been defined

						if [[ "$get_this_role_sessmax" != "$ROLE_SESSION_LENGTH_IN_SECONDS" ]]; then

							# set sessmax for the role for quick mode since the role's session
							# length is different from the set default (usually 3600)

							merged_sessmax[$idx]="$get_this_role_sessmax"

							# then erase the persisted sessmax since the default is used
							writeSessmax "${merged_ident[$idx]}" "$get_this_role_sessmax"
						fi
					fi

				else  # could not acquire role's session length (due to policy)

					# setting these blindly, just a sanity check
					if [[ "${merged_sessmax[$idx]}" != "" ]] &&
						[[ "${merged_sessmax[$idx]}" -lt "900" ||
						   "${merged_sessmax[$idx]}" -gt "129600" ]]; then

						# set sessmax internally to the default if:
						#  - the persisted sessmax is outside the allowed range 900-129600
						merged_sessmax[$idx]="$ROLE_SESSION_LENGTH_IN_SECONDS"

						# then erase the persisted sessmax since the default is used
						writeSessmax "${merged_ident[$idx]}" "erase"
					fi
				fi
			fi

		elif [[ "${merged_type[$idx]}" =~ mfasession|rolesession ]]; then  # MFA OR ROLE SESSION AUGMENT ------------

			# no point to augment this session if the timestamps indicate
			# the session has expired or if the session's credential information
			# is incomplete (i.e. the sessio is invalid). Note: this also checks
			# the session validity for the sessions whose init+sessmax or expiry
			# weren't set for some reason. After this process merged_session_status
			# will be populated for all sessions with one of the following values:
			# valid, expired, invalid (i.e. not expired but not functional)

			if [[ ! "${merged_session_status[$idx]}" =~ ^(expired|invalid)$ ]]; then

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
			printf "${BIWhite}${On_Black}Please wait.${Color_Off}"
			notice_reprint="false"
		elif [[ "$DEBUG" != "true" ]]; then
			printf "${BIWhite}${On_Black}.${Color_Off}"
		fi

		# reset a loop variable
		get_this_role_mfa_req="false"

	done

	# phase II for things that have a depencency for a complete profile reference from PHASE I
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" == "role" ]] &&
			[[ "${merged_role_arn[$idx]}" != "" ]] &&
			[[ "${merged_role_source_profile_ident[$idx]}" != "" ]]; then  # ROLE AUGMENT, PHASE II -------------------

			# set default for role_xaccn as 'false' if it was not set in the persisted props
			[[ "${merged_role_xaccn[$idx]}" == "" ]] &&
				merged_role_xaccn[$idx]="false"

			# add source_profile username to the merged_role_source_username array
			merged_role_source_username[$idx]=""
			if [[ "${merged_role_source_baseprofile_idx[$idx]}" != "" ]]; then

				# merged_username is now available for all baseprofiles
				# (since this comes after the first dynamic augment loop)
				merged_role_source_username[$idx]="${merged_username[${merged_role_source_baseprofile_idx[$idx]}]}"

				# determine if this is a local or a x-account role
				# (note: baseprofile's merged_account_id is a dynamic
				# operation and thus only available here in dynamic augment)

				if [[ "${merged_account_id[$idx]}" == "${merged_account_id[${merged_role_source_baseprofile_idx[$idx]}]}" ]]; then

					# this role is local to its source_profile
					merged_role_xaccn[$idx]="false"

					# persist the detected local role for quick mode intelligence
					# (ensure it's not marked as xaccn)
					writeRoleXaccn $idx "false"

					# role_mfa requirement check (persist the associated
					# source profile mfa_arn if avialable/changed)
					if [[ "$jq_minimum_version_available" == "true" ]]; then
						# use the cached get-role to avoid
						# an extra lookup if jq is available

						if [[ ! "${cached_get_role_arr[$idx]}" =~ ^ERROR_ ]]; then

							get_this_role_mfa_req="$(printf '%s' "${cached_get_role_arr[$idx]}" | jq -r '.Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"')"
						fi

					else

						get_this_role_mfa_req="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" --region "${merged_region[${merged_role_source_baseprofile_idx[$idx]}]}" iam get-role \
							--role-name "${merged_role_name[$idx]}" \
							--query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' \
							--output 'text' 2>&1)"

						[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" --region \"${merged_region[${merged_role_source_baseprofile_idx[$idx]}]}\" iam get-role --role-name \"${merged_role_name[$idx]}\" --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool.*' --output 'text':\\n${ICyan}${get_this_role_mfa_req}${Color_Off}\\n"

						checkGetRoleErrors get_this_role_mfa_req_errors "$get_this_role_mfa_req"

						[[ "$get_this_role_mfa_req_errors" != "none" ]] &&
							get_this_role_mfa_req="$get_this_role_mfa_req_errors"

					fi

				else  # the role ARN account and the source_profile ARN account do not match -- A XACCN ROLE!!

					# this role is remote to its source_profile (a x-accn role)
					merged_role_xaccn[$idx]="true"

					# persist the detected xaccn for quick mode intelligence
					writeRoleXaccn $idx "true"

					# use override region or role source profile region for the query
					if [[ "$XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE" != "" ]]; then
						query_region="--region $XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE"
					else
						query_region="--region ${merged_region[${merged_role_source_profile_idx[$idx]}]}"
					fi

					# query the local SSM for session_length & mfa_required;
					# if found, set as sessmax & mfa_req in merged_ arrays and persist

					# SESSION_LENGTH
					get_this_role_session_maxlength="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" $query_region ssm get-parameter \
						--name "/unencrypted/roles/${merged_account_id[$idx]}/${merged_role_name[$idx]}/session_length" \
						--output 'text' \
						--query 'Parameter.Value' 2>&1)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" $query_region ssm get-parameter --name \"/unencrypted/roles/${merged_account_id[$idx]}/${merged_role_name[$idx]}/session_length\" --query 'Parameter.Value' --output 'text':\\n${ICyan}${get_this_role_session_maxlength}${Color_Off}\\n"

					if [[ "$get_this_role_session_maxlength" =~ .*ParameterNotFound.* ]]; then

						[[ "$DEBUG" == "true" ]] &&
							printf "${BIWhite}${On_Black}No session_maxlength data available for the x-accn role \"${merged_role_name[$idx]}\"; assuming the default ${ROLE_SESSION_LENGTH_IN_SECONDS}.${Color_Off}"

					elif  [[ "$get_this_role_session_maxlength" =~ ^[[:digit:]][[:digit:]][[:digit:]]+$ ]] &&
						! [[ "$get_this_role_session_maxlength" -lt "900" ||
 							 "$get_this_role_session_maxlength" -gt "129600" ]]; then

						# add to the array & persist if no errors occurred and the value has been set
						merged_sessmax[$idx]="$get_this_role_session_maxlength"
						writeSessmax "${merged_ident[$idx]}" "$get_this_role_session_maxlength"

					else

						# illegal value or other error occurred, so we use the default
						merged_sessmax[$idx]="${ROLE_SESSION_LENGTH_IN_SECONDS}"

						[[ "$DEBUG" == "true" ]] &&
							printf "\\n\
${BIWhite}${On_Black}An unspecified anomaly occurred while retrieving session_length data for the x-accn role \"${merged_role_name[$idx]}\"\\n\
Assuming the role session default length of ${ROLE_SESSION_LENGTH_IN_SECONDS} seconds.${Color_Off}\\n"

					fi

					# MFA_REQUIRED
					get_this_role_mfa_req="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_role_source_baseprofile_ident[$idx]}" $query_region ssm get-parameter \
						--name "/unencrypted/roles/${merged_account_id[$idx]}/${merged_role_name[$idx]}/mfa_required" \
						--output 'text' \
						--query 'Parameter.Value' 2>&1)"

					[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_role_source_baseprofile_ident[$idx]}\" $query_region ssm get-parameter --name \"/unencrypted/roles/${merged_account_id[$idx]}/${merged_role_name[$idx]}/mfa_required\" --query 'Parameter.Value' --output 'text':\\n${ICyan}${get_this_role_mfa_req}${Color_Off}\\n"

					if [[ "$get_this_role_mfa_req" =~ .*ParameterNotFound.* ]]; then

						# no entry; assume not required (to override )
						merged_role_mfa_required[$idx]="false"
						get_this_role_mfa_req="false"

						[[ "$DEBUG" == "true" ]] &&
							printf "${BIWhite}${On_Black}No mfa_required data available for the x-accn role \"${merged_role_name[$idx]}\".${Color_Off}"

					elif [[ ! "$get_this_role_mfa_req" =~ ^(true|false)$ ]]; then

						merged_role_mfa_required[$idx]="false"
						get_this_role_mfa_req="false"

						[[ "$DEBUG" == "true" ]] &&
							printf "\\n\
${BIWhite}${On_Black}An unspecified anomaly occurred while retrieving mfa_required data for the x-accn role \"${merged_role_name[$idx]}\"\\n\
Assuming no MFA required by default.${Color_Off}\\n"

					elif [[ "$get_this_role_mfa_req" =~ ^(true|false)$ ]]; then
						
						# for xaccn roles respect the SSM only in showing the MFA req'd notice
						merged_role_ssm_mfareq_lookup[$idx]="true"

					fi
				fi
			fi

			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}Processing MFA req for role name '${merged_role_name[$idx]}'. MFA is req'd (by policy): ${get_this_role_mfa_req}${Color_Off}\\n"

			if [[ "${get_this_role_mfa_req}" == "true" ]] ||
				[[ "${merged_role_xaccn[$idx]}" == "true" ]]; then

				if [[ "${get_this_role_mfa_req}" == "false" ]] &&
					[[ "${merged_role_xaccn[$idx]}" == "true" ]]; then

					# for xaccn with legit false mfa_req, write mfa arn
					# nonetheless because if an xaccn role details aren't
					# advertised in SSM, its mfa_req cannot be known
					# and is always 'false' (even when actually required)
					merged_role_mfa_required[$idx]="false"

				else 
					# the normal state
					merged_role_mfa_required[$idx]="true"
				fi

				this_source_mfa_arn="${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}"

				if [[ "$this_source_mfa_arn" == "" &&
					  "${merged_mfa_arn[$idx]}" != "" ]] ||

					# always remove MFA ARN from a chained profile if present
					[[ "${merged_mfa_arn[$idx]}" != "" &&
					   "${merged_role_chained_profile[$idx]}" == "true" ]]; then

					# A non-functional role: the role requires an MFA,
					# the role profile has a vMFAd configured, but the
					# source profile [no longer] has one configured
					#
					# OR this is a chained role; they authenticate with
					# the upstream role's existing role session, and never
					# with an MFA
					writeProfileMfaArn "${merged_ident[$idx]}" "erase"

				elif [[ "$this_source_mfa_arn" != "" ]] &&
					[[ "${merged_mfa_arn[$idx]}" != "$this_source_mfa_arn" ]] &&
					[[ "${merged_role_chained_profile[$idx]}" != "true" ]]; then

					# the role requires an MFA, the source profile
					# has vMFAd available, and it differs from what
					# is currently configured (including blank)
					#
					# Note: "blank to configured" is the most likely scenario
					# here since unless the role's source_profile changes
					# the vMFAd Arn doesn't change even if it gets reissued
					writeProfileMfaArn "${merged_ident[$idx]}" "$this_source_mfa_arn"
				fi
			else
				merged_role_mfa_required[$idx]="false"

				# the role [no longer] requires an MFA
				# and one is currently configured, so remove it
				if [[ "${merged_mfa_arn[$idx]}" != "" ]]; then

					writeProfileMfaArn "${merged_ident[$idx]}" "erase"
				fi
			fi

			if [[ ( "${merged_role_source_profile_ident[$idx]}" != "" &&
				    "${merged_role_source_profile_absent[$idx]}" == "false" ) &&

			   		"${merged_role_source_baseprofile_ident[$idx]}" != "" ]]; then

				[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}   source baseprofile ident: ${merged_role_source_baseprofile_ident[$idx]}${Color_Off}\\n"

				# get role account alias when available; this is available
				# for local roles and x-accn roles when target account details
				# are advertised in SSM.
				getAccountAlias _ret "${merged_ident[$idx]}" "${merged_role_source_baseprofile_ident[$idx]}"

				if [[ ! "${_ret}" =~ 'could not be found' ]]; then

					merged_account_alias[$idx]="${_ret}"
				fi
			fi
		fi

		# process the deferred profile state set now that xaccn state is known
		if [[ "${merged_deferred_profile_state[$idx]}" == "set" ]] &&
			[[ "${merged_role_xaccn[$idx]}" != "true" ]]; then

			# the role is gone or the source profile is bad;
			# either way, the role is invalid
			# NOTE: do not invalidate xaccn roles as they're inverifiable
			# especially when MFA is enforced (so we won't even try)
			toggleInvalidProfile "set" "${merged_ident[$idx]}"

		else
			toggleInvalidProfile "unset" "${merged_ident[$idx]}"

		fi

 	done

	[[ "$DEBUG" != "true" ]] &&
		printf "${BIWhite}${On_Black}.${Color_Off}"

	printf "\\n\\n"
}

getMfaToken() {
	# $1 is getMfaToken_result
	# $2 is token_target ('mfa' or 'role')

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getMfaToken] token_target: $2${Color_Off}\\n"

	getMfaToken_result=""
	local token_target="$2"

	while :
	do
		printf "${BIWhite}${On_Black}"
		read -p ">>> " -r getMfaToken_result
		printf "${Color_Off}"

		if [[ "$token_target" == "mfa" ]]; then

			if ! [[ "$getMfaToken_result" =~ ^$ || "$getMfaToken_result" =~ ^[0-9]{6}$ ]]; then
				printf "${BIRed}${On_Black}The MFA token must be exactly six digits, or blank to bypass (to use the baseprofile without an MFA session).${Color_Off}\\n"
				continue
			else
				break
			fi

		elif [[ "$token_target" == "role" ]]; then

			if ! [[ "$getMfaToken_result" =~ ^[0-9]{6}$ ]]; then
				printf "${BIRed}${On_Black}The MFA token must be exactly six digits.${Color_Off}\\n"
				continue
			else
				break
			fi
		fi
	done

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getMfaToken_result}${Color_Off}\\n"
	eval "$1=\"$getMfaToken_result\""
}

persistSessionMaybe() {
 	# $1 is the baseprofile ident
	# $2 is the target (session) ident
	# $3 is session result dataset
	# $4 (bool) is, if present, a request for no-questions-asked persist (a call by the role session init MFA init request)

	interactive_persist="false"  # this is used as a marker for auto-export
	local baseprofile_ident="$1"
	local target_session_ident="$2"
	local session_data="$3"
	local confs_profile_idx
	local creds_profile_idx
	local session_word="MFA"
	local auto_persist="false"
	[[ "$4" == "true" ]] && auto_persist="true"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function persistSessionMaybe] baseprofile_ident: $baseprofile_ident, target_session_ident: $target_session_ident, auto_persist: $auto_persist, session_data: $session_data${Color_Off}\\n"

	# interactive request
	if [[ "${auto_persist}" == "false" ]]; then

		[[ "$AWS_ROLESESSION_INITIALIZED" == "true" ]] &&
			session_word="role"

			printf "${BIWhite}${On_Black}\
Make this $session_word session persistent?${Color_Off} (Saves the session in $CREDFILE\\n\
so that you can return to it during its validity period, ${AWS_SESSION_EXPIRY_PR}.)\\n"

		read -s -p "$(printf "${BIWhite}${On_Black}Yes (default) - make persistent${Color_Off}; No - only the envvars will be used ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
		printf "\\n"
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
			printf "\\n\\n" >> "$CONFFILE"
			printf "[profile ${AWS_SESSION_IDENT}]\\n" >> "$CONFFILE"
			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** ADDED A CONFFILE STUB FOR: ${AWS_SESSION_IDENT}${Color_Off}\\n"
		fi

		# get index in creds array if any (use duplicate as
		# the creds_ident is truncated during merge)
		idxLookup creds_profile_idx creds_ident_duplicate[@] "$AWS_SESSION_IDENT"

		if [[ "$creds_profile_idx" == "" ]]; then

			# no existing profile was found; make sure there's
			# a stub entry for the session profile in $CREDFILE
			# in preparation to persisting the profile
			printf "\\n\\n" >> "$CREDFILE"
			printf "[${AWS_SESSION_IDENT}]\\n" >> "$CREDFILE"
			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** ADDED A CREDFILE STUB FOR: ${AWS_SESSION_IDENT}${Color_Off}\\n"
		fi

		# PERSIST THE CONFIG
		# persist the session expiration time
		writeSessionExpTime "$AWS_SESSION_IDENT" "$AWS_SESSION_EXPIRY"

		# persist the region and the output format
		setSessionOutputAndRegion "$AWS_SESSION_IDENT" "true"

		# a global indicator that a persistent MFA session has been initialized
		persistent_MFA="true"

		# PERSIST THE CREDENTIALS
		# export the selection to the remaining subshell commands in this script
		# so that "--profile" selection is not required, and in fact should not
		# be used for setting the credentials (or else they go to the conffile)
		export AWS_DEFAULT_PROFILE="$AWS_SESSION_IDENT"
		# even though AWS_PROFILE is only used by the SDKs we're setting it for
		# completeness' sake (and for legacy reasons ;-)
		export AWS_PROFILE="$AWS_SESSION_IDENT"

		# make sure a persisted profile isn't marked invalid (this is a likely
		# scenario, as a previously persisted sessions that have expired are
		# marked invalid)
		toggleInvalidProfile "unset" "$AWS_SESSION_IDENT"

		# NOTE: These do not require the "--profile" switch because AWS_DEFAULT_PROFILE
		#       has been exported above. If you set --profile, the details
		#       go to the CONFFILE instead of CREDFILE (so don't set it! :-)
		aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
		aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
		aws configure set aws_session_token "$AWS_SESSION_TOKEN"

	elif [[ "${auto_persist}" == "false" ]] &&
		[[ "${interactive_persist}" == "false" ]]; then

		# when persist is interactively declined, set the in-script
		# globals for the region and the output format
		setSessionOutputAndRegion "$AWS_SESSION_IDENT" "false"
	fi
}

AWS_MFASESSION_INITIALIZED="false"
AWS_ROLESESSION_INITIALIZED="false"
acquireSession() {
	# $1 is acquireSession_result
	# $2 is the source profile - a baseprofile or a role profile - ident
	# $3 is, if present, a request for no-questions-asked auto-persist (a recursive call by the role session init)

	local session_sourceprofile_ident="$2"
	local auto_persist_request="false"
	[[ "$3" == "true" ]] && auto_persist_request="true"

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function acquireSession] base/role profile ident: $2, auto_persist: $3${Color_Off}\\n"

	mfa_token=""
	local acquireSession_result
	local session_request_type="unknown"
	local role_session_request_type
	local source_profile_has_session
	local source_profile_mfa_session_status
	local mfa_session_detail
	local profile_idx
	local role_init_profile=""
	local serial_switch=""
	local token_switch=""
	local external_id_switch=""
	local session_duration
	local profile_check
	local output_type
	local result=""
	local result_check
	local session_word

	[[ "$jq_minimum_version_available" == "true" ]] &&
		output_type="json" ||
		output_type="text"

	# get the requesting profile idx
	idxLookup profile_idx merged_ident[@] "$session_sourceprofile_ident"

	# get the type of session being requested ("baseprofile" for mfasession, "role" for rolesession, or "root" for root MFA session)
	if [[ "${merged_type[$profile_idx]}" != "" ]]; then
		session_request_type="${merged_type[$profile_idx]}"
	fi

	if [[ "$session_request_type" =~ ^(baseprofile|root)$ ]]; then  # INIT BASEPROFILE/ROOT MFASESSION ----------------

		getMaxSessionDuration session_duration "$session_sourceprofile_ident" "baseprofile"

		if [[ "${auto_persist_request}" == "false" ]]; then

			if [[ "$session_request_type" != "root" ]]; then

				printf "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${merged_ident[$profile_idx]}'\\n\
to start/renew an MFA session,${Color_Off} or leave empty (just press [ENTER])\\n\
to use the selected baseprofile without the MFA.\\n\\n"

			else  # this is root

				printf "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the root user profile '${merged_ident[$profile_idx]}'\\n\
to start/renew a root MFA session,${Color_Off} or leave empty (just press [ENTER])\\n\
to use the selected root credentials without the MFA.\\n\\n"

			fi

			getMfaToken mfa_token "mfa"

		else  # this is a recursive req by rolesession init to acquire a parent
			  # baseprofile MFA session; do not allow skipping of the MFA token entry

			printf "\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${merged_ident[$profile_idx]}'\\n\
to start an MFA session${Color_Off} (it will be persisted automatically).\\n\\n"

			getMfaToken mfa_token "role"
		fi

		if [[ "$mfa_token" != "" ]]; then

			acquireSession_result="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$profile_idx]}" sts get-session-token \
				--serial-number "${merged_mfa_arn[$profile_idx]}" \
				--duration "$session_duration" \
				--token-code "$mfa_token" \
				--output "$output_type" 2>&1)"

			if [[ "$DEBUG" == "true" ]]; then
				printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$profile_idx]}\" sts get-session-token --serial-number \"${merged_mfa_arn[$profile_idx]}\" --duration \"$session_duration\" --token-code \"$mfa_token\" --output \"$output_type\"':\\n${ICyan}${acquireSession_result}${Color_Off}\\n"
			fi

			# exits on error
			checkAWSErrors _is_error "true" "$acquireSession_result" "${merged_ident[$profile_idx]}" "An error occurred while attempting to acquire the MFA session credentials; cannot continue!"

			# determines whether to print session details
			session_profile="true"

		else  # empty mfa_token

			if [[ "$DEBUG" == "true" ]]; then
				printf "\\n${Cyan}${On_Black}** Requesting baseprofile as-is (no MFA session initialized)${Color_Off}\\n"
			fi

			AWS_DEFAULT_PROFILE="${merged_ident[$profile_idx]}"
			AWS_PROFILE="$AWS_DEFAULT_PROFILE"

			# determines whether to print session details
			session_profile="false"
		fi

	elif [[ "$session_request_type" == "role" ]]; then  # INIT ROLESESSION --------------------------------------------

		if [[ "${merged_role_chained_profile[$profile_idx]}" == "true" ]]; then

			role_session_request_type="chained"
		else
			role_session_request_type="standard"
		fi

		# does the source_profile have an MFA session?
		source_profile_has_session="${merged_has_session[${merged_role_source_profile_idx[$profile_idx]}]}"

		# is the MFA session valid?
		# (role profile IDX -> role source_profile IDX -> source profile's session IDX -> source profile's session status)
		source_profile_mfa_session_status="${merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$profile_idx]}]}]}"

		if [[ "$DEBUG" == "true" ]]; then
			printf "\\n${Yellow}${On_Black}\
role_session_request_type: ${role_session_request_type}\\n\
merged_role_chained_profile for index ${profile_idx}: ${merged_role_chained_profile[$profile_idx]}\\n\
source_profile_mfa_session_status: ${merged_session_status[${merged_session_idx[${merged_role_source_profile_idx[$profile_idx]}]}]}${Color_Off}\\n\\n"

		fi

		# AUTH OPTIONS
		declare -a role_auth_options

		if  [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] ||
			[[ "${merged_mfa_arn[$profile_idx]}" != "" ]]; then

			# source vMFAd one-off auth
			role_auth_options[${#role_auth_options[@]}]="adhoc-mfa"
		fi

		if [[ "$quick_mode" == "true" ]]; then

			if [[ "$source_profile_has_session" == "true" ]] &&
				[[ "$source_profile_mfa_session_status" == "valid" ]]; then

				# existing MFA session
				role_auth_options[${#role_auth_options[@]}]="exist-mfa"
			else
				# start a new MFA session
				role_auth_options[${#role_auth_options[@]}]="start-mfa"
			fi

			if [[ "${merged_role_mfa_required[$profile_idx]}" != "true" ]]; then
				# source creds as-is
				role_auth_options[${#role_auth_options[@]}]="source-creds"
			fi

		else  # quick mode off

			if [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]]; then

				if [[ "$source_profile_has_session" == "true" ]] &&
					[[ "$source_profile_mfa_session_status" == "valid" ]]; then

					# existing MFA session
					role_auth_options[${#role_auth_options[@]}]="exist-mfa"
				else
					# start a new MFA session
					role_auth_options[${#role_auth_options[@]}]="start-mfa"
				fi

			else
				# source creds as-is
				role_auth_options[${#role_auth_options[@]}]="source-creds"
			fi
		fi

		# do not create menu for chained roles since they
		# can only authenticate with the upstream role session
		if [[ "$role_session_request_type" == "standard" ]]; then

			# ROLE AUTH INSTRUCTION
			if [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&
				[[ "$source_profile_has_session" == "true" ]] &&
				[[ "$source_profile_mfa_session_status" == "valid" ]] &&
				[[ "$role_session_request_type" == "standard" ]]; then

				printf "\\n${BIWhite}${On_Black}\
The role session requires MFA authentication and the role's source profile\\n\
has an active MFA session. Your choices:${Color_Off}\\n"

			elif [[ "${merged_role_mfa_required[$profile_idx]}" == "true" ]] &&
				[[ "$role_session_request_type" == "standard" ]] &&
				[[ "$source_profile_has_session" == "false" ||
				   "$source_profile_mfa_session_status" != "valid" ]]; then

				printf "\\n${BIWhite}${On_Black}\
The role session requires MFA authentication and the role's source profile\\n\
doesn't have an active MFA session. Your choices:${Color_Off}\\n"

			elif [[ "${merged_role_mfa_required[$profile_idx]}" == "false" ]] &&
				[[ "$quick_mode" == "true" ]] &&
				[[ "$role_session_request_type" == "standard" ]]; then

				printf "\\n${BIWhite}${On_Black}\
The role session may not require MFA authentication (unconfirmed because\\n\
the quick mode is in effect). Your choices:${Color_Off}\\n"

			elif [[ "${merged_role_mfa_required[$profile_idx]}" == "false" ]] &&
				[[ "$quick_mode" == "false" ]] &&
				[[ "$role_session_request_type" == "standard" ]]; then

				printf "\\n${BIWhite}${On_Black}\
The role session does not require MFA authentication. Your choices:${Color_Off}\\n"

			fi

			printf "\\n"

			# session length/truncation indicator
			session_limited=""
			session_unlimited=""
			if [[ "${merged_sessmax[$profile_idx]}" != "" ]] &&
				[[ "${merged_sessmax[$profile_idx]}" -gt 3600 ]]; then

				getPrintableTimeRemaining maximum_session_length "${merged_sessmax[$profile_idx]}"

				session_limited="\\n     Session length truncated to 1 hour."
				session_unlimited="\\n     Session length not truncated (${maximum_session_length})."
			fi

			# ROLE AUTH MENU
			declare -a role_auth_index
			role_auth_display="0"
			for ((auth_itr=0; auth_itr<${#role_auth_options[@]}; ++auth_itr))
			do
				# increment the display value
				(( role_auth_display++ ))

				# save the selection in the lookup index
				role_auth_index[${#role_auth_index[@]}]="${role_auth_options[$auth_itr]}"

				printf " ${BIWhite}$role_auth_display - "

				if [[ "${role_auth_options[$auth_itr]}" == "adhoc-mfa" ]]; then

					printf "\
Use the source profile's virtual MFA device for an one-off authentication${Color_Off}${session_unlimited}\\n\\n"

				elif [[ "${role_auth_options[$auth_itr]}" == "exist-mfa" ]]; then

					printf "\
Use the source profile's existing MFA session to authenticate${Color_Off}${session_limited}\\n\\n"

				elif [[ "${role_auth_options[$auth_itr]}" == "start-mfa" ]]; then

					printf "\
Start a new persistent MFA session for the source profile;${Color_Off}\\n\
     It will be used automatically to authenticate for this role session.${session_limited}\\n\\n"

				elif [[ "${role_auth_options[$auth_itr]}" == "source-creds" ]]; then

					printf "\
Use the source profile's credentials without an MFA session${Color_Off}${session_unlimited}\\n\\n"

				fi

			done

			for ((auth_itr=0; auth_itr<${#merged_ident[@]}; ++auth_itr))
			do
				if [[ "${merged_ident[$auth_itr]}" =~ -rolesession$ ]] &&
					[[ "${merged_session_status[$auth_itr]}" == "valid" ]] &&
					[[ "${merged_ident[$auth_itr]}" != "${merged_ident[$profile_idx]}-rolesession" ]]; then  # do not display self

					# save the selection in the lookup index
					role_auth_index[${#role_auth_index[@]}]="ROLESESSION--${merged_ident[$auth_itr]}"

					# increment the display value
					(( role_auth_display++ ))

					printf " ${BIWhite}$role_auth_display - \
Authenticate with a chained role session: '${merged_ident[$auth_itr]}'${Color_Off}\\n\
     You can use this only if the above role is authorized to assume the new role.${session_limited}\\n\\n"
				fi
			done

			printf "${BIWhite}${On_Black}ROLE AUTH CHOICE: "
			read -r sel_role_auth
			printf "${Color_Off}"

			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** selection received: ${sel_role_auth}${Color_Off}\\n"

		fi  # closes [[ "$role_session_request_type" == "standard" ]]


	# PROCESS THE SELECTION -------------------------------------------------------------------------------------------

		if [[ "$role_session_request_type" == "standard" ]]; then

			# check for a valid selection pattern
			if [[ "$sel_role_auth" =~ ^[[:digit:]]+$ ]] &&
				[[ "$sel_role_auth" -gt 0 ]] &&
				[[ "$sel_role_auth" -le $role_auth_display ]]; then

				(( sel_role_auth-- ))

				role_auth_sel="${role_auth_index[$sel_role_auth]}"
			else

				# empty selection -> exit
				printf "${BIRed}${On_Black}You didn't select any authentication option.${Color_Off}\\n\\n"
				exit 1
			fi
		else
			# use the existing chained role session to authenticate
			role_auth_sel="exist-mfa"
		fi

		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}   role_auth_sel: ${role_auth_sel}${Color_Off}\\n"

		if [[ "${role_auth_sel}" == "adhoc-mfa" ]]; then
			# source vMFAd one-off auth

			printf "\\n\\n${BIWhite}${On_Black}\
Enter the current MFA one time pass code for the profile '${merged_role_source_profile_ident[$profile_idx]}'${Color_Off}\\n\
for a one-off authentication for a role session initialization.\\n\\n"

			getMfaToken mfa_token "role"
			getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role"

			if [[ "$mfa_token" != "" ]]; then

				token_switch=" --token-code ${mfa_token} "

				# if the source profile's MFA serial hasn't been
				# imported to the role, use the source profile entry
				if [[ "${merged_mfa_arn[$profile_idx]}" != "" ]]; then
					serial_switch=" --serial-number ${merged_mfa_arn[$profile_idx]} "
				elif [[ "${merged_mfa_arn[${merged_source_profile_idx[$profile_idx]}]}" != "" ]]; then
					serial_switch=" --serial-number ${merged_mfa_arn[${merged_source_profile_idx[$profile_idx]}]} "
				fi

				role_init_profile="${merged_role_source_profile_ident[$profile_idx]}"
			else
				printf "\\n${BIRed}${On_Black}An MFA token was not received. Cannot continue.${Color_Off}\\n\\n\\n"
				exit 1
			fi

		elif [[ "${role_auth_sel}" == "exist-mfa" ]]; then
			# existing MFA session

			if [[ "$role_session_request_type" == "standard" ]]; then

				selected_auth_session_ident="${merged_role_source_profile_ident[$profile_idx]}-mfasession"
			else  # this is a chained role, so use a role session instead

				selected_auth_session_ident="${merged_role_source_profile_ident[$profile_idx]}-rolesession"
			fi

			idxLookup selected_auth_session_idx merged_ident[@] "$selected_auth_session_ident"

			getRemaining jit_remaining_time "${merged_aws_session_expiry[$selected_auth_session_idx]}" "jit"
			if [[ "$jit_remaining_time" -lt 10 ]]; then
				printf "\\n${BIRed}${On_Black}The selected auth session expired while waiting. Cannot continue. Please try again.\\n${Color_Off}\\n"
				exit 1
			fi

			role_init_profile="${selected_auth_session_ident}"

			# get truncated session duration
			getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role" "true"

		elif [[ "${role_auth_sel}" == "start-mfa" ]]; then
			# start a new MFA session

			# this is recursive; the third param requests silent auto persist
			acquireSession mfa_session_detail "${merged_role_source_profile_ident[$profile_idx]}" "true"

			# the aquireSession with "true" as the third param auto-persists the new
			# session so that it can be used here simply by referring to the ident
			role_init_profile="${merged_role_source_profile_ident[$profile_idx]}-mfasession"

			# get truncated session duration
			getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role" "true"

		elif [[ "${role_auth_sel}" == "source-creds" ]]; then
			# source creds as-is

			role_init_profile="${merged_role_source_profile_ident[$profile_idx]}"
			getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role"

		elif [[ "${role_auth_sel}" =~ ^ROLESESSION--(.*)$ ]]; then
			# chained role session

			chained_role_ident="${BASH_REMATCH[1]}"
			idxLookup selected_auth_session_idx merged_ident[@] "$chained_role_ident"

			getRemaining jit_remaining_time "${merged_aws_session_expiry[$selected_auth_session_idx]}" "jit"
			if [[ "$jit_remaining_time" -lt 10 ]]; then
				printf "\\n${BIRed}${On_Black}The selected auth session expired while waiting. Cannot continue. Please try again.\\n${Color_Off}\\n"
				exit 1
			fi

			role_init_profile="${chained_role_ident}"
			getMaxSessionDuration session_duration "${merged_ident[$profile_idx]}" "role" "true"
		fi

		# generate '--external-id' switch if an exeternal ID has been defined in config
		if [[ "${merged_role_external_id[$profile_idx]}" != "" ]]; then
			external_id_switch="--external-id ${merged_role_external_id[$profile_idx]}"
		else
			external_id_switch=""
		fi

		acquireSession_result="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "$role_init_profile" sts assume-role \
			$serial_switch $token_switch $external_id_switch \
			--role-arn "${merged_role_arn[$profile_idx]}" \
			--role-session-name "${merged_role_session_name[$profile_idx]}" \
			--duration-seconds "$session_duration" \
			--output "$output_type" 2>&1)"

		if [[ "$DEBUG" == "true" ]]; then
			printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"$role_init_profile\" sts assume-role $serial_switch $token_switch $external_id_switch --role-arn \"${merged_role_arn[$profile_idx]}\" --role-session-name \"${merged_role_session_name[$profile_idx]}\" --duration-seconds \"$session_duration\" --output \"$output_type\"':\\n${ICyan}${acquireSession_result}${Color_Off}\\n"
		fi

		# exits on error
		checkAWSErrors _is_error "true" "$acquireSession_result" "$role_init_profile" "An error occurred while attempting to acquire the role session credentials; cannot continue!"

		# determines whether to print session details
		session_profile="true"

	else  # NO SESSION INIT (should never happen; the session request type is "unknown", "mfasession", or "rolesession")

		printf "\\n${BIRed}${On_Black}\
A $session_request_type cannot request a session (program error).\\n\
Cannot continue.${Color_Off}\\n"

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
			result="$(printf "$result" | xargs echo -n)"

			if [[ "$session_request_type" =~ ^(baseprofile|root)$ ]]; then

				result_check="$(printf '%s' "$acquireSession_result" | awk '{ print $2 }')"
			else  # this is a role

				result_check="$(printf '%s' "$acquireSession_result" | sed -n 2p | awk '{ print $2 }')"
			fi
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

				if [[ "$session_request_type" =~ ^(baseprofile|root)$ ]]; then

					read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SESSION_EXPIRY <<< $(printf '%s' "$acquireSession_result" | awk '{ print $2, $4, $5, $3 }')
				else
					# role session has a "title" line, so drop it to get to the credentials
					read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SESSION_EXPIRY <<< $(printf '%s' "$acquireSession_result" | sed -n 2p | awk '{ print $2, $4, $5, $3 }')
				fi
			fi

			if [[ "$session_request_type" =~ ^(baseprofile|root)$ ]]; then

				printf "\\n${Green}${On_Black}MFA session token acquired.${Color_Off}\\n\\n"
				# setting globals (depends on the use-case which one will be exported)
				AWS_DEFAULT_PROFILE="${merged_ident[$profile_idx]}-mfasession"
				AWS_PROFILE="$AWS_DEFAULT_PROFILE"
				AWS_SESSION_IDENT="$AWS_DEFAULT_PROFILE"

				AWS_SESSION_TYPE="mfasession"

			elif [[ "$session_request_type" == "role" ]]; then

				printf "\\n${Green}${On_Black}Role session token acquired.${Color_Off}\\n\\n"
				# setting globals (depends on the use-case which one will be exported)
				AWS_DEFAULT_PROFILE="${merged_ident[$profile_idx]}-rolesession"
				AWS_PROFILE="$AWS_DEFAULT_PROFILE"
				AWS_SESSION_IDENT="$AWS_DEFAULT_PROFILE"

				AWS_SESSION_TYPE="rolesession"
			fi

			AWS_SESSION_PARENT_IDX="${profile_idx}"

			if [[ "$auto_persist_request" == "true" ]]; then
				# auto-persist request for the MFA session initialized for the role session init
				printf "${Green}${On_Black}Requesting session persist.${Color_Off}\\n\\n"
				persistSessionMaybe "${merged_ident[$profile_idx]}" "$AWS_SESSION_IDENT" "$acquireSession_result" "true"
			else
				# only set AWS_*SESSION_INITIALIZED for the user-requested sessions
				# (i.e. do not set it for the persisted MFA session needed for the
				# role session init)

				if [[ "$AWS_SESSION_TYPE" == "mfasession" ]]; then
					AWS_MFASESSION_INITIALIZED="true"

					if [[ "${merged_type[$profile_idx]}" != "root" ]]; then
						printf "${Green}${On_Black}MFA session started.${Color_Off}\\n\\n"
					else
						printf "${BIGreen}${On_Black}ROOT USER${Green} MFA session started.${Color_Off}\\n\\n"
					fi

					if [[ "${merged_type[$profile_idx]}" == "root" ]] &&

						[[ ( "${merged_sessmax[$profile_idx]}" != "" &&
						     "${merged_sessmax[$profile_idx]}" -gt 3600 ) ||

						   ( "${merged_sessmax[$profile_idx]}" == "" &&
						   	 "$MFA_SESSION_LENGTH_IN_SECONDS" -gt 3600 ) ]]; then

						printf "${BIYellow}${On_Black}\
NOTE: This is a root account MFA session; the session length
      has been truncated to the AWS maximum of 3600 seconds (1h).${Color_Off}\\n\\n"
					fi
				else
					AWS_ROLESESSION_INITIALIZED="true"
					printf "${Green}${On_Black}Role session started.${Color_Off}\\n\\n"
				fi
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
				printf "\\n"
				printf "${BIYellow}${On_Black}AWS_PROFILE: ${Yellow}${On_Black}${AWS_PROFILE}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_DEFAULT_PROFILE: ${Yellow}${On_Black}${AWS_DEFAULT_PROFILE}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SESSION_IDENT: ${Yellow}${On_Black}${AWS_SESSION_IDENT}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_ACCESS_KEY_ID: ${Yellow}${On_Black}${AWS_ACCESS_KEY_ID}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SECRET_ACCESS_KEY: ${Yellow}${On_Black}${AWS_SECRET_ACCESS_KEY}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SESSION_TOKEN: ${Yellow}${On_Black}${AWS_SESSION_TOKEN}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SESSION_EXPIRY: ${Yellow}${On_Black}${AWS_SESSION_EXPIRY} (in ${AWS_SESSION_EXPIRY_PR} from now)${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SESSION_TYPE: ${Yellow}${On_Black}${AWS_SESSION_TYPE}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}AWS_SESSION_PARENT_IDX: ${Yellow}${On_Black}${AWS_SESSION_PARENT_IDX}${Color_Off}\\n"
				printf "${BIYellow}${On_Black}auto_persist_request: ${Yellow}${On_Black}${auto_persist_request}${Color_Off}\\n"
				printf "\\n"
			fi
			## END DEBUG

			eval "$1=\"${acquireSession_result}\""

		else  # the session token was not received

			if [[ "$session_request_type" =~ ^(baseprofile|root)$ ]]; then

				session_word="An MFA"

			elif [[ "$session_request_type" == "role" ]]; then

				session_word="A role"
			fi

			printf "${BIRed}${On_Black}\
$session_word session could not be initialized for the profile '${merged_ident[$profile_idx]}'.\\n\
Cannot continue.${Color_Off}\\n\\n\\n"

			exit 1
		fi
	fi  # close [[ "${session_profile}" == "true" ]]
}  # close aquireSession()

# sets the output and the region for the given
# session ident (global transits are used)
setSessionOutputAndRegion() {
	# $1 is the session profile to act on
	# $2 (bool) persist output and region for the profile;
	#    "false" (or undef) only sets the globals in this script

	# If the region and output format have not been set for this profile, set them.
	# For the parent/baseprofiles, use the defaults; for the MFA/session profiles
	# first use the base/parent settings if present, then the defaults if base/parent
	# doesn't have them. If nothing exits, use 'json' for output; region can't be set.

	local output_region_profile_ident="$1"
	local persist="$2"
	[[ "${persist}" == "" ]] && persist="false"

	local add_region_prop="false"
	local add_output_prop="false"
	local profile_idx

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function setSessionOutputAndRegion] ident to set output/region for: $1, persist: $2${Color_Off}\\n"

	idxLookup profile_idx merged_ident[@] "$output_region_profile_ident"

	if [[ "${profile_idx}" != "" ]]; then
		# session previously persisted (an older session with the same name)

		if [[ "${merged_region[$profile_idx]}" != "" ]]; then
			# a persisted region exists for the session
			# profile of the same name, so we'll use it
			AWS_DEFAULT_REGION="${merged_region[$profile_idx]}"

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}  AWS_DEFAULT_REGION set to $AWS_DEFAULT_REGION${Color_Off}\\n"

		else
			# a persisted profile exists,
			# but the region wasn't part of it
			add_region_prop="true"
		fi

		if [[ "${merged_output[$profile_idx]}" != "" ]]; then
			# a persisted output exists for the session
			# profile of the same name, so we'll use it
			AWS_DEFAULT_OUTPUT="${merged_output[$profile_idx]}"

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}  AWS_DEFAULT_OUTPUT set to $AWS_DEFAULT_OUTPUT${Color_Off}\\n"

		else
			# a persisted profile exists,
			# but the output wasn't part of it
			add_output_prop="true"
		fi

	else
		# not previously persisted, so add if so requested
		# (at this point we know a stub exists)
		add_region_prop="true"
		add_output_prop="true"
	fi

	if [[ "${merged_ident[$profile_idx]}" =~ (-mfasession|-rolesession)$ ]] ||
		[[ "$AWS_MFASESSION_INITIALIZED" == "true" ]] ||
		[[ "$AWS_ROLESESSION_INITIALIZED" == "true" ]]; then
		session_word="session "
	else
		session_word=""
	fi

	# REGION
	if [[ "$add_region_prop" == "true" ]]; then

		# if this is a session, does the source have a region?
		if [[ "${output_region_profile_ident}" =~ (-mfasession|-rolesession)$ ]] &&
			[[ "${merged_region[$AWS_SESSION_PARENT_IDX]}" != "" ]]; then

			# it's available so we'll use it!
			AWS_DEFAULT_REGION="${merged_region[$AWS_SESSION_PARENT_IDX]}"

				printf "\\n\
NOTE: The region had not been defined for the selected session profile;
      it has been set to same as the parent profile (${merged_region[$AWS_SESSION_PARENT_IDX]}).\\n"

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}  Using source's region: $AWS_DEFAULT_REGION${Color_Off}\\n"

		elif [[ "$valid_default_exists" == "true" ]] &&
			[[ "${default_region}" != "" ]]; then  # source has no region.. maybe the default is available?

			# we're in luck, the default is defined, so we'll use it!
			AWS_DEFAULT_REGION="${default_region}"

				printf "\\n\
NOTE: The region had not been defined for the selected ${session_word}profile;\\n\
      it has been set to same as the default region (${default_region}).\\n"

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}  Using default region: $AWS_DEFAULT_REGION${Color_Off}\\n"

		else
			# region is not available for this profile; warn
			AWS_DEFAULT_REGION="unavailable"

			printf "\\n${BIRed}${On_Black}\
NOTE: The region had not been configured for the selected ${session_word}profile\\n\
      and the defaults are not available (the baseprofiles:\\n\
      the default region; the MFA/role sessions: the region of\\n\
      the parent profile, then the default region).\\n\
\\n\
      Please note that while the session is started, you'll\\n\
      have to define the region with a command line parameter\\n\
      '--region' for many aws commands unless you set the region\\n\
      for the profile (or for the parent profile in case of the\\n\
      MFA/role sessions), or set the default region.\\n\
\\n\
	  To configure the region for this profile, you can set it with:\\n\
	  ${BIWhite}${On_Black}aws --profile \"${merged_ident[$profile_idx]}\" configure set region \"us-east-1\"${Color_Off}\\n\
	  (adjust the chosen AWS region if different from 'us-east-1').\\n\\n"

			[[ "$DEBUG" == "true" ]] && printf "n${Yellow}${On_Black}  NO REGION AVAILABLE!${Color_Off}\\n"
		fi
	fi

	# OUTPUT
	if [[ "$add_output_prop" == "true" ]]; then

		# if this is a session, does the source have a region?
		if [[ "${output_region_profile_ident}" =~ (-mfasession|-rolesession)$ ]] &&
			[[ "${merged_output[$AWS_SESSION_PARENT_IDX]}" != "" ]]; then

			# it's available so we'll use it!
			AWS_DEFAULT_OUTPUT="${merged_output[$AWS_SESSION_PARENT_IDX]}"

			printf "\\n\
NOTE: The output format had not been defined for the selected session profile;
      it has been set to same as the parent profile (${merged_output[$AWS_SESSION_PARENT_IDX]}).\\n"

			[[ "$DEBUG" == "true" ]] && printf "n${Yellow}${On_Black}  Using source's output: $AWS_DEFAULT_OUTPUT${Color_Off}\\n"

		elif [[ "$valid_default_exists" == "true" ]] &&
			[[ "${default_output}" != "" ]]; then  # source has no output.. maybe the default is available?

			# we're in luck, the default is defined, so we'll use it!
			AWS_DEFAULT_OUTPUT="${default_output}"

			printf "\\n\
NOTE: The output format had not been defined for the selected ${session_word}profile;\\n\
      it has been set to same as the default region (${default_output}).\\n"

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}  Using default output: $AWS_DEFAULT_OUTPUT${Color_Off}\\n"

		else
			# output is not available for this profile; use the AWS default (json)
			AWS_DEFAULT_OUTPUT="json"

			printf "\\n\
NOTE: The output format had not been defined for the selected ${session_word}profile.\\n\
      Neither the default nor the source profile made it available so\\n\
      the output format has been set to the AWS default ('json').\\n"

			[[ "$DEBUG" == "true" ]] && printf "n${Yellow}${On_Black}  NO OUTPUT DEFINED -- USING THE AWS DEFAULT ('json')!${Color_Off}\\n"
		fi
	fi

	# persist if requested
	if [[ "$persist" == "true" ]]; then

		if [[ "$add_region_prop" == "true" ]] &&
			[[ "$AWS_DEFAULT_REGION" != "unavailable" ]]; then

			(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${output_region_profile_ident}" configure set region "$AWS_DEFAULT_REGION")
		fi

		if [[ "$add_region_prop" == "true" ]]; then

			(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${output_region_profile_ident}" configure set output "$AWS_DEFAULT_OUTPUT")
		fi
	fi
}

# JIT check for the availability of a vMFAd Arn when a valid
# profile is selected in quick mode; this is significant when
# a vMFAd has been initialized for a profile after the last
# non-quick run, and the script is executed in quick mode
# again (hence the profile has no record of the vMFAd Arn)
refreshProfileMfaArn() {
	# $1 refreshProfileMfaArn_result
	# $2 is the idx

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function refreshProfileMfaArn] index: $1${Color_Off}\\n"

	local refreshProfileMfaArn_result="unavailable"
	local this_idx="$2"

	local get_this_mfa_arn

	if [[ "${merged_username[$this_idx]}" == "" ]]; then

		# get the user ARN; this should be always
		# available for valid profiles
		getProfileArn _ret "${merged_ident[$this_idx]}"

		if [[ "${_ret}" =~ ^arn:aws: ]]; then

			merged_baseprofile_arn[$this_idx]="${_ret}"

			if [[ "${_ret}" =~ [[:digit:]]+:user.*/([^/]+)$ ]]; then

				merged_username[$this_idx]="${BASH_REMATCH[1]}"
			fi
		else
			# flag the profile as invalid (for quick mode intelligence)
			toggleInvalidProfile "set" "${merged_ident[$this_idx]}"
		fi
	fi

	if [[ "${merged_username[$this_idx]}" != "" ]]; then
		# get the vMFA device Arn if one is now available (obviously one wasn't
		# previously available when the script was last executed without 'quick')
		get_this_mfa_arn="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$this_idx]}" iam list-mfa-devices \
			--user-name "${merged_username[$this_idx]}" \
			--output text \
			--query 'MFADevices[].SerialNumber' 2>&1)"

			[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"${merged_ident[$this_idx]}\" iam list-mfa-devices --user-name \"${merged_username[$this_idx]}\" --query 'MFADevices[].SerialNumber' --output text':\\n${ICyan}${get_this_mfa_arn}${Color_Off}\\n"

		if [[ "$get_this_mfa_arn" =~ ^arn:aws: ]]; then

			# we know it's not in config at the moment,
			# so persist the MFA Arn..
			writeProfileMfaArn "${merged_ident[$this_idx]}" "$get_this_mfa_arn"

			# ..and update in this script state
			# (it was blank previously)
			merged_mfa_arn[$this_idx]="$get_this_mfa_arn"

			refreshProfileMfaArn_result="available"
		fi
	fi

	eval "$1=\"$refreshProfileMfaArn_result\""
}

# walks up the role chain to get
# the original baseprofile ident
getRoleChainBaseProfileIdent() {
	# $1 is getRoleChainBaseProfileIdent_result
	# $2 is the role ident for which the baseprofile is being looked up

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}[function getRoleChainBaseProfileIdent] ident: $2${Color_Off}\\n"

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

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  ::: output: ${getRoleChainBaseProfileIdent_result}${Color_Off}\\n"

	eval "$1=\"$getRoleChainBaseProfileIdent_result\""
}

## END FUNCTIONS ======================================================================================================

## MAIN ROUTINE START =================================================================================================
## PREREQUISITES CHECK

if [[ "$quick_mode" == "false" ]]; then
	available_script_version="$(getLatestRelease 'vwal/awscli-mfa')"

	versionCompare "$script_version" "$available_script_version"
	version_result="$?"

	if [[ "$version_result" -eq 2 ]]; then
		printf "${BIYellow}${On_Black}A more recent release of this script is available on GitHub.${Color_Off}\\n\\n"
	fi
fi

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
		printf "\\nNOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM.\\n\\n"
	fi
else
	OS="unknown"
	has_brew="false"
fi

[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** OS: '${OS}', has_brew: '${has_brew}'${Color_Off}\\n"

coreutils_status="unknown"
if  [[ "$OS" =~ Linux$ ]]; then

	if exists apt ; then
		install_command="apt"

		# do not run in WSL_Linux
		if [[ "$OS" == "Linux" ]]; then
			coreutils_status="$(dpkg-query -s coreutils 2>/dev/null | grep Status | grep -o installed)"
		fi

	elif exists yum ; then
		install_command="yum"

		# do not run in WSL_Linux
		if [[ "$OS" == "Linux" ]] &&
			exists rpm; then

			coreutils_status="$(rpm -qa | grep -i ^coreutils | head -n 1)"
		fi
	else
		install_command="unknown"
	fi

	# blank status == not installed; "unknown" == untested
	if [[ "${coreutils_status}" == "" ]]; then

		printf "\\n${BIRed}${On_Black}'coreutils' is required on Linux. Cannot continue.${Color_Off}\\nPlease install with your operating system's package manager, then try again.\\n\\n\\n"

		if [[ "${install_command}" == "apt" ]]; then

			printf "Install with:\\nsudo apt update && sudo apt -y install coreutils\\n\\n"

		elif [[ "${install_command}" == "yum" ]]; then

			printf "Install with:\\nsudo yum install -y coreutils\\n\\n"
		fi

		exit 1
	fi

elif [[ "$OS" == "macOS" ]] &&
	[[ "$has_brew" == "true" ]]; then

	install_command="brew"
else
	install_command="unknown"
fi

[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** install_command: '${install_command}'${Color_Off}\\n"

# is AWS CLI installed?
if ! exists aws ; then

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** NO awscli!${Color_Off}\\n"

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
[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** awscli detected!${Color_Off}\\n"

filexit="false"
confdir="true"
# check for ~/.aws directory
# if the custom config defs aren't in effect
if [[ "$AWS_CONFIG_FILE" == "" ||
	  "$AWS_SHARED_CREDENTIALS_FILE" == "" ]] &&
	[[ ! -d "$HOME/.aws" ]]; then

	printf "\\n${BIRed}${On_Black}\
AWSCLI configuration directory '$HOME/.aws' is not present.${Color_Off}\\n\
Make sure it exists, and that you have at least one profile configured\\n\
using the 'config' and/or 'credentials' files within that directory.\\n\\n"
	filexit="true"
	confdir="false"
fi

# SUPPORT CUSTOM CONFIG FILE SET WITH ENVVAR
if [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ -f "$AWS_CONFIG_FILE" ]]; then

	absolute_AWS_CONFIG_FILE="$(realpath "$AWS_CONFIG_FILE")"

	active_config_file="$absolute_AWS_CONFIG_FILE"
	printf "${BIYellow}${On_Black}\
NOTE: A custom configuration file defined with AWS_CONFIG_FILE\\n\
      envvar in effect: '$absolute_AWS_CONFIG_FILE'${Color_Off}\\n\\n"

elif [[ "$AWS_CONFIG_FILE" != "" ]] &&
	[[ ! -f "$absolute_AWS_CONFIG_FILE" ]]; then

	printf "${BIRed}${On_Black}\
The custom AWSCLI configuration file defined with AWS_CONFIG_FILE envvar,\\n\
'$AWS_CONFIG_FILE', was not found.${Color_Off}\\n\
Make sure it is present or purge the AWS envvars with:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up.\\n\\n"
	filexit="true"

elif [[ -f "$CONFFILE" ]]; then

	active_config_file="$CONFFILE"

else
	printf "${BIRed}${On_Black}\
The AWSCLI configuration file '$CONFFILE' was not found.${Color_Off}\\n\
Make sure it and '$CREDFILE' files exist (at least one\\n\
configured baseprofile is requred for this script to be operational).\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up.\\n"
	filexit="true"
fi

# SUPPORT CUSTOM CREDENTIALS FILE SET WITH ENVVAR
if [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[[ -f "$AWS_SHARED_CREDENTIALS_FILE" ]]; then

	absolute_AWS_SHARED_CREDENTIALS_FILE="$(realpath "$AWS_SHARED_CREDENTIALS_FILE")"

	active_credentials_file="$absolute_AWS_SHARED_CREDENTIALS_FILE"
	printf "${BIYellow}${On_Black}\
NOTE: A custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE\\n\
      envvar in effect: '$absolute_AWS_SHARED_CREDENTIALS_FILE'${Color_Off}\\n\\n"

elif [[ "$AWS_SHARED_CREDENTIALS_FILE" != "" ]] &&
	[[ ! -f "$absolute_AWS_SHARED_CREDENTIALS_FILE" ]]; then

	printf "${BIRed}${On_Black}\
The custom credentials file defined with AWS_SHARED_CREDENTIALS_FILE envvar,\\n\
'$AWS_SHARED_CREDENTIALS_FILE', is not present.${Color_Off}\\n\
Make sure it is present or purge the AWS envvars with:\\n\
${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh${Color_Off}\\n\
See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
for the details on how to set them up.\\n"
	filexit="true"

elif [[ -f "$CREDFILE" ]]; then

	active_credentials_file="$CREDFILE"

elif [[ "$confdir" == "true" ]]; then
	# assume any existing creds are in $CONFFILE;
	# create a shared credentials file stub for session creds
    touch "$CREDFILE"
    chmod 600 "$CREDFILE"

	active_credentials_file="$CREDFILE"

	printf "\\n${BIWhite}${On_Black}\
NOTE: A shared credentials file ('~/.aws/credentials') was not found;\\n\
      assuming existing credentials are in the config file ('$CONFFILE').${Color_Off}\\n\\n\
NOTE: A blank shared credentials file ('~/.aws/credentials') was created\\n\
      as the session credentials will be stored in it.\\n"
else
	filexit="true"
fi

if [[ "$filexit" == "true" ]]; then

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Necessary config files not present; exiting!${Color_Off}\\n"
	printf "\\n"
	exit 1
fi

CONFFILE="$active_config_file"
CREDFILE="$active_credentials_file"

# make sure the selected CONFFILE has a linefeed in the end
LF_maybe="$(tail -c 1 "$CONFFILE")"

if [[ "$LF_maybe" != "" ]]; then

	printf "\\n" >> "$CONFFILE"
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Adding linefeed to '${CONFFILE}'${Color_Off}\\n"
fi

# make sure the selected CREDFILE has a linefeed in the end
LF_maybe="$(tail -c 1 "$CREDFILE")"

if [[ "$LF_maybe" != "" ]]; then

	printf "\\n" >> "$CREDFILE"
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Adding linefeed to '${CONFFILE}'${Color_Off}\\n"
fi

# read the credentials and/or config files,
# and make sure that at least one profile is configured
ONEPROFILE="false"

conffile_props_in_credfile="false"
profile_header_check="false"
access_key_id_check="false"
secret_access_key_check="false"
creds_unsupported_props=""
profile_count="0"
session_profile_count="0"

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
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Starting credfile check ('${CREDFILE}')${Color_Off}\\n"

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
			[[ "$line" =~ ^(mfa_arn).* ]] ||
			[[ "$line" =~ ^(output).* ]] ||
			[[ "$line" =~ ^(sessmax).* ]] ||
			[[ "$line" =~ ^(mfa_req).* ]] ||
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

# check the last iteration
exitOnArrDupes dupes[@] "${profile_ident_hold}" "props"

# check for duplicate profile labels and exit if any are found
exitOnArrDupes labels_for_dupes[@] "$CREDFILE" "credfile"
unset labels_for_dupes

if [[ "$prespace_check" == "true" ]]; then

	printf "\\n${BIRed}${On_Black}\
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
  aws_access_key_id=AKIA...  <- no spaces on the property lines!\\n\\n"

      exit 1
fi

if [[ "$illegal_profilelabel_check" == "true" ]]; then

	printf "\\n${BIRed}${On_Black}\
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
aws_access_key_id=AKIA...\\n\\n"

      exit 1
fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	# only one profile is present
	ONEPROFILE="true"
fi

if [[ "$conffile_props_in_credfile" == "true" ]]; then

	printf "\\n${BIWhite}${On_Black}\
NOTE: The credentials file ('$CREDFILE') contains the following properties\\n\
      only supported in the config file ('$CONFFILE'):\\n\\n\
${creds_unsupported_props}${Color_Off}\\n\
      The credentials file may only contain credentials and session expiration timestamps;\\n\
      please see https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
      and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\
      for the details on how to correctly set up the config and shared credentials files.\\n"
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

[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Checking for invalid labels in '${CONFFILE}'${Color_Off}\\n"
profile_ident_hold=""
declare -a labels_for_dupes

# makes sure dupes array is empty
# after the credfile check
unset dupes; declare -a dupes

while IFS='' read -r line || [[ -n "$line" ]]; do

	if [[ "$line" =~ $label_regex ]]; then

		profile_ident="${BASH_REMATCH[1]}"

		# save labels for label dupes check
		labels_for_dupes[${#labels_for_dupes[@]}]="${profile_ident}"

		if [[ "$line" =~ $config_labelcheck1_regex ]]; then

			illegal_defaultlabel_check="true"
		fi

		if [[ ! "$line" =~ $config_labelcheck2_negative_regex ]]; then
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

# check the last iteration
exitOnArrDupes dupes[@] "${profile_ident_hold}" "props"

# check for duplicate profile labels and exit if any are found
exitOnArrDupes labels_for_dupes[@] "$CONFFILE" "conffile"
unset labels_for_dupes

if [[ "$prespace_check" == "true" ]]; then

	printf "\\n${BIRed}${On_Black}\
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
  region=us-east-1  <- no spaces on the property lines!\\n\\n"

      exit 1
fi

if [[ "$illegal_defaultlabel_check" == "true" ]]; then

	printf "\\n${BIRed}${On_Black}\
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
aws_access_key_id = AKIA...\\n\\n"

      exit 1
fi

if [[ "$illegal_profilelabel_check" == "true" ]]; then

	printf "\\n${BIRed}${On_Black}\
NOTE: One or more of the profile labels in '$CONFFILE' are missing the 'profile' prefix.\\n\
      While it's required in the credentials file, it is not allowed in the config file.${Color_Off}\\n\
      Also note that the 'default' profile is an exception; it may NEVER have the 'profile' prefix.\\n\\n\
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
aws_access_key_id = AKIA...\\n\\n"

      exit 1
fi

if [[ "$profile_count" -eq 0 ]] &&
	[[ "$session_profile_count" -gt 0 ]]; then

	printf "\\n${BIRed}${On_Black}\
THE ONLY CONFIGURED PROFILE WITH CREDENTIALS MAY NOT BE A SESSION PROFILE.${Color_Off}\\n\\n\
Please add credentials for at least one baseprofile, and try again.\\n\\n"

	exit 1

fi

if [[ "$profile_header_check" == "true" ]] &&
	[[ "$secret_access_key_check" == "true" ]] &&
	[[ "$access_key_id_check" == "true" ]]; then

	# only one profile is present
	ONEPROFILE="true"
fi

if [[ "$ONEPROFILE" == "false" ]]; then

	printf "\\n${BIRed}${On_Black}\
NO CONFIGURED AWS PROFILES WITH CREDENTIALS FOUND.${Color_Off}\\n\
Please make sure you have at least one configured profile\\n\
that has aws_access_key_id and aws_secret_access_key set.\\n\
For more info on how to set them up, see AWS CLI configuration\\n\
documentation at the following URLs:\\n\
https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html\\n\
and https://docs.aws.amazon.com/cli/latest/topic/config-vars.html\\n\\n"

	exit 1

else

	## TEST AWS API CONNECTIVITY; EXIT IF NOT REACHABLE ---------------------------------------------------------------

	# using the defined persisted profile
	connectivity_test="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; AWS_ACCESS_KEY_ID="AKIAXXXXXXXXXXXXXXXX"; AWS_SECRET_ACCESS_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; \
		aws sts get-caller-identity \
		--output text 2>&1)"

	[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for: 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; AWS_ACCESS_KEY_ID=\"AKIAXXXXXXXXXXXXXXXX\"; AWS_SECRET_ACCESS_KEY=\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"; aws sts get-caller-identity --output text':\\n${ICyan}${connectivity_test}${Color_Off}\\n"

	if [[ "$connectivity_test" =~ Could[[:space:]]not[[:space:]]connect[[:space:]]to[[:space:]]the[[:space:]]endpoint[[:space:]]URL ]]; then
		# bail out to prevent profiles being tagged as invalid
		# due to connectivity problems (AWS API not reachable)
		printf "${BIRed}${On_Black}AWS API endpoint not reachable (connectivity problems)! Cannot continue.${Color_Off}\\n\\n"
		exit 1
	fi

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Checking for the default profile${Color_Off}\\n"

	isProfileValid _ret "default"
	if [[ "${_ret}" == "false" ]]; then

		valid_default_exists="false"
		default_region=""
		default_output=""

		printf "${BIYellow}${On_Black}\
NOTE: The default profile is not present.${Color_Off}\\n\
      As a result the default parameters (region, output format)\\n\
      are not available and you need to also either define the\\n\
      profile in the environment (such as, using this script),\\n\
      or select the profile for each awscli command using\\n\
      the '${BIWhite}${On_Black}--profile {some profile name}${Color_Off}' switch.\\n\\n"

	else

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** 'default' profile found${Color_Off}\\n"
		valid_default_exists="true"

		# get default region and output format
		default_region="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "default" configure get region 2>&1)"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"default\" configure get region':\\n${ICyan}'${default_region}'${Color_Off}\\n"

		default_output="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "default" configure get output 2>&1)"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}result for 'unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile \"default\" configure get output':\\n${ICyan}'${default_output}'${Color_Off}\\n"

	fi

	if [[ "$default_region" == "" ]]; then

		printf "${BIYellow}${On_Black}\
NOTE: The default region has not been configured.${Color_Off}\\n\
      You need to use the '--region {some AWS region}' switch\\n\
      for commands that require the region if the base/role profile\\n\
      in use doesn't have the region set. You can set the default region\\n\
      in '$CONFFILE', for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set region \"us-east-1\"${Color_Off}\\n\
      ${BIYellow}${On_Black}Do NOT use '--profile default' switch when configuring the defaults!${Color_Off}\\n\\n"

	fi

	# warn if the default output doesn't exist; set to 'json' (the AWS default)
	if [[ "$default_output" == "" ]]; then
		# default output is not set in the config;
		# set the default to the AWS default internally
		# (so that it's available for the MFA sessions)
		default_output="json"

		[[ "$DEBUG" == "true" ]] && printf "${Cyan}${On_Black}default output for this script was set to: ${ICyan}json${Color_Off}\\n\\n"
		printf "${BIYellow}${On_Black}\
NOTE: The default output format has not been configured;${Color_Off} the AWS\\n\
      default, 'json', is used. You can modify it, for example, like so:\\n\
      ${BIWhite}${On_Black}source ./source-this-to-clear-AWS-envvars.sh\\n\
      aws configure set output \"table\"${Color_Off}\\n\
      ${BIYellow}${On_Black}Do NOT use '--profile default' switch when configuring the defaults!${Color_Off}\\n\\n"

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
	profiles_init="0"
	creds_iterator="0"
	unset dupes

	# a hack to relate different values because
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	# NOTE: this pass is quick as no aws calls are done
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}ITERATING CREDFILE ---${Color_Off}\\n"
	while IFS='' read -r line || [[ -n "$line" ]]; do

		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}iterating credfile line: ${line}${Color_Off}\\n"

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

			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}creds_iterator ${creds_iterator}: ${_ret}${Color_Off}\\n"

			if [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -mfasession$ ]]; then

				creds_type[$creds_iterator]="mfasession"

			elif [[ "${_ret}" != "" ]] &&
				[[ "${_ret}" =~ -rolesession$ ]]; then

				creds_type[$creds_iterator]="rolesession"
			else
				creds_type[$creds_iterator]="baseprofile"
			fi

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}   .. ${creds_type[$creds_iterator]}${Color_Off}\\n"
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

			printf "\\n${BIRed}${On_Black}\
NOTE: The role '${this_role}' is defined in the credentials\\n\
      file ('$CREDFILE') and will be ignored.${Color_Off}\\n\\n\
      The credentials file may only contain credentials;\\n\
      you should define roles in the config file ('$CONFFILE').\\n\\n"

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
	declare -a confs_mfa_req
	declare -a confs_invalid_as_of
	declare -a confs_mfa_arn
	declare -a confs_ca_bundle
	declare -a confs_cli_timestamp_format
	declare -a confs_output
	declare -a confs_parameter_validation
	declare -a confs_region
	declare -a confs_role_arn
	declare -a confs_role_xaccn
	declare -a confs_role_credential_source
	declare -a confs_role_external_id
	declare -a confs_role_session_name
	declare -a confs_role_source_profile_ident
	declare -a confs_type
	confs_init="0"
	confs_iterator="0"
	unset dupes

	# read in the config file params
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}ITERATING CONFFILE ---${line}${Color_Off}\\n"
	while IFS='' read -r line || [[ -n "$line" ]]; do

		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}iterating conffile line: ${line}${Color_Off}\\n"

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

			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}confs_iterator ${confs_iterator}: ${_ret}${Color_Off}\\n"

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

		# mfa_arn (hard property for direct credentials; "MFA required" indicator for the roles)
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

		# role_xaccn
		if [[ "$line" =~ ^role_xaccn[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_xaccn[$confs_iterator]="${BASH_REMATCH[1]}"
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

		# role_session_name
		if [[ "$line" =~ ^role_session_name[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
			confs_role_session_name[$confs_iterator]="${BASH_REMATCH[1]}"
			confs_type[$confs_iterator]="role"
		fi

		[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}   .. ${confs_type[$confs_iterator]}${Color_Off}\\n"

	done < "$CONFFILE"

	# UNIFIED ARRAYS (config + credentials, and more)
	declare -a merged_ident  # baseprofile name, *-mfasession, or *-rolesession
	declare -a merged_type  # baseprofile, role, mfasession, rolesession, or root
	declare -a merged_aws_access_key_id
	declare -a merged_aws_secret_access_key
	declare -a merged_aws_session_token
	declare -a merged_has_in_env_session  # true/false for baseprofiles, roles, sessions: a more recent in-env session exists (i.e. expiry is further out)
	declare -a merged_has_session  # true/false (baseprofiles and roles only; not session profiles)
	declare -a merged_session_idx  # reference to the associated session profile index (baseprofile->mfasession or role->rolesession) in this array (from offline augment)
	declare -a merged_parent_idx  # idx of the parent (baseprofile or role) for mfasessions and rolesessions for easy lookup of the parent data (from offline augment)
	declare -a merged_sessmax  # optional profile-specific session length
	declare -a merged_mfa_arn  # configured vMFAd if one exists; like role's sessmax, this is written to config, and re-verified by dynamic augment (can be present in baseprofile, role profile, or root profile)
	declare -a merged_invalid_as_of  # optional marker for an invalid profile (persisted intelligence for the quick mode)
	declare -a merged_session_status  # valid/expired/unknown/invalid (session profiles only; valid/expired/unknown based on recorded time in offline, valid/unknown translated to valid/invalid in online augmentation)
	declare -a merged_aws_session_expiry  # both MFA and role session expiration timestamp
	declare -a merged_session_remaining  # remaining seconds in session; automatically calculated for mfa and role profiles
	declare -a merged_ca_bundle
	declare -a merged_cli_timestamp_format
	declare -a merged_output
	declare -a merged_parameter_validation
	declare -a merged_region  # precedence: environment, baseprofile (for mfasessions, roles [via source_profile])

	# ROLE ARRAYS
	declare -a merged_role_arn    # this must be provided by the user for a valid role config
	declare -a merged_role_xaccn  # determined by comparing the role/source_profile account#'s in the ARNs, then persisted
	declare -a merged_role_name   # this is discerned/set from the merged_role_arn
	declare -a merged_role_credential_source
	declare -a merged_role_external_id  # optional external id if defined
	declare -a merged_role_session_name
	declare -a merged_role_chained_profile  # true if source_profile is not a baseprofile
	declare -a merged_role_source_baseprofile_ident
	declare -a merged_role_source_profile_ident
	declare -a merged_role_source_profile_idx
	declare -a merged_role_source_profile_absent  # set to true when the defined source_profile doesn't exist
	declare -a merged_role_ssm_mfareq_lookup  #holds status of a possible SSM lookup for advertised mfa_req detail (used to determine persisted mfa_req for xaccn roles)

	# DYNAMIC AUGMENT ARRAYS
	declare -a merged_deferred_profile_state  # internal utility variable to defer setting the role state past x-accn role detection
	declare -a merged_baseprofile_arn  # based on get-caller-identity, this can be used as the validity indicator for the baseprofiles (combined with merged_session_status for the select_status)
	declare -a merged_baseprofile_operational_status  # ok/reqmfa/none/unknown based on 'iam get-access-key-last-used' (a 'valid' profile can be 'reqmfa' depending on policy; but shouldn't be 'none' or 'unknown' since 'sts get-caller-id' passed)
	declare -a merged_account_alias
	declare -a merged_account_id
	declare -a merged_username  # username derived from a baseprofile, or role name from a role profile
	declare -a merged_role_source_username  # username for a role's source profile, derived from the source_profile (if avl)
	declare -a merged_role_mfa_required  # LOCAL ROLES: if a role profile has a functional source_profile, this is derived via get-role with a query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"' (the result will override an existing role profile property)
										 # 				 (note: this is preliminarily set in offline augment as true/false based on whether the MFA ARN is present in the role config)
										 # XACCN ROLES: local SSM is queried for the advertised details about the role at:
										 #               /unencrypted/xaccn-roles/{ROLE_AWS_ACCN#}/role-name (this will override an existing role profile property if one is present, but absence of this will not erase an existing value)
										 #               (note: this is preliminarily set in offline augment as true/false based on whether the MFA ARN is present in the role config)

	# BEGIN CONF/CRED ARRAY MERGING PROCESS ---------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Creating merged arrays; importing config/creds file contents${Color_Off}\\n"

	for ((itr=0; itr<${#confs_ident[@]}; ++itr))
	do
		# import content from the confs_ arrays
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
		merged_role_xaccn[$itr]="${confs_role_xaccn[$itr]}"
		merged_role_credential_source[$itr]="${confs_role_credential_source[$itr]}"
		merged_role_external_id[$itr]="${confs_role_external_id[$itr]}"
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

		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}merged itr ${itr}: ${merged_ident[$itr]}${Color_Off}\\n"

	done

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Creating merged arrays; importing credentials-only contents${Color_Off}\\n"

	# merge in possible credentials-only profiles as they
	# would not have been merged by the above process
	for ((itr=0; itr<${#creds_ident[@]}; ++itr))
	do
		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}merge itr ${itr}...${Color_Off}\\n"

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
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  .. merged ${merged_ident[$merge_idx]} at merge_idx ${merge_idx}${Color_Off}\\n"
		fi
	done

	## QUICK MODE NOTICE ----------------------------------------------------------------------------------------------

	if [[ "$quick_mode" == "true" ]]; then

		printf "\\n${BIYellow}${On_Black}\
NOTE: The quick mode is in effect; dynamic information such as profile validation is not available.${Color_Off}\\n\
      The information about invalid profiles or about the vMFA\\n\
      devices is derived from your awscli configuration files.\\n\\n"

	fi

	## awscli AND jq VERSION CHECK (this needs to happen for awscli after the config file checks) ---------------------

	# check for the minimum awscli version
	# (awscli existence is already checked)
	required_minimum_awscli_version="1.16.0"
	this_awscli_version="$(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --version 2>&1 | awk '/^aws-cli\/([[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+)/{print $1}' | awk -F'/' '{print $2}')"

	if [[ "$this_awscli_version" != "" ]]; then

		versionCompare "$this_awscli_version" "$required_minimum_awscli_version"
		awscli_version_result="$?"

		if [[ "$awscli_version_result" -eq 2 ]]; then

			printf "${BIRed}${On_Black}\
Please upgrade your awscli to the latest version, then try again.${Color_Off}\\n\
Installed awscli version: $this_awscli_version\\n\
Minimum required version: $required_minimum_awscli_version\\n\\n\
To upgrade, run:\\n\
${BIWhite}${On_Black}pip3 install --upgrade awscli${Color_Off}\\n\\n"

			exit 1
		else
			printf "${Green}${On_Black}\
The current awscli version is ${this_awscli_version}${Color_Off}\\n\\n"

		fi

	else
			printf "\\n${BIYellow}${On_Black}\
Could not get the awscli version! If this script doesn't appear\\n\
to work correctly make sure the 'aws' command works!${Color_Off}\\n\\n"

	fi

	# check for jq, version
	if exists jq ; then
		required_minimum_jq_version="1.5"
		jq_version_string="$(jq --version 2>&1)"
		jq_available="false"
		jq_minimum_version_available="false"

		if [[ "$jq_version_string" =~ ^jq-.* ]]; then

			jq_available="true"

			[[ "$jq_version_string" =~ ^jq-([.0-9]+) ]] &&
				this_jq_version="${BASH_REMATCH[1]}"

			if [[ "$this_jq_version" != "" ]]; then

				versionCompare "$this_jq_version" "$required_minimum_jq_version"
				jq_version_result="$?"

				if [[ "$jq_version_result" -eq 2 ]]; then

					printf "${Red}${On_Black}Please upgrade your 'jq' to the latest version.${Color_Off}\\n\\n"
				else
					jq_minimum_version_available="true"
					printf "${Green}${On_Black}The current jq version is ${this_jq_version}${Color_Off}\\n\\n"
				fi
			else
					printf "${Yellow}${On_Black}\
Consider installing 'jq' for faster and more reliable operation.${Color_Off}\\n\\n"
			fi
		else
			printf "${Yellow}${On_Black}\
Consider installing 'jq' for faster and more reliable operation.${Color_Off}\\n\\n"
		fi
	else
		printf "${Yellow}${On_Black}\
Consider installing 'jq' for faster and more reliable operation.${Color_Off}\\n\\n"
	fi


	## BEGIN OFFLINE AUGMENTATION: PHASE I ----------------------------------------------------------------------------

	if [[ "$DEBUG" == "true" ]]; then
		printf "\
MERGED INVENTORY\\n\
----------------\\n\\n"

		for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
		do
			printf "$idx: ${merged_ident[$idx]}\\n"
		done

		printf "\\n${BIYellow}${On_Black}** Offline augmentation: PHASE I${Color_Off}\\n"
	fi

	# SESSION PROFILES offline augmentation: discern and set merged_has_session,
	# merged_session_idx, and merged_role_source_profile_idx

	for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
	do
		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}  idx: ${idx}${Color_Off}\\n"

		# get baseprofile/root acccount ID from the MFA Arn if one is present
		if [[ "${merged_type[$idx]}" =~ ^(baseprofile|root)$ ]] &&
			[[ "${merged_mfa_arn[$idx]}" != "" ]]; then

			if [[ "${merged_mfa_arn[$idx]}" =~ ([[:digit:]]+):mfa/.+$ ]]; then
				merged_account_id[$idx]="${BASH_REMATCH[1]}"
			fi
		fi

		# set has_in_env_session to 'false' (augment changes this to "true"
		# only when the in-env session is more recent than the persisted one,
		# when the full secrets are in-env and only a stub is persisted,
		# or if the persisted session is expired/invalid); only set for
		# baseprofiles and roles
		if [[ "${merged_type[$idx]}" =~ ^(baseprofile|role|root)$ ]]; then

			has_in_env_session[$idx]="false"
		fi

		if [[ "${merged_type[$idx]}" =~ ^role$ ]]; then

			# set default to 'false' for role profiles
			merged_role_source_profile_absent[$idx]="false"
		fi

		# set merged_has_in_env_session to "false" by default for all profile types
		merged_has_in_env_session[$idx]="false"

		for ((int_idx=0; int_idx<${#merged_ident[@]}; ++int_idx))  # iterate all profiles for each profile
		do
			# add merged_has_session and merged_session_idx properties to the baseprofile and role indexes
			# to make it easier to generate the selection arrays; add merged_parent_idx property to the
			# mfasession and rolesession indexes to make it easier to set has_in_env_session
			if [[ "${merged_ident[$int_idx]}" =~ ^${merged_ident[$idx]}-(mfasession|rolesession)$ ]]; then

				[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  found session for index $idx: session index $int_idx${Color_Off}\\n"
				merged_has_session[$idx]="true"
				merged_session_idx[$idx]="$int_idx"
				merged_parent_idx[$int_idx]="$idx"
			fi

			# add merged_role_source_profile_idx property to easily access a role's source_profile data
			# (this assumes that the role has source_profile set in config; dynamic augment will happen
			# later unless '--quick' is used, and this will be repeated then)
			if [[ ${merged_type[$idx]} == "role" ]] &&
				[[ "${merged_role_source_profile_ident[$idx]}" == "${merged_ident[$int_idx]}" ]]; then

				[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}  found source profile for role at index $idx (${merged_ident[$idx]}): source index $int_idx (${merged_role_source_profile_ident[$idx]})${Color_Off}\\n"
				merged_role_source_profile_idx[$idx]="$int_idx"
			fi
		done

		if [[ ${merged_type[$idx]} == "role" ]] &&
			[[ "${merged_role_source_profile_ident[$idx]}" != "" ]] &&
			[[ "${merged_role_source_profile_idx[$idx]}" == "" ]]; then

			if [[ "$DEBUG" == "true" ]]; then
				printf "\\n${Yellow}${On_Black}\
  role at index $idx (${merged_ident[$idx]}) has an invalid source profile ident: ${merged_role_source_profile_ident[$idx]}${Color_Off}\\n\
merged_role_source_profile_ident: ${merged_role_source_profile_ident[$idx]}\\n\
merged_role_source_profile_idx: ${merged_role_source_profile_idx[$idx]}\\n"
			fi

			merged_role_source_profile_absent[$idx]="true"
		fi

	done

	## BEGIN OFFLINE AUGMENTATION: PHASE II ---------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** Offline augmentation: PHASE II${Color_Off}\\n"

	# further offline augmentation: persistent profile standardization (relies on
	# merged_role_source_profile_idx assignment, above, having been completed)
	# including region, role_name, and role_session name
	#
	# also determines/sets merged_session_status
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))  # iterate all profiles
	do
		[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}     Iterating merged ident ${merged_ident[$idx]}..${Color_Off}\\n"

		if [[ "${merged_type[$idx]}" =~ ^(baseprofile|root)$ ]]; then	# this is a base or root profile

			# if a base/root profile has mfa arn defined, the account
			# number can be determined without dynamic agumentation

			if [[ "${merged_mfa_arn[$idx]}" =~ ^arn:aws:iam::([[:digit:]]+):mfa/ ]]; then

				merged_account_id[$idx]="${BASH_REMATCH[1]}"
			fi

			# Warn if neither the region is set
			# nor is the default region configured
			if [[ "${merged_region[$idx]}" == "" ]] &&			# a region has not been set for this profile
				[[ "$default_region" == "" ]]; then				# and the default is not available

				printf "${BIYellow}${On_Black}\
The profile '${merged_ident[$idx]}' does not have a region set,\\n\
and the default region is not available (hence the region is also.\\n\
not available for roles or MFA sessions based off of this profile).${Color_Off}\\n\\n"
			fi
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
			(unset AWS_PROFILE ; unset AWS_DEFAULT_PROFILE ; aws --profile "${merged_ident[$idx]}" configure set region "${merged_region[$idx]}")

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

			printf "${BIYellow}${On_Black}\
The role '${merged_ident[$idx]}' does not have the region set\\n\
and it cannot be determined from its source (it doesn't have one\\n\
set either), and the default doesn't exist.${Color_Off}\\n\\n"
		fi

		if [[ "$DEBUG" == "true" ]]; then
			printf "\\n${Yellow}${On_Black}\
      merged_ident: ${merged_ident[$idx]}\\n\
      merged_type: ${merged_type[$idx]}\\n\
      mered_role_arn: ${merged_role_arn[$idx]}${Color_Off}\\n"
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

		# ROLE PROFILES: add role_name for easier get-role use, and account_id for xaccn determination
		if [[ "${merged_type[$idx]}" == "role" ]] && 		# this is a role
			[[ "${merged_role_arn[$idx]}" != "" ]] &&		# and it has an arn (if it doesn't, it's not a valid role profile)
			[[ "${merged_role_arn[$idx]}" =~ ^arn:aws:iam::([[:digit:]]+):role.*/([^/]+)$ ]]; then

			merged_account_id[$idx]="${BASH_REMATCH[1]}"
			merged_role_name[$idx]="${BASH_REMATCH[2]}"

			if [[ "$DEBUG" == "true" ]]; then
				printf "\\n${Yellow}${On_Black}\
ADDING merged_account_id ${BASH_REMATCH[1]} for profile ${merged_ident[$idx]}\\n\
ADDING merged_role_name ${BASH_REMATCH[2]} for profile ${merged_ident[$idx]}${Color_Off}\\n"
			fi

			# in offline augment, since the baseprofile Arn isn't available, the role xaccn status
			# can only be deduced by comparing the role Arn account# to the account# of the mfa_arn
			# (if one is defined), or to the account# of the mfa_arn in the source_profile
			# (if it has one). This is set to 'false' by default.

			# also add merged_role_mfa_required based on presence of MFA arn in role config
			if [[ "${merged_mfa_arn[$idx]}" != "" ]]; then  # if the MFA serial is present, MFA will be required regardless of whether the role actually demands it (but a negative dynamic augment result from get-role or local SSM will override this)

				merged_role_mfa_required[$idx]="true"

			else  # if the MFA serial is not present, we have no way to know without dynamic augment whether the role actually requires MFA (this is for quick mode)

				merged_role_mfa_required[$idx]="unknown"
			fi

			if [[ "${merged_role_source_profile_absent[$idx]}" == "false" ]]; then

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

				if [[ "$DEBUG" == "true" ]]; then
					printf "\\n${Yellow}${On_Black}\
   source profile type: $this_source_profile_type\\n\
   source profile ident: $this_source_profile_ident\\n\
   source baseprofile ident: ${merged_role_source_baseprofile_ident[$idx]}${Color_Off}\\n"
				fi
			fi

		elif [[ "${merged_type[$idx]}" == "role" ]] &&  # this is a role
				[[ "${merged_role_arn[$idx]}" == "" ||  # and it doesn't have role_arn defined
														#  -OR-
				   "${merged_role_source_profile_ident[$idx]}" == ""  ||  # it doesn't have source_profile defined
														#  -OR-
				   "${merged_role_source_profile_absent[$idx]}" == "true" ]]; then  # the source_profile is defined but doesn't exist

			# flag invalid roles for easy identification
			toggleInvalidProfile "set" "${merged_ident[$idx]}"

		elif [[ "${merged_type[$idx]}" == "role" &&  # this is a role
				"${merged_role_arn[$idx]}" != "" ]] &&  # and it has *something for an Arn
			 ! [[ "${merged_role_arn[$idx]}" =~ ^arn:aws:iam::([[:digit:]]+):role.*/([^/]+)$ ]]; then  # but the Arn isn't of the valid format

			printf "${Red}${On_Black}>>> The role profile ${merged_ident[$idx]} ARN '${merged_role_arn[$idx]}' is of invalid format!${Color_Off}\\n"

			# flag invalid roles for easy identification
			toggleInvalidProfile "set" "${merged_ident[$idx]}"

			# set marker for this run output
			merged_invalid_as_of[$idx]="true"

		fi

		# SESSION PROFILES: set merged_session_status ("expired/valid/invalid/unknown")
		# expired - creds present, time stamp expired
		# valid   - creds present, time stamp valid
		# invalid - no creds
		# unknown - creds present, timestamp missing
		# based on the remaining time for the MFA & role sessions
		# (dynamic augment will reduce these to valid/invalid):
		if [[ "${merged_type[$idx]}" =~ ^(mfasession|rolesession)$ ]]; then

			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}       calculating remaining seconds to the expiry timestamp of ${merged_aws_session_expiry[$idx]}..${Color_Off}\\n"

			if [[ "${merged_aws_access_key_id[$idx]}" == "" ]] ||
				[[ "${merged_aws_secret_access_key[$idx]}" == "" ]] ||
				[[ "${merged_aws_session_token[$idx]}" == "" ]]; then

				merged_session_status[$idx]="invalid"

			elif [[ "${merged_aws_session_expiry[$idx]}" == "" ]]; then  # creds are ok because ^^

				merged_session_status[$idx]="unknown"
			else

				getRemaining _ret "${merged_aws_session_expiry[$idx]}"
				merged_session_remaining[$idx]="${_ret}"

				[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}       remaining session (seconds): ${_ret}${Color_Off}\\n"

				case ${_ret} in
					-1)
						merged_session_status[$idx]="unknown"  # bad timestamp, time-based validity status cannot be determined
						;;
					0)
						merged_session_status[$idx]="expired"  # note: this includes the time slack
						;;
					*)
						merged_session_status[$idx]="valid"
						;;
				esac
			fi

			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}       session status set to: ${merged_session_status[$idx]}${Color_Off}\\n"

		else
			# base & role profiles
			merged_session_status[$idx]=""
		fi
	done

	## END ROLE PROFILE OFFLINE AUGMENTATION --------------------------------------------------------------------------

	if [[ "$quick_mode" == "false" ]]; then

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** starting dynamic augment${Color_Off}\\n"
		dynamicAugment
	fi

	# check possible existing config in
	# the environment before proceeding
	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** in-env credentials check${Color_Off}\\n"
	checkInEnvCredentials

	## BEGIN SELECT ARRAY DEFINITIONS ---------------------------------------------------------------------------------

	[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** creating select arrays${Color_Off}\\n"

	declare -a select_ident  # imported merged_ident
	declare -a select_type  # baseprofile, role, or root
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
	for ((idx=0; idx<${#merged_ident[@]}; ++idx))
	do
		if [[ "${merged_type[$idx]}" =~ ^(baseprofile|root)$ ]]; then

			select_ident[$select_idx]="${merged_ident[$idx]}"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]}${Color_Off}\\n"

			select_type[$select_idx]="${merged_type[$idx]}"
			(( baseprofile_count++ ))

			if [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" != "" ]]; then  # sts get-caller-identity had checked out ok for the baseprofile

				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" ]] &&
				[[ "${merged_baseprofile_arn[$idx]}" == "" ]]; then  # sts get-caller-identity had not worked on the baseprofile

				select_status[$select_idx]="invalid"

			elif [[ "$quick_mode" == "true" ]] &&
				[[ "${merged_invalid_as_of[$idx]}" != "" ]]; then  # quick mode is active; profile has been flagged invalid previously

				select_status[$select_idx]="flagged_invalid"

			else  # quick mode is active, no 'invalid' flag; the profile is probably ok, but no way to know for sure

				select_status[$select_idx]="unknown"
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
				printf "\\n\
${Yellow}${On_Black}select_ident ${select_idx}: ${select_ident[$select_idx]} (role)${Color_Off}\\n\\n
merged_ident: ${merged_ident[$idx]}\\n\
merged_role_source_profile_ident: ${merged_role_source_profile_ident[$idx]}\\n\
merged_type: ${merged_type[${merged_role_source_profile_idx[$idx]}]}
merged_role_source_baseprofile_ident: ${merged_role_source_baseprofile_ident[$idx]}\\n\
merged_baseprofile_arn: ${merged_baseprofile_arn[${merged_role_source_baseprofile_idx[$idx]}]}\\n\
merged_account_id: ${merged_account_id[${merged_role_source_baseprofile_idx[$idx]}]}\\n\\n\\n"

			fi

			select_type[$select_idx]="role"
			(( role_count++ ))

			if [[ "${merged_role_arn[$idx]}" == "" ]]; then  # does not have an arn

				select_status[$select_idx]="invalid"

			elif [[ "${merged_role_source_profile_ident[$idx]}" == "" ]]; then  # does not have a source_profile

				select_status[$select_idx]="invalid_nosource"

			elif [[ ${merged_invalid_as_of[$idx]} != "" ]]; then

				select_status[$select_idx]="invalid_badrole"

			elif [[ "$quick_mode" == "false" &&
					"${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_type[${merged_role_source_profile_idx[$idx]}]}" == "role" &&  # .. but it's a role..
					"${merged_role_source_baseprofile_ident[$idx]}" != "${merged_ident[${merged_role_source_profile_idx[$idx]}]}" &&  # .. and the source baseprofile ident doesn't equal source profile ident
					"${merged_baseprofile_arn[${merged_role_source_baseprofile_ident[$idx]}]}" != "" ]] ||  # and the source baseprofile has an ARN

				 [[ "$quick_mode" == "true" &&
					"${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_type[${merged_role_source_profile_idx[$idx]}]}" == "role" &&  # .. but it's a role..
					"${merged_role_source_baseprofile_ident[$idx]}" != "${merged_ident[${merged_role_source_profile_idx[$idx]}]}" &&  # .. and the source baseprofile ident doesn't equal source profile ident
					"${merged_invalid_as_of[${merged_role_source_baseprofile_ident[$idx]}]}" == "" ]]; then  # but the source has been flagged invalid

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

			elif [[ "$quick_mode" == "false" &&
					"${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_baseprofile_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]] ||

				 [[ "$quick_mode" == "true" &&
					"${merged_role_source_profile_ident[$idx]}" != "" &&  # has a source_profile..
					"${merged_invalid_as_of[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # but the source has been flagged invalid

				select_status[$select_idx]="invalid_source"

			elif [[ "$quick_mode" == "false" &&
					"${merged_role_mfa_required[$idx]}" == "false" ]] ||  # above OK + no MFA required (confirmed w/quick off)

				 [[ "$quick_mode" == "true" &&
					"${merged_mfa_arn[$idx]}" == "" ]]; then  # above OK + no MFA required (based on absence of mfa_arn w/quick on)

				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" &&
					"${merged_role_mfa_required[$idx]}" == "true" ]] &&  # MFA is required..

				 [[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" != "" ]]; then  # .. and the source_profile has a valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="valid"

			elif [[ "$quick_mode" == "false" &&
					"${merged_role_mfa_required[$idx]}" == "true" ]] &&  # MFA is required..

				 [[ "${merged_mfa_arn[${merged_role_source_profile_idx[$idx]}]}" == "" ]]; then  # .. and the source_profile has no valid MFA ARN

				# not quick mode, role's source_profile is defined but invalid
				select_status[$select_idx]="invalid_mfa"

			else
				# quick_mode is active and MFA is required (plus a catch-all for other possible use-cases)
				select_status[$select_idx]="unknown"
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

		printf "${BIRed}${On_Black}No baseprofiles found. Cannot continue.${Color_Off}\\n\\n\\n"
		exit 1

	elif [[ "${baseprofile_count}" -eq 1 ]] &&  # only one baseprofile is present (it may or may not have a session)..	#2 - ONE BASEPROFILE ONLY (W/WO SESSION)
		[[ "${role_count}" -eq 0 ]]; then  # .. and no roles; use the simplified menu

		single_profile="true"
		printf "\\n"

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

			printf "\\n${BIWhite}${On_Black}You have one configured profile: ${BIYellow}${select_ident[0]}${Color_Off} (IAM: ${merged_username[${select_merged_idx[0]}]}${pr_accn})\\n"
			if [[ "${merged_baseprofile_operational_status[${select_merged_idx[$idx]}]}" == "reqmfa" ]]; then
				printf "${Yellow}${On_Black}.. it may require MFA for access${Color_Off}\\n"
			fi

			if [[ "${merged_mfa_arn[${select_merged_idx[0]}]}" != "" ]]; then
				printf "${Green}${On_Black}.. its vMFAd is enabled${Color_Off}\\n"

				if [[ "${select_has_session[0]}" == "true" ]] &&
					[[ "${merged_invalid_as_of[${select_merged_session_idx[0]}]}" == "" ]] &&
					[[ "${merged_aws_access_key_id[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_aws_secret_access_key[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_aws_session_token[${select_merged_session_idx[0]}]}" != "" ]] &&
					[[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]]; then

					if [[ "${merged_session_remaining[${select_merged_session_idx[0]}]}" != "-1" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[0]}]}"

						printf ".. and it ${BIPurple}${On_Black}has an active MFA session ${Purple}(with ${pr_remaining} of the validity period remaining)${Color_Off}\\n"
					else
						printf ".. and it ${BIPurple}${On_Black}has an unconfirmed MFA session ${Purple}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
					fi
				else
					printf ".. and no active persistent MFA sessions exist\\n"
				fi

			else  # no vMFAd configured
				printf "\
.. but it doesn't have a virtual MFA device attached/enabled\\n\
(use the 'enable-disable-vmfa-device.sh' script to enable a vMFAd).\\n\\n\
Without a vMFAd the listed baseprofile can only be used as-is.\\n\\n"

			fi

		elif [[ "${select_status[0]}" =~ ^(unknown|flagged_invalid)$ ]]; then  # status 'unknown' or 'flagged_invalid' are by definition 'quick'

			printf "${BIWhite}${On_Black}You have one configured profile: ${BIYellow}${select_ident[0]}${Color_Off}\\n"

			if [[ "${select_status[0]}" == "flagged_invalid" ]]; then
				printf "${BIRed}${On_Black}.. but it was previously flagged invalid, and likely will not work${Color_Off}\\n"
			fi

			if [[ "${select_has_session[0]}" == "true" ]] &&
				[[ "${merged_invalid_as_of[${select_merged_session_idx[0]}]}" == "" ]] &&
				[[ "${merged_aws_access_key_id[${select_merged_session_idx[0]}]}" != "" ]] &&
				[[ "${merged_aws_secret_access_key[${select_merged_session_idx[0]}]}" != "" ]] &&
				[[ "${merged_aws_session_token[${select_merged_session_idx[0]}]}" != "" ]] &&
				[[ "${merged_session_status[${select_merged_session_idx[0]}]}" != "expired" ]]; then  # since this is quick, the status can be 'valid' or 'unknown'

				if [[ "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]]; then

					if [[ "${merged_session_remaining[${select_merged_session_idx[0]}]}" != "-1" ]]; then
						getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[0]}]}"

						printf ".. and it ${BIPurple}${On_Black}has an active MFA session ${Purple}(with ${pr_remaining} of the validity period remaining)${Color_Off}\\n"
					else
						printf ".. and it ${BIPurple}${On_Black}has an unconfirmed MFA session ${Purple}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
					fi

				else  # no expiry timestamp for some reason

					printf ".. and it ${BIWhite}${On_Black}has an MFA session (the validity status could not be determined)${Color_Off}\\n"
				fi
			else
				printf ".. and no active persistent MFA sessions exist\\n"
			fi
		else  # no baseprofiles in 'valid' (not quick) or 'unknown' (quick) status; bailing out

			printf "${BIRed}${On_Black}No valid baseprofiles found; please check your AWS configuration files.\\nCannot continue.${Color_Off}\\n\\n\\n"
			exit 1
		fi

		printf "\\nDo you want to:\\n"
		printf "${BIWhite}${On_Black}U${Color_Off}: Use the above baseprofile as-is (without an MFA session)?\\n"

		single_select_start_mfa="disallow"
		if [[ "${select_status[0]}" == "valid" &&  # not quick, profile validated..
			  "${merged_mfa_arn[${select_merged_idx[0]}]}" != "" ]] ||  # .. and it has a vMFAd configured
			[[ "${quick_mode}" == "true" ]]; then  # or the quick mode is on (in which case the status is unknown and we assume the user knows what they're doing)

			printf "${BIWhite}${On_Black}S${Color_Off}: Start/renew an MFA session for the profile mentioned above?\\n"
			single_select_start_mfa="allow"
		fi

		single_select_resume="disallow"
		if  [[ "${select_status[0]}" == "valid" &&  # not quick, profile validated..
			   "${select_has_session[0]}" == "true" &&  # .. and it has an MFA session..
			   "${merged_session_status[${select_merged_session_idx[0]}]}" == "valid" ]] ||  # .. which is valid

			[[ "${quick_mode}" == "true" &&  # or the quick mode is on (in which case the status is unknown and we assume the user knows what they're doing)
			   "${select_has_session[0]}" == "true" &&  # .. an MFA session exists..
			   "${merged_session_status[${select_merged_session_idx[0]}]}" =~ ^(valid|unknown)$ ]]; then  # and it's ok by timestamp or the timestamp doesn't exist

			printf "${BIWhite}${On_Black}R${Color_Off}: Resume the existing active MFA session?\\n"
			single_select_resume="allow"
		fi

		# single profile selector
		while :
		do
			read -s -n 1 -r
			case $REPLY in
				u|U)
					printf "Using the ${select_type[0]} credentials as-is (no MFA)..\\n"
					selprofile="1"
					break
					;;
				s|S)
					if [[ ${single_select_start_mfa} == "allow" ]]; then
						printf "Starting an MFA session..\\n"
						selprofile="1"
						mfa_req="true"
						break
					else  # no baseprofiles in 'valid' status; bailing out
						printf "${BIRed}${On_Black}Please select one of the options above!${Color_Off}\\n"
					fi
					;;
				r|R)
					if [[ "${single_select_resume}" == "allow" ]]; then
						printf "Resuming the existing MFA session..\\n"
						selprofile="1s"
						session_profile="true"
						break
					else
						printf "${BIRed}${On_Black}Please select one of the options above!${Color_Off}\\n"
					fi
					;;
				*)
					printf "${BIRed}${On_Black}Please select one of the options above!${Color_Off}\\n"
					;;
			esac
		done

	# MULTI-PROFILE MENU
	# (roles are only allowed with at least one baseprofile)
	elif [[ "${baseprofile_count}" -gt 1 ]] ||   # more than one baseprofile is present..								#3 - >1 BASEPROFILES (W/WO SESSION), (≥1 ROLES)
												 # -or-
		 [[ "${baseprofile_count}" -ge 1 &&      # one or more baseprofiles are present
			"${role_count}" -ge 1 ]]; then       # .. AND one or more role profiles are present

		# create the baseprofile selections
		printf "\\n${BIWhite}${On_DGreen} CONFIGURED AWS PROFILES: ${Color_Off}\\n\\n"

		# this may be different as this count will not include
		# the invalid, non-selectable profiles
		selectable_multiprofiles_count="0"
		display_idx="0"
		invalid_count="0"

		for ((idx=0; idx<${#select_ident[@]}; ++idx))
		do
			[[ "$DEBUG" == "true" ]] && printf "${Yellow}${On_Black}select_ident: ${select_ident[$idx]}, select_type: ${select_type[$idx]}, select_status: ${select_status[$idx]}${Color_Off}\\n"

			if [[ "${select_type[$idx]}" =~ ^(baseprofile|root)$ ]] &&
				[[ "${select_status[$idx]}" =~ ^(valid|unknown|flagged_invalid)$ ]]; then

				# increment selectable_multiprofiles_count
				(( selectable_multiprofiles_count++ ))

				# make a more-human-friendly selector digit (starts from 1)
				(( display_idx++ ))

				# reference to the select_display array
				select_display[$display_idx]="$idx"

				if [[ "$quick_mode" == "false" ]]; then

					# IAM username available? (a dynamic augment data point)
					if [[ "${merged_username[${select_merged_idx[$idx]}]}" != "" ]]; then

						pr_user="${merged_username[${select_merged_idx[$idx]}]}"
					else  # should never occur as the entire profile should be flagged invalid in this case
						pr_user="unknown — a bad profile?"
					fi

					# account alias available? (a dynamic augment data point)
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

					if [[ "${merged_baseprofile_operational_status[${select_merged_idx[$idx]}]}" == "reqmfa" ]]; then
						mfa_enforced="; ${Yellow}${On_Black}MFA may be enforced${Color_Off}"
					else
						mfa_enforced=""
					fi

					# print the baseprofile entry
					if [[ "${select_type[$idx]}" != "root" ]]; then
						printf "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off} (IAM: ${pr_user}${pr_accn}${mfa_notify}${mfa_enforced})\\n"
					else
						printf "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off} (${BIYellow}${On_Black}ROOT USER${Color_Off}${pr_accn}${mfa_notify})\\n"
					fi

					# print an associated session entry if one exist and is valid
					if [[ "${select_has_session[$idx]}" == "true" ]] &&
						[[ "${merged_invalid_as_of[${select_merged_session_idx[$idx]}]}" == "" ]] &&
						[[ "${merged_aws_access_key_id[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_secret_access_key[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_session_token[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" == "valid" ]]; then

						if [[ "${merged_session_remaining[${select_merged_session_idx[$idx]}]}" != "-1" ]]; then

							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"
							printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} ${Purple}${On_Black}(${pr_remaining} of the validity period remaining)${Color_Off}\\n"
						else
							printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} ${Purple}${On_Black}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
						fi
					fi

					printf "\\n"

				else  # quick_mode is active; print abbreviated data w/available intelligence

					# print the baseprofile
					if [[ "${select_status[$idx]}" =~ ^flagged_invalid$ ]]; then
						printf "${BIBlue}${On_Black}${display_idx}: ${select_ident[$idx]}"

						(( invalid_count++ ))

						if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" =~ ^arn:aws: ]]; then

							printf " (profile was previously flagged invalid; vMFAd record present)${Color_Off}\\n"
						else
							printf " (profile was previously flagged invalid)${Color_Off}\\n"
						fi

					else
						printf "${BIWhite}${On_Black}${display_idx}: ${select_ident[$idx]}${Color_Off}"

						if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" =~ ^arn:aws: ]]; then

							printf " (vMFAd record present)\\n"
						else
							printf "\\n"
						fi
					fi

					# print an associated session if one exist, is not flagged invalid,
					# and is not expired (i.e. is in 'valid' or 'unknown' status)
					if [[ "${select_has_session[$idx]}" == "true" ]] &&
						[[ "${merged_invalid_as_of[${select_merged_session_idx[$idx]}]}" == "" ]] &&
						[[ "${merged_aws_access_key_id[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_secret_access_key[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_aws_session_token[${select_merged_session_idx[$idx]}]}" != "" ]] &&
						[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" != "expired" ]]; then

						if [[ "${merged_session_remaining[${select_merged_session_idx[$idx]}]}" != "-1" ]]; then
							getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

							printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} ${Purple}${On_Black}(${pr_remaining} of the validity period remaining)${Color_Off}\\n"
						else
							printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} MFA session${Color_Off} ${Purple}${On_Black}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
						fi

					fi
					printf "\\n"
				fi

			elif [[ "${select_type[$idx]}" =~ ^(baseprofile|root)$ ]] &&
				[[ "${select_status[$idx]}" == "invalid" ]]; then

				(( invalid_count++ ))

				# print the invalid baseprofile notice
				printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (credentials have no access)\\n"
				printf "\\n"
			fi
		done

		if [[ "${role_count}" -gt 0 ]]; then
			# create the role profile selections
			printf "\\n${BIWhite}${On_DGreen} CONFIGURED AWS ROLES: ${Color_Off}\\n\\n"

			for ((idx=0; idx<${#select_ident[@]}; ++idx))
			do
				if [[ "${select_type[$idx]}" == "role"  &&
					  "${select_status[$idx]}" =~ ^(valid|unknown|chained_source_valid)$ ]]; then

					# increment selectable_multiprofiles_count
					(( selectable_multiprofiles_count++ ))

					# make a more-human-friendly selector digit (starts from 1)
					(( display_idx++ ))

					# reference to the select_display array
					select_display[$display_idx]="$idx"

					# set x-accn notify & source profile account alias/number
					if [[ "${merged_role_xaccn[${select_merged_idx[$idx]}]}" == "true" ]]; then

						xaccn_notify="[x-account] "
					else
						xaccn_notify=""
					fi

					# if available, set role source profile alias or account for display
					# (not available for non-MFA source profiles with the quick mode in effect)
					if [[ "${merged_account_alias[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}" != "" ]]; then

						# use an alias if one has been set,..
						pr_accn=" @${merged_account_alias[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}"

					elif [[ "${merged_account_id[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}" != "" ]]; then

						# use the AWS account number if no alias has been defined..

						pr_accn=" @${merged_account_id[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}"
					else
						# .. or nothing for a bad profile
						pr_accn=""
					fi

					if [[ "$quick_mode" == "false" ]]; then

						pr_rolename="${merged_role_name[${select_merged_idx[$idx]}]}"

						# use account alias if available, otherwise the bare account number
						# (the number is *always available for valid roles)
						if [[ "${merged_account_alias[${select_merged_idx[$idx]}]}" != "" ]]; then

							pr_roleaccn=" @${merged_account_alias[${select_merged_idx[$idx]}]}"
						else
							pr_roleaccn=" @${merged_account_id[${select_merged_idx[$idx]}]}"
						fi

						if [[ "${select_status[$idx]}" == "chained_source_valid" ]]; then
							pr_source_name="${merged_role_name[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}"
							pr_chained="${Yellow}${On_Black}[CHAINED]${Color_Off} "
						else
							pr_source_name="${merged_role_source_username[${select_merged_idx[$idx]}]}"
							pr_chained=""
						fi

						if [[ "$DEBUG" == "true" ]]; then
							printf "\\n${BIYellow}${On_Black}\
merged_role_mfa_required: ${merged_role_mfa_required[${select_merged_idx[$idx]}]}\\n\
select_status: ${select_status[$idx]}\\n\
merged_role_xaccn: ${merged_role_xaccn[${select_merged_idx[$idx]}]}\\n\
merged_role_ssm_mfareq_lookup: ${merged_role_ssm_mfareq_lookup[${select_merged_idx[$idx]}]}${Color_Off}\\n"
						fi

						# display MFA required indicator if:
						#  rolemfa req'd is set, this is not a chained roule, and not an xaccn role
						#  or
						#  this is an xaccn role, role mfa req'd is set, AND SSM had true/false for mfa_req
						if [[ "${merged_role_mfa_required[${select_merged_idx[$idx]}]}" == "true" &&
						    ! "${select_status[$idx]}" =~ ^chained_source &&
						      "${merged_role_xaccn[${select_merged_idx[$idx]}]}" != "true" ]] ||
						    
						    [[ "${merged_role_xaccn[${select_merged_idx[$idx]}]}" == "true" &&
							   "${merged_role_mfa_required[${select_merged_idx[$idx]}]}" == "true" &&
						       "${merged_role_ssm_mfareq_lookup[${select_merged_idx[$idx]}]}" == "true" ]]; then

							mfa_notify="; ${Red}${On_Black}MFA required to assume${Color_Off}"

						elif [[ "${merged_role_xaccn[${select_merged_idx[$idx]}]}" == "true" ]] &&
							   ! [[ "${merged_role_mfa_required[${select_merged_idx[$idx]}]}" == "false" &&
						            "${merged_role_ssm_mfareq_lookup[${select_merged_idx[$idx]}]}" == "true" ]]; then

							mfa_notify="; ${Yellow}${On_Black}MFA may be required to assume${Color_Off}"

						else
							mfa_notify=""
						fi

						if [[ "${select_status[$idx]}" =~ ^chained_source_valid ]]; then

							chained_notify="; ${Green}${On_Black}uses the role session of '${merged_role_source_profile_ident[${select_merged_idx[$idx]}]}' to authenticate${Color_Off}"
						else
							chained_notify=""
						fi

						# print the role
						printf "${BIWhite}${On_Black}${display_idx}:${Color_Off} ${pr_chained}${BIWhite}${On_Black}${xaccn_notify}${select_ident[$idx]}${Color_Off} (${pr_source_name}${pr_accn} -> ${pr_rolename}${pr_roleaccn}${chained_notify}${mfa_notify})\\n"

						# print the associated role session
						if [[ "${select_has_session[$idx]}" == "true" ]] &&
							[[ "${merged_invalid_as_of[${select_merged_session_idx[$idx]}]}" == "" ]] &&
							[[ "${merged_aws_access_key_id[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_aws_secret_access_key[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_aws_session_token[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" == "valid" ]]; then

							if [[ "${merged_session_remaining[${select_merged_session_idx[$idx]}]}" != "-1" ]]; then
								getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

								printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} role session${Color_Off} ${Purple}${On_Black}(${pr_remaining} of the validity period remaining)${Color_Off}\\n"
							else
								printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} role session${Color_Off} ${Purple}${On_Black}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
							fi
						fi

					else  # quick_mode is active; print abbreviated data

						pr_rolename="${merged_role_name[${select_merged_idx[$idx]}]}"
						pr_roleaccn=" @${merged_account_id[${select_merged_idx[$idx]}]}"

						if [[ "${select_status[$idx]}" == "chained_source_valid" ]]; then
							pr_chained="${Yellow}${On_Black}[CHAINED]${Color_Off} "
							pr_source_name="${merged_role_name[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}"
						else
							pr_chained=""
							pr_source_name="${merged_ident[${merged_role_source_profile_idx[${select_merged_idx[$idx]}]}]}"
						fi

						if [[ "${merged_mfa_arn[${select_merged_idx[$idx]}]}" != "" ]]; then

							mfa_notify="; ${Yellow}${On_Black}MFA may be required to assume${Color_Off}"
						else
							mfa_notify=""
						fi

						if [[ "${select_status[$idx]}" =~ ^chained_source_valid ]]; then

							chained_notify="; ${Green}${On_Black}uses the role session of '${merged_role_source_profile_ident[${select_merged_idx[$idx]}]}' to authenticate${Color_Off}"
						else
							chained_notify=""
						fi

						# print the role
						printf "${BIWhite}${On_Black}${display_idx}:${Color_Off} ${pr_chained}${BIWhite}${On_Black}${xaccn_notify}${select_ident[$idx]}${Color_Off} (${pr_source_name}${pr_accn} -> ${pr_rolename}${pr_roleaccn}${chained_notify}${mfa_notify})\\n"

						# print an associated role session if exist and not expired (i.e. 'valid' or 'unknown')
						if [[ "${select_has_session[$idx]}" == "true" ]] &&
							[[ "${merged_invalid_as_of[${select_merged_session_idx[$idx]}]}" == "" ]] &&
							[[ "${merged_aws_access_key_id[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_aws_secret_access_key[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_aws_session_token[${select_merged_session_idx[$idx]}]}" != "" ]] &&
							[[ "${merged_session_status[${select_merged_session_idx[$idx]}]}" != "expired" ]]; then

							if [[ "${merged_session_remaining[${select_merged_session_idx[$idx]}]}" != "-1" ]]; then
								getPrintableTimeRemaining pr_remaining "${merged_session_remaining[${select_merged_session_idx[$idx]}]}"

								printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} role session${Color_Off} ${Purple}${On_Black}(${pr_remaining} of the validity period remaining)${Color_Off}\\n"
							else
								printf "${BIPurple}${On_Black}${display_idx}s: ${select_ident[$idx]} role session${Color_Off} ${Purple}${On_Black}(expiration timestamp missing; an expired legacy session?)${Color_Off}\\n"
							fi
						fi
					fi

					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (the role profile is missing the role identifier ('role_arn'))\\n"
					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "chained_source_invalid" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}CHAINED ROLE: ${select_ident[$idx]}${Color_Off} (requires an active role session by '${merged_role_source_profile_ident[${select_merged_idx[$idx]}]}' to authenticate)\\n"
					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_source" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (configured source profile is non-functional)\\n"
					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_badrole" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (configured role ARN is invalid or other role configuration error)\\n"
					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_nosource" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (source profile not defined for the role; run without quick mode to set)\\n"
					printf "\\n"

				elif [[ "${select_type[$idx]}" == "role" ]] &&
					[[ "${select_status[$idx]}" == "invalid_mfa" ]]; then

					# print the invalid role profile notice
					printf "${BIBlue}${On_Black}INVALID: ${select_ident[$idx]}${Color_Off} (role requires MFA, but source profile has no vMFAd configured)\\n"
					printf "\\n"

				fi
			done
		fi

		printf "\\n\
You can switch to a baseprofile to use it as-is, start an MFA session for a baseprofile\\n\
if it has a vMFAd configured/enabled, or switch to an existing active MFA or role session\\n\
if any are available (indicated by the letter 's' after the profile ID, e.g. '1s').\\n\
NOTE: The expired MFA and role sessions are not displayed.\\n"

		if [[ $invalid_count -gt 0 ]]; then

			printf "\\n\
To remove profiles marked 'invalid' from the configuration, remove the corresponding\\n\
profile entries from your AWS configuration files at the following locations:\\n\
'$CONFFILE'\\n\
'$CREDFILE'\\n"

		fi

		# prompt for profile selection
		if [[ "$quick_mode" == "true" ]]; then
			printf "\\n${Yellow}${On_Black}NOTE: The profile will be validated upon selection.${Color_Off}\\n"
		fi
		printf "\\n${BIWhite}${On_Black}SELECT A PROFILE BY THE ID:${Color_Off} "
		read -r selprofile
		printf "\\n"

	fi  # end profile selections


	# PROCESS THE SELECTION -------------------------------------------------------------------------------------------

	if [[ "$selprofile" != "" ]]; then

		[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** selection received: ${selprofile}${Color_Off}\\n"

		# check for a valid selection pattern
		if [[ ! "$selprofile" =~ ^[[:digit:]]+$ ]] &&
			[[ ! "$selprofile" =~ ^[[:digit:]]+s$ ]]; then

			# non-acceptable characters were present in the selection -> exit
			printf "${BIRed}\
There is no profile '${selprofile}'.${Color_Off}\\n\
You may select the base and role profiles by the corresponding digit(s),\\n\
and the MFA or role session (if any exist) by the corresponding digit(s)\\n\
followed immediately by the letter 's'.\\n"

			exit 1
		fi

		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_selval="${BASH_REMATCH[1]}"

		if [[ "$selprofile_selval" != "" ]]; then
			# if the numeric selection was found,
			# translate it to the array index and validate

			# remove leading zeros if any are present
			[[ "$selprofile_selval" =~ ^0*(.*)$ ]] && selprofile_selval="${BASH_REMATCH[1]}"

			(( adjusted_display_idx=selprofile_selval-1 ))

			# first check that the selection is in range:
			# does the selected profile exist? (this includes baseprofiles/roleprofiles);
			if [[ $adjusted_display_idx -ge $selectable_multiprofiles_count ||
				$adjusted_display_idx -lt 0 ]] &&

				[[ "$single_profile" == "false" ]]; then

				# a selection outside of the existing range was specified -> exit
				printf "\\n${BIRed}${On_Black}There is no profile '${selprofile}'. Cannot continue.${Color_Off}\\n\\n"
				exit 1
			fi

			# look up select index by the selected display index
			# (select index includes possible invalids and can thus be a different value)
			selprofile_idx="${select_display[$selprofile_selval]}"

			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** display index in select array: ${selprofile} (${select_ident[$selprofile_idx]})${Color_Off}\\n"
			[[ "$DEBUG" == "true" ]] && printf "\\n${BIYellow}${On_Black}** selprofile_idx: ${selprofile_idx}${Color_Off}\\n"

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

				if [[ "${select_type[$selprofile_idx]}" =~ ^(baseprofile|root)$ ]]; then  # select_type is 'baseprofile' or 'role' because selection menus don't have session details internally

					final_selection_type="mfasession"
					printf "SELECTED MFA SESSION PROFILE: ${final_selection_ident} (for the baseprofile \"${select_ident[$selprofile_idx]}\")\\n"

				elif [[ "${select_type[$selprofile_idx]}" == "role" ]]; then

					final_selection_type="rolesession"
					printf "SELECTED ROLE SESSION PROFILE: ${final_selection_ident} (for the role profile \"${select_ident[$selprofile_idx]}\")\\n"
				fi

				# determines whether to print session details
				session_profile="true"

			elif [[ "$selprofile_session_check" != "" ]] &&
				[[ "${select_has_session[$selprofile_idx]}" == "false" ]]; then
				# a session profile ('s') was selected for a base/role profile that has no session -> exit

				printf "${BIRed}${On_Black}
There is no profile '${selprofile}'.${Color_Off}\\n
(Profile '$selprofile_selval' has no session.)\\n\\n"

				exit 1

			elif [[ "$selprofile_session_check" == "" ]] &&
				[[ "${select_type[$selprofile_idx]}" =~ ^(baseprofile|root)$ ]]; then

				# A BASEPROFILE WAS SELECTED <<<<<<<============================
				# (can also be a root profile)

				final_selection_idx="${select_merged_idx[$selprofile_idx]}"
				final_selection_ident="${select_ident[$selprofile_idx]}"
				final_selection_type="baseprofile"

				if [[ "$quick_mode" == "true" ]]; then

					# JIT profile check the selected profile in quick mode only
					printf "${Green}${On_Black}Validating the selection '${final_selection_ident}'...${Color_Off}\\n\\n"
					profileCheck profile_validity_check "$final_selection_ident"

					if [[ "${profile_validity_check}" == "true" ]]; then
						# get and persist advertised session length (if any)
						mfaSessionLengthOverrideCheck "$final_selection_ident"

						user_detail_phrase=""
						user_account_detail=""
						if [[ "${merged_account_alias[${final_selection_idx}]}" != "" ]]; then
							user_account_detail="${merged_account_alias[${final_selection_idx}]}"
						else
							user_account_detail="${merged_account_id[${final_selection_idx}]}"
						fi

						if [[ "${merged_type[${final_selection_idx}]}" == "baseprofile" ]] &&
							[[ "${merged_username[${final_selection_idx}]}" != "" ]]; then

							user_detail_phrase=" (IAM: ${merged_username[${final_selection_idx}]} @${user_account_detail})"

						elif [[ "${merged_type[${final_selection_idx}]}" == "root" ]]; then
							user_detail_phrase=" (root user @${user_account_detail})"
						fi

						printf "${BIGreen}${On_Black}SELECTED BASE PROFILE: '${final_selection_ident}'${Green}${user_detail_phrase}'${Color_Off}\\n"
					else
						printf "${BIRed}${On_Black}The selected profile ('${final_selection_ident}') has no access. Cannot continue.${Color_Off}\\n\\n"
						exit 1
					fi

				else

					# get and persist advertised session length (if any)
					mfaSessionLengthOverrideCheck "$final_selection_ident"
					printf "${BIGreen}${On_Black}SELECTED BASE PROFILE: '${final_selection_ident}'${Color_Off}\\n"
				fi

			elif [[ "$selprofile_session_check" == "" ]] &&
				[[ "${select_type[$selprofile_idx]}" == "role" ]]; then

				# A ROLE PROFILE WAS SELECTED <<<<<<<===========================

				final_selection_idx="${select_merged_idx[$selprofile_idx]}"
				final_selection_ident="${select_ident[$selprofile_idx]}"

				if [[ "${select_status[$select_idx]}" == "chained_source_valid" ]]; then
					final_selection_type="chained_role"
				else
					final_selection_type="role"
				fi

				printf "${BIGreen}${On_Black}\
SELECTED ROLE PROFILE: $final_selection_ident${Color_Off}\\n\
SOURCE PROFILE: ${merged_role_source_profile_ident[$final_selection_idx]}\\n"

			fi
		else
			# no numeric part in selection -> exit
			printf "${BIRed}${On_Black}There is no profile '${selprofile}'.${Color_Off}\\n\\n"
			exit 1
		fi
	else
		# empty selection -> exit
		printf "${BIRed}${On_Black}You didn't select any profile.${Color_Off}\\n\\n"
		exit 1
	fi

	# ACQUIRE SESSION -------------------------------------------------------------------------------------------------

	# this is an MFA request (an vMFAd ARN exists but the MFA is not active;
	# all baseprofile selections from the multi-menu are considered MFA requests
	# (user has the option to hit enter at the MFA code prompt to opt to use the
	# baseprofile as-is), while from the simplified single-profile menu the MFA
	# session request is explicit.

	session_processing=""

	# session selection logic
	if [[ "${merged_mfa_arn[$final_selection_idx]}" != "" ]] &&	 # quick_mode off: merged_mfa_arn comes from dynamicAugment; quick_mode on: merged_mfa_arn comes from confs_mfa_arn (if avl)
																 #  AND
		[[ ( "$single_profile" == "false" &&					 # limit to multiprofiles +
			 "$final_selection_type" == "baseprofile" ) ||		 # baseprofile selection from the multiprofile menu (also can be root)
																 #  OR
			 "$mfa_req" == "true" ]]; then						 # 'mfa_req' is an explicit MFA request used by the simplified single baseprofile display

		# BASEPROFILE MFA REQUEST
		session_processing="mfasession"

	elif [[ "$quick_mode" == "true" ]] &&							# quick mode is active
																	#  AND
		 [[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&	# there is no vMFAd ARN in the conf -- could be new or not [yet] persisted
		 															#  AND
		 [[ ( "$single_profile" == "false" &&						# limit to multiprofiles
			  "$final_selection_type" == "baseprofile" ) ||			# baseprofile selection from the multiprofile menu (also can be root)
																	#  OR
			  "$mfa_req" == "true" ]]; then							# single-profile MFA session req

		if [[ "${merged_invalid_as_of[$final_selection_idx]}" != "" ]]; then

			session_processing="nosession"

		else
			mfa_arn_refresh_result=""
			# a JIT lookup for vMFAd Arn only when the profile is likely valid
			refreshProfileMfaArn mfa_arn_refresh_result $final_selection_idx

			if [[ "$mfa_arn_refresh_result" == "available" ]]; then

				session_processing="mfasession"
			else
				session_processing="nosession"
			fi
		fi

	elif [[ "$quick_mode" == "false" ]] &&							# quick_mode is inactive..
																	#  AND
		 [[ "${merged_mfa_arn[$final_selection_idx]}" == "" ]] &&	# .. and no vMFAd is configured (no dynamically acquired vMFAd ARN); print a notice and exit
		 															#  AND
		 [[ ( "$single_profile" == "false" &&						# limit to multiprofiles
			  "$final_selection_type" == "baseprofile" ) ||			# baseprofile selection from the multiprofile menu (also can be root)
		 															#  OR
			  "$mfa_req" == "true" ]]; then							# single-profile MFA session req

		session_processing="nosession"

	elif [[ "$final_selection_type" == "role" ]]; then  # only selecting roles; all the critical parameters have already been
														# checked for select_ arrays; invalid profiles cannot have final_ params.
		# ROLE SESSION REQUEST
		session_processing="rolesession"
	fi

	# SESSION (OR NOT) REQUEST PROCESSING -----------------------------------------------------------------------------

	if [[ "$session_processing" == "mfasession" ]]; then

		# reassigned for better code narrative below
		AWS_BASEPROFILE_IDENT="$final_selection_ident"
		printf "\\nAcquiring an MFA session token for the baseprofile: ${BIWhite}${On_Black}${AWS_BASEPROFILE_IDENT}${Color_Off}...\\n"

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
			export AWS_DEFAULT_PROFILE="$AWS_BASEPROFILE_IDENT"
			# exporting AWS_PROFILE too even though it's only supported by the SDKs
			export AWS_PROFILE="$AWS_BASEPROFILE_IDENT"
		fi

	elif [[ "$session_processing" == "rolesession" ]]; then

		# reassigned for better code narrative below
		AWS_ROLE_PROFILE_IDENT="$final_selection_ident"
		printf "\\nAcquiring a role session token for the role profile: ${BIWhite}${On_Black}${AWS_ROLE_PROFILE_IDENT}${Color_Off}...\\n"

		acquireSession role_session_data "$AWS_ROLE_PROFILE_IDENT"

		# Add the '-rolesession' suffix to final_selection_ident,
		# as it's not there yet since the session was just created.
		# This is a global updated in acquireSession
		final_selection_ident="$AWS_SESSION_IDENT"

		persistSessionMaybe "$AWS_ROLE_PROFILE_IDENT" "$AWS_SESSION_IDENT" "$role_session_data"

	elif [[ "$session_processing" == "nosession" ]]; then  # offer to use baseprofile creds only

		# determines whether to print session details
		session_profile="false"

		# switching the single-profile mfa_req to false since no vMFAd is available
		mfa_req="false"

		if [[ "${merged_type[$final_selection_idx]}" != "root" ]]; then

			printf "\\n${BIRed}${On_Black}\
A vMFAd has not been configured/enabled for this profile!${Color_Off}\\n\
To start an MFA session for this profile you need to first run\\n\
'enable-disable-vmfa-device.sh' script to configure and enable\\n\
the vMFAd for this profile.\\n\
\\n\
However, you can use this baseprofile as-is without an MFA session.\\n\
Note that the effective security policy may limit your access\\n\
without an active MFA session.\\n"

			printf "\\nDo you want to use the baseprofile without an MFA session? ${BIWhite}${On_Black}Y/N${Color_Off}\\n"
			yesNo yes_or_no

			if [[ "${yes_or_no}" == "no" ]]; then
				printf "\\n${BIWhite}${On_Black}Exiting.${Color_Off}\\n\\n"
				exit 1
			fi
		else  # yeah, this is a root profile

			printf "\\n${BIYellow}${On_Black}This is a root profile; MFA sessions are not supported.${Color_Off}\\n\\n"

		fi

	fi

	# USE THE PROFILE AS-IS (THIS MAY BE AN EXISTING ACTIVE SESSION, OR A NON-MFA BASEPROFILE) ------------------------

	# this is _not_ a new MFA session, so read in the selected persistent values
	# (for the new MFA/role sessions they are already present as they were set
	# in acquireSession as globals)
	if [[ ( "$final_selection_type" == "baseprofile" &&  # (also can be root)
		  "$AWS_MFASESSION_INITIALIZED" == "false" ) ||

		( "$final_selection_type" == "mfasession" &&
		  "$AWS_MFASESSION_INITIALIZED" == "false" ) ||

		( "$final_selection_type" == "rolesession" &&
		  "$AWS_ROLESESSION_INITIALIZED" == "false" ) ||

		( "${single_profile}" == "true" &&
		  "${mfa_req}" == "false" ) ]]; then

		AWS_ACCESS_KEY_ID="${merged_aws_access_key_id[${final_selection_idx}]}"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}aws_access_key_id retrieved from the merge arrays:\\n${ICyan}${AWS_ACCESS_KEY_ID}${Color_Off}\\n"

		AWS_SECRET_ACCESS_KEY="${merged_aws_secret_access_key[${final_selection_idx}]}"
		[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}aws_access_key_id retrieved from the merge arrays:\\n${ICyan}${AWS_SECRET_ACCESS_KEY}${Color_Off}\\n"

		# set AWS_DEFAULT_OUTPUT and AWS_DEFAULT_REGION from the persisted values
		setSessionOutputAndRegion "${final_selection_ident}" "false"

		if [[ "$session_profile" == "true" ]]; then  # this is a persistent MFA profile (a subset of [[ "$mfa_token" == "" ]])

			AWS_SESSION_TOKEN="${merged_aws_session_token[${final_selection_idx}]}"
			[[ "$DEBUG" == "true" ]] && printf "\\n${Cyan}${On_Black}aws_session_token retrieved from the merge arrays:\\n${ICyan}${AWS_SESSION_TOKEN}${Color_Off}\\n"

			getSessionExpiry _ret "${final_selection_ident}"
			AWS_SESSION_EXPIRY="${_ret}"
			AWS_SESSION_TYPE="$final_selection_type"
		fi
	fi

	# OUTPUT SELECTED PROFILE/SESSION DETAILS -------------------------------------------------------------------------

	if [[ "$session_profile" == "true" ]]; then
		getRemaining session_expiration_datetime "$AWS_SESSION_EXPIRY" "datetime"
	fi

	printf "\\n\\n${BIWhite}${On_DGreen}                            * * * PROFILE DETAILS * * *                            ${Color_Off}\\n\\n"

	if [[ "$session_profile" == "true" ]]; then
		printf "${BIWhite}${On_Black}MFA profile name: '${final_selection_ident}'${Color_Off}\\n\\n"
	else
		printf "${BIWhite}${On_Black}Profile name '${final_selection_ident}'${Color_Off}\\n"
		printf "\\n${BIYellow}${On_Black}NOTE: This is not an MFA session!${Color_Off}\\n\\n"
	fi

	if [[ "$AWS_DEFAULT_REGION" != "unavailable" ]]; then

		printf "Region is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_REGION}${Color_Off}\\n"
	else
		printf "${BIRed}${On_Black}\
Region has not been defined.${Color_Off} Please set it, for example, like so:\\n\
  aws --profile \"${final_selection_ident}\" configure set region \"us-east-1\"\\n\\n"

	fi

	printf "Output format is set to: ${BIWhite}${On_Black}${AWS_DEFAULT_OUTPUT}${Color_Off}\\n\\n"

	if [[ "$mfa_token" != "" &&
		   "$persistent_MFA" == "false" ]] ||
		[[ "$interactive_persist" == "false" ]]; then  # persist was declined when offered after init

		# always export secrets when initialized
		# a new session and selected not to persist

		secrets_out="true"

	else  # otherwise ask the user (since the profile is now always persisted)

		# Display the persistent profile's envvar details for export?
		read -s -p "$(printf "${BIWhite}${On_Black}Do you want to export the selected profile's secrets to the environment?${Color_Off} - ${BIWhite}${On_Black}[Y]${Color_Off}/N ")" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]] ||
			[[ $REPLY == "" ]]; then

			secrets_out="true"
		else
			secrets_out="false"
		fi
		printf "\\n\\n"
	fi

	if [[ "$mfa_token" != "" &&
		  "$persistent_MFA" == "false" ]] ||
		[[ "$interactive_persist" == "false" ]]; then  # persist was declined when offered after init

		if [[ "$AWS_MFASESSION_INITIALIZED" == "true" ]]; then
			session_word="MFA"
		else
			session_word="ROLE"
		fi

		printf "${BIWhite}${On_Black}\
*** THIS IS A NON-PERSISTENT $session_word SESSION! ${BIYellow}${On_Black}THE $session_word SESSION ACCESS KEY ID,\\n\
    SECRET ACCESS KEY, AND THE SESSION TOKEN ARE *ONLY* SHOWN BELOW!\\n\
    NOTE THAT YOU CAN *NOT* REFER TO THIS PROFILE WITH ${BIWhite}--profile${BIYellow} SWITCH!${Color_Off}\\n"

	fi

	printf "\\n${BIWhite}${On_Black}THE ACTIVATION COMMANDS FOR THE SELECTED PROFILE:${Color_Off}\\n\\n"

	maclinux_adhoc_remove="env "
	maclinux_adhoc_add=""

	maclinux_exporter=""
	wincmd_exporter=""
	powershell_exporter=""
	sql_exporter=""
	NL=$'\n'

	if [[ "$secrets_out" == "false" ]]; then

		if [[ "$final_selection_ident" == "default" ]]; then

			# default profile requires no environment
			# selector to be effective
			printf "unset AWS_PROFILE\\n"
			printf "unset AWS_DEFAULT_PROFILE\\n"

			maclinux_exporter+="unset AWS_PROFILE; unset AWS_DEFAULT_PROFILE; "

			maclinux_adhoc_remove+="-u AWS_PROFILE -u AWS_DEFAULT_PROFILE "

		elif [[ "$final_selection_ident" != "default" ]]; then

			# selector must be exported for all non-default
			# profiles when the secrets are not exported
			printf "export AWS_PROFILE=\"${final_selection_ident}\"\\n"
			printf "export AWS_DEFAULT_PROFILE=\"${final_selection_ident}\"\\n"

			maclinux_exporter+="export AWS_PROFILE=\"${final_selection_ident}\"; export AWS_DEFAULT_PROFILE=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_PROFILE=\"${final_selection_ident}\" AWS_DEFAULT_PROFILE=\"${final_selection_ident}\" "
		fi

		printf "unset AWS_PROFILE_IDENT\\n"
		printf "unset AWS_ACCESS_KEY_ID\\n"
		printf "unset AWS_SECRET_ACCESS_KEY\\n"
		printf "unset AWS_DEFAULT_OUTPUT\\n"
		printf "unset AWS_DEFAULT_REGION\\n"
		printf "unset AWS_SESSION_EXPIRY\\n"
		printf "unset AWS_SESSION_IDENT\\n"
		printf "unset AWS_SESSION_TOKEN\\n"
		printf "unset AWS_SESSION_TYPE\\n"

		maclinux_exporter+="unset AWS_PROFILE_IDENT; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_DEFAULT_OUTPUT; unset AWS_DEFAULT_REGION; unset AWS_SESSION_EXPIRY; unset AWS_SESSION_IDENT; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE"

		maclinux_adhoc_remove+="-u AWS_PROFILE_IDENT -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_DEFAULT_OUTPUT -u AWS_DEFAULT_REGION -u AWS_SESSION_EXPIRY -u AWS_SESSION_IDENT -u AWS_SESSION_TOKEN -u AWS_SESSION_TYPE "

	else  # exporting the secrets

		# we'll never export AWS_PROFILE/AWS_DEFAULT_PROFILE when the secrets
		# are exported to the environment; also note that AWS_PROFILE/
		# AWS_DEFAULT_PROFILE are *never exported to PowerShell or to Windows
		# CMD output, as those environments are not expected to have
		# preconfigured profiles (if AWS_PROFILE/AWS_DEFAULT_PROFILE are
		# present w/o an existing corresponding profile, the request will fail)

		if [[ "$session_profile" == "true" ]]; then

			printf "export AWS_SESSION_IDENT=\"${final_selection_ident}\"\\n"

			maclinux_exporter+="export AWS_SESSION_IDENT=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_SESSION_IDENT=\"${final_selection_ident}\" "

		else
			printf "export AWS_PROFILE_IDENT=\"${final_selection_ident}\"\\n"

			maclinux_exporter+="export AWS_PROFILE_IDENT=\"${final_selection_ident}\"; "

			maclinux_adhoc_add+="AWS_PROFILE_IDENT=\"${final_selection_ident}\" "

		fi

		printf "export AWS_ACCESS_KEY_ID=\"${BIWhite}${On_Black}${AWS_ACCESS_KEY_ID}${Color_Off}\"\\n"
		printf "export AWS_SECRET_ACCESS_KEY=\"${BIWhite}${On_Black}${AWS_SECRET_ACCESS_KEY}${Color_Off}\"\\n"
		printf "export AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\"\\n"
		printf "export AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\"\\n"

		maclinux_exporter+="export AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; export AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; export AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\"; export AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\"; "
		sql_exporter+="ACCESS_KEY_ID '${AWS_ACCESS_KEY_ID}'${NL}SECRET_ACCESS_KEY '${AWS_SECRET_ACCESS_KEY}'${NL}"

		maclinux_adhoc_add+="AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\" AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\" AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\" AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\" "

		if [[ "$session_profile" == "true" ]]; then

			printf "export AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\"\\n"
			printf "export AWS_SESSION_TOKEN=\"${BIWhite}${On_Black}${AWS_SESSION_TOKEN}${Color_Off}\"\\n"
			printf "export AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\"\n"
			printf "unset AWS_PROFILE_IDENT\\n"
			printf "unset AWS_DEFAULT_PROFILE\\n"
			printf "unset AWS_PROFILE\\n"

			maclinux_exporter+="export AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\"; export AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"; export AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\"; unset AWS_PROFILE; unset AWS_DEFAULT_PROFILE; unset AWS_PROFILE_IDENT"
			sql_exporter+="SESSION_TOKEN '${AWS_SESSION_TOKEN}'${NL}"

			maclinux_adhoc_remove+="-u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_PROFILE_IDENT "
			maclinux_adhoc_add+="AWS_SESSION_EXPIRY=\"${AWS_SESSION_EXPIRY}\" AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\" AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\""
		else
			printf "unset AWS_SESSION_EXPIRY\\n"
			printf "unset AWS_SESSION_IDENT\\n"
			printf "unset AWS_SESSION_TOKEN\\n"
			printf "unset AWS_SESSION_TYPE\\n"
			printf "unset AWS_DEFAULT_PROFILE\\n"
			printf "unset AWS_PROFILE\\n"

			maclinux_exporter+="unset AWS_SESSION_EXPIRY; unset AWS_SESSION_IDENT; unset AWS_SESSION_TOKEN; unset AWS_SESSION_TYPE; unset AWS_PROFILE; unset AWS_DEFAULT_PROFILE"

			maclinux_adhoc_remove+="-u AWS_SESSION_EXPIRY -u AWS_SESSION_IDENT -u AWS_SESSION_TOKEN -u AWS_SESSION_TYPE -u AWS_PROFILE -u AWS_DEFAULT_PROFILE"
		fi
	fi

	maclinux_adhoc_exporter="${maclinux_adhoc_remove} ${maclinux_adhoc_add}"

	# Windows command prompt and PowerShell are not expected to have
	# configured profiles so a complete profile w/secrets is always exported
	if [[ "$session_profile" == "false" ]]; then

		wincmd_exporter+="set AWS_PROFILE=&&set AWS_DEFAULT_PROFILE=&&set AWS_SESSION_EXPIRY=&&set AWS_SESSION_IDENT=&&set AWS_SESSION_TOKEN=&&set AWS_SESSION_TYPE=&&set AWS_PROFILE_IDENT=${final_selection_ident}&&"
		powershell_exporter+="\$env:AWS_PROFILE=\"\"; \$env:AWS_DEFAULT_PROFILE=\"\"; \$env:AWS_SESSION_EXPIRY=\"\"; \$env:AWS_SESSION_IDENT=\"\"; \$env:AWS_SESSION_TOKEN=\"\"; \$env:AWS_SESSION_TYPE=\"\"; \$env:AWS_PROFILE_IDENT=\"${final_selection_ident}\"; "
	else  # session
		wincmd_exporter+="set AWS_PROFILE=&&set AWS_DEFAULT_PROFILE=&&set AWS_PROFILE_IDENT=&&set AWS_SESSION_EXPIRY=${session_expiration_datetime}&&set AWS_SESSION_IDENT=${final_selection_ident}&&set AWS_SESSION_TYPE=${AWS_SESSION_TYPE}&&set AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}&&"
		powershell_exporter+="\$env:AWS_PROFILE=\"\"; \$env:AWS_DEFAULT_PROFILE=\"\"; \$env:AWS_PROFILE_IDENT=\"\"; \$env:AWS_SESSION_EXPIRY=\"${session_expiration_datetime}\"; \$env:AWS_SESSION_IDENT=\"${final_selection_ident}\"; \$env:AWS_SESSION_TYPE=\"${AWS_SESSION_TYPE}\"; \$env:AWS_SESSION_TOKEN=\"${AWS_SESSION_TOKEN}\"; "
	fi

	wincmd_exporter+="set AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}&&set AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}&&set AWS_DEFAULT_OUTPUT=${AWS_DEFAULT_OUTPUT}&&set AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}"
	powershell_exporter+="\$env:AWS_ACCESS_KEY_ID=\"${AWS_ACCESS_KEY_ID}\"; \$env:AWS_SECRET_ACCESS_KEY=\"${AWS_SECRET_ACCESS_KEY}\"; \$env:AWS_DEFAULT_OUTPUT=\"${AWS_DEFAULT_OUTPUT}\"; \$env:AWS_DEFAULT_REGION=\"${AWS_DEFAULT_REGION}\""

	# DISPLAY THE ACTIVATION STRINGS ----------------------------------------------------------------------------------

	if [[ "$OS" == "macOS" ]] ||
		[[ "$OS" =~ Linux$ ]]; then

		if [[ "$session_profile" == "true" ]]; then
			session_word="session"
		else
			session_word="profile"
		fi

		# is the selection persisted?
		idxLookup persisted_idx merged_ident[@] "$final_selection_ident"

		# make sure we're looking at *this* instantiation
		# of the mfa/role session (the previous instance
		# may have been persisted and this not)
		if [[ "$persistent_MFA" == "true" ]] ||
			[[ "$persisted_idx" != "" &&
			   "${merged_aws_access_key_id[$persisted_idx]}" == "${AWS_ACCESS_KEY_ID}" ]]; then

			printf "\\n${BIWhite}${On_Black}\
To use this selected ${session_word} temporarily (to bypass the currently effective profile for a single aws command\\n\
without modifying the environment permanently) you can use ${BIYellow}--profile '${final_selection_ident}'${BIWhite} switch with your\\n\
aws command, or prefix your command with the following prefix string in the bash shell (macOS, Linux, WSL Linux):${Color_Off}\\n\\n"
			printf "$maclinux_adhoc_exporter ${BIWhite}${On_Black}{your aws command here}${Color_Off}\\n"
		else
			printf "\\n${BIWhite}${On_Black}\
Note that because you chose not to persist this session, ${BIYellow}you cannot refer to it with the '--profile' parameter,${BIWhite}\\n\
however, you can use this selected session temporarily (to bypass the currently effective profile for a single aws command\\n\
without modifying the environment permanently) by prefixing your command with the following prefix string in the bash shell\\n\
(macOS, Linux, WSL Linux):${Color_Off}\\n\\n"
			printf "$maclinux_adhoc_exporter ${BIWhite}${On_Black}{your aws command here}${Color_Off}\\n"
		fi

		printf "\\n${BIWhite}${On_Black}\
To use this ${session_word} in a SQL query (such as for COPY/UNLOAD), simply include the following lines in your query.${Color_Off}\\n\\n"
		printf "$sql_exporter\\n"

		printf "\\n${BIYellow}${On_Black}\
To export this selected profile permanently for the current bash shell (macOS, Linux, WSL Linux)\\n\
SIMPLY PASTE THE FOLLOWING AT PROMPT AND HIT [ENTER]:${Color_Off}\\n\\n"
		printf "${Yellow}${On_Black}$maclinux_exporter${Color_Off}\\n"

		if [[ "$OS" == "WSL_Linux" ]]; then

			printf "\\n${BICyan}${On_Black}\
Since you're using Windows bash shell (\"WSL bash\"), the exports for Windows Powershell and\\n\
Windows Command Prompt are also provided. Simply paste one of the following activation strings\\n\
into the respective environment and hit [Enter] to activate the profile/session in that environment:${Color_Off}\\n\\n"

			printf "${BICyan}${On_Black}Windows Powershell:${Color_Off}\\n\\n"
			printf "${Cyan}${On_Black}$powershell_exporter${Color_Off}\\n"

			printf "\\n${BICyan}${On_Black}Windows Command Prompt:${Color_Off}\\n\\n"
			printf "${Cyan}${On_Black}$wincmd_exporter${Color_Off}\\n\\n"
		fi

		printf "\\n${BIRed}${On_Black}\
*** YOUR SELECTED PROFILE IS NOT EFFECTIVE UNTIL YOU ACTIVATE IT AS INSTRUCTED ABOVE! ***${Color_Off}\\n\\n"

	# COPY ACTIVATION PROFILE TO THE CLIPBOARD ------------------------------------------------------------------------

		if [[ "$OS" == "Linux" ]] &&
			exists xclip; then

			printf "xclip found. "
			xclip_present="true"
		else
			xclip_present="false"
		fi

		if [[ "$OS" == "macOS" ]] ||
			[[ "$OS" == "Linux" &&
			   "$xclip_present" == "true" ]]; then

			export_this=""
			printf "Which activation string do you want on your clipboard for easy pasting?\\n"
			read -s -p "$(printf "Export for the current [B]ash environment, get an [A]d-hoc command prefix,\\nget a [S]QL query string, or [D]o not copy? ${BIWhite}${On_Black}[B]${Color_Off}/A/S/D ")" -n 1 -r
			printf "\\n"
			if [[ $REPLY =~ ^[Bb]$ ]] ||
				[[ $REPLY == "" ]]; then

				export_this="$maclinux_exporter"
				export_string="export string for the Bash environment"

			elif [[ $REPLY =~ ^[Aa]$ ]]; then

				export_this="$maclinux_adhoc_exporter"
				export_string="Ad-hoc command prefix string"

			elif [[ $REPLY =~ ^[Ss]$ ]]; then

				export_this="$sql_exporter"
				export_string="SQL query string"

			else
				printf "\\n${BIBlue}${On_Black}Nothing copied to the clipboard${Color_Off}\\n\\n"
			fi

			# the actual export
			if [[ "$export_this" != "" ]]; then

				if [[ "$OS" == "macOS" ]]; then

					printf "%s" "$export_this" | pbcopy

				elif [[ "$OS" == "Linux" ]]; then

					# export to all xclip clipboards for easy
					# access no matter which clipboard is in use
					printf "%s" "$export_this" | xclip -i
					xclip -o | xclip -sel clipboard
					xclip -o | xclip -sel primary
					xclip -o | xclip -sel secondary
				fi

				printf "\\n${BIGreen}${On_Black}The $export_string has been copied on your clipboard.${Color_Off}\\n"
				if [[ ! "$REPLY" =~ ^[Ss]$ ]]; then
					printf "Now paste it at the prompt!\\n"
				fi
			fi

		elif [[ "$OS" == "Linux" &&
				"$xclip_present" == "false" ]]; then

			printf "\
NOTE: If you're using an X GUI on Linux, install 'xclip' to have\\n\
      the activation string copied to the clipboard automatically!\\n"

		fi
	fi

	if [[ "$OS" == "WSL_Linux" ]]; then

		printf "\
Which activation string do you want on your clipboard for easy pasting?\\n\
Note that the clipboard is shared between WSL bash and Windows otherwise.\\n"
		read -s -p "$(printf "Export for the current [B]ash shell, [P]owerShell, Windows [C]ommand Prompt;\\nget an [A]d-hoc command prefix (for bash), [S]QL query string, or [D]o not copy? ${BIWhite}${On_Black}[B]${Color_Off}/P/C/A/D ")" -n 1 -r
		printf "\\n"

		export_this=""
		if [[ $REPLY =~ ^[Bb]$ ]] ||
			[[ $REPLY == "" ]]; then

			export_this="$maclinux_exporter"
			export_string="export string for the WSL Bash environment"

		elif [[ $REPLY =~ ^[Pp]$ ]]; then

			export_this="$powershell_exporter"
			export_string="export string for the PowerShell environment"

		elif [[ $REPLY =~ ^[Cc]$ ]]; then

			export_this="$wincmd_exporter"
			export_string="export string for the Windows Command Prompt environment"

		elif [[ $REPLY =~ ^[Aa]$ ]]; then

			export_this="$maclinux_adhoc_exporter"
			export_string="Ad-hoc command prefix string"

		elif [[ $REPLY =~ ^[Ss]$ ]]; then

			export_this="$sql_exporter"
			export_string="SQL query string"

		else
			# do not export (exit)
			printf "\\n${BIBlue}${On_Black}Nothing copied to the clipboard${Color_Off}\\n\\n"
		fi

		# the actual export
		if [[ "$export_this" != "" ]]; then

			printf "%s" "${export_this}" | clip.exe

			printf "\\n${BIGreen}${On_Black}The $export_string has been copied on your clipboard.${Color_Off}\\nNow paste it at the prompt!\\n"
		fi
	fi
	printf "\\n"
fi
