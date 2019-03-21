#!/usr/bin/env bash

################################################################################
# RELEASE: 21 March 2019 - MIT license
# script version 2.6.0 beta
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

# enable monochrome mode with '-m' or '--monochrome' command line argument..
[[ "$1" == "-m" || "$1" == "--monochrome" ]] && SOURCEPARAM_monochrome="true" || SOURCEPARAM_monochrome="false"

# COLOR DEFINITIONS ===================================================================================================

if [[ "$SOURCEPARAM_monochrome" == "false" ]]; then

	SOURCEPARAM_Color_Off='\033[0m'       # Color reset
	SOURCEPARAM_BIGreen='\033[1;92m'      # Green
	SOURCEPARAM_BIWhite='\033[1;97m'      # White
	SOURCEPARAM_BIYellow='\033[1;93m'     # Yellow
	SOURCEPARAM_On_Black='\033[40m'       # Black
	SOURCEPARAM_Yellow='\033[0;33m'       # Yellow

else  # SOURCEPARAM_monochrome == "true"

	# Reset
	SOURCEPARAM_Color_Off=''    # Color reset
	SOURCEPARAM_Yellow=''       # Yellow
	SOURCEPARAM_On_Black=''     # Black
	SOURCEPARAM_BIGreen=''      # Green
	SOURCEPARAM_BIYellow=''     # Yellow
	SOURCEPARAM_BIWhite=''      # White

fi

# enable zsh support
[[ -n $ZSH_VERSION ]] && setopt BASH_REMATCH

if [[ "$0" == "$BASH_SOURCE" ]]; then

	printf "\\n${SOURCEPARAM_BIYellow}${SOURCEPARAM_On_Black}\
You must source this script to clear the AWS environment variables, like so:\\n\
\\n\
${SOURCEPARAM_BIWhite}source ./source-to-clear-AWS-envvars.sh${SOURCEPARAM_Color_Off}\\n\\n\\n"

	exit 1
fi

printf "\\n"

SOURCEPARAM_present_aws_envvars=()

if [[ "$(env | grep '^AWS_PROFILE[[:space:]]*=.')" != "" ]]; then 
	SOURCEPARAM_present_aws_envvars+=('AWS_PROFILE')
fi

if [[ "$(env | grep '^AWS_DEFAULT_PROFILE[[:space:]]*=.')" != "" ]]; then 
	SOURCEPARAM_present_aws_envvars+=('AWS_DEFAULT_PROFILE')
fi

if [[ "$(env | grep '^AWS_PROFILE_IDENT[[:space:]]*=.*')" != "" ]]; then 
	SOURCEPARAM_present_aws_envvars+=('AWS_PROFILE_IDENT')
fi

if [[ "$(env | grep '^AWS_SESSION_IDENT[[:space:]]*=.*')" != "" ]]; then 
	SOURCEPARAM_present_aws_envvars+=('AWS_SESSION_IDENT')
fi

if [[ "$(env | grep '^AWS_ACCESS_KEY_ID[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_ACCESS_KEY_ID')
fi

if [[ "$(env | grep '^AWS_SECRET_ACCESS_KEY[[:space:]]*=.*')" != "" ]]; then 
	SOURCEPARAM_present_aws_envvars+=('AWS_SECRET_ACCESS_KEY')
fi

if [[ "$(env | grep '^AWS_SESSION_TOKEN[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_SESSION_TOKEN')
fi

if [[ "$(env | grep '^AWS_SESSION_TYPE[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_SESSION_TYPE')
fi

if [[ "$(env | grep '^AWS_SESSION_EXPIRY[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_SESSION_EXPIRY')
fi

if [[ "$(env | grep '^AWS_DEFAULT_REGION[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_DEFAULT_REGION')
fi

if [[ "$(env | grep '^AWS_DEFAULT_OUTPUT[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_DEFAULT_OUTPUT')
fi

if [[ "$(env | grep '^AWS_CA_BUNDLE[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_CA_BUNDLE')
fi

if [[ "$(env | grep '^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_METADATA_SERVICE_TIMEOUT')
fi

if [[ "$(env | grep '^AWS_METADATA_SERVICE_NUM_ATTEMPTS[[:space:]]*=.*')" != "" ]]; then
	SOURCEPARAM_present_aws_envvars+=('AWS_METADATA_SERVICE_NUM_ATTEMPTS')
fi

SOURCEPARAM_aws_config_file=""
SOURCEPARAM_aws_shared_credentials_file=""

if [[ "$(env | grep '^AWS_CONFIG_FILE[[:space:]]*=.*')" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
	if [[ -n $ZSH_VERSION ]]; then
		SOURCEPARAM_aws_config_file="${BASH_REMATCH[2]}"
	else
		SOURCEPARAM_aws_config_file="${BASH_REMATCH[1]}"
	fi

	if [[ $SOURCEPARAM_aws_config_file != "" ]] &&
		[[ ! -f "$SOURCEPARAM_aws_config_file" ]]; then

		# file does not exist; clear the filevar
		SOURCEPARAM_aws_config_file=""

		# defined file does not exist; remove the envvar
		SOURCEPARAM_present_aws_envvars+=('AWS_CONFIG_FILE')
	fi
fi

if [[ "$(env | grep '^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=.*')" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
	if [[ -n $ZSH_VERSION ]]; then
		SOURCEPARAM_aws_shared_credentials_file="${BASH_REMATCH[2]}"
	else
		SOURCEPARAM_aws_shared_credentials_file="${BASH_REMATCH[1]}"
	fi

	if [[ $SOURCEPARAM_aws_shared_credentials_file != "" ]] &&
		[[ ! -f "$SOURCEPARAM_aws_shared_credentials_file" ]]; then

		# file does not exist; clear the filevar
		SOURCEPARAM_aws_shared_credentials_file=""

		# defined file does not exist; remove the envvar
		SOURCEPARAM_present_aws_envvars+=('AWS_SHARED_CREDENTIALS_FILE')	
	fi
fi

if [[ "${#SOURCEPARAM_present_aws_envvars[@]}" -gt 0 ]]; then

	printf "${SOURCEPARAM_BIGreen}${SOURCEPARAM_On_Black}The following AWS_ envvars are present:${SOURCEPARAM_Color_Off}\\n\\n"

	for ((i=0; i<=${#SOURCEPARAM_present_aws_envvars[@]}; i++))
	do
		SOURCEPARAM_this_aws_envvar="$(env | grep "^${SOURCEPARAM_present_aws_envvars[$i]}[[:space:]]*=.*$")"

		if [[ $SOURCEPARAM_this_aws_envvar =~ ^(${SOURCEPARAM_present_aws_envvars[$i]})[[:space:]]*=[[:space:]]*(.*)$ ]]; then
			if [[ -n $ZSH_VERSION ]]; then
				printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}${BASH_REMATCH[2]}${SOURCEPARAM_Color_Off}=${BASH_REMATCH[3]}\\n"
			else
				printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}${BASH_REMATCH[1]}${SOURCEPARAM_Color_Off}=${BASH_REMATCH[2]}\\n"
			fi
		fi
	done

	if [[ "$SOURCEPARAM_aws_config_file" != "" ]]; then
		printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}AWS_CONFIG_FILE${SOURCEPARAM_Color_Off}=${SOURCEPARAM_aws_config_file} ${SOURCEPARAM_Yellow}${SOURCEPARAM_On_Black}(file exists; envvar will not be unset)${SOURCEPARAM_Color_Off}\\n"
	fi

	if [[ "$SOURCEPARAM_aws_shared_credentials_file" != "" ]]; then
		printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}AWS_SHARED_CREDENTIALS_FILE${SOURCEPARAM_Color_Off}=${SOURCEPARAM_aws_shared_credentials_file} ${SOURCEPARAM_Yellow}${SOURCEPARAM_On_Black}(file exists; envvar will not be unset)${SOURCEPARAM_Color_Off}\\n"
	fi

	printf "\\n${SOURCEPARAM_BIYellow}${SOURCEPARAM_On_Black}Do you want to clear them? Y/N ${SOURCEPARAM_Color_Off}"

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	SOURCEPARAM_yesNo_result="$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )"
	stty "$old_stty_cfg"

	if printf "$SOURCEPARAM_yesNo_result" | grep -iq "^y" ; then

		for ((i=0; i<=${#SOURCEPARAM_present_aws_envvars[@]}; i++))
		do
			if [[ ${SOURCEPARAM_present_aws_envvars[$i]} != "" ]]; then
				unset "${SOURCEPARAM_present_aws_envvars[$i]}"
			fi
		done

		printf "\\n${SOURCEPARAM_BIGreen}${SOURCEPARAM_On_Black}AWS environment variables cleared.${SOURCEPARAM_Color_Off}\\n"
	fi
fi

if [[ "$SOURCEPARAM_aws_config_file" != "" ]] ||
	[[ "$SOURCEPARAM_aws_shared_credentials_file" != "" ]]; then

	SOURCEPARAM_display_aws_filevars="false"

	if [[ "${#SOURCEPARAM_present_aws_envvars[@]}" -eq 0 ]]; then

		SOURCEPARAM_display_aws_filevars="true"
		printf "${SOURCEPARAM_BIGreen}${SOURCEPARAM_On_Black}\
The following AWS_ envvars are present:${SOURCEPARAM_Color_Off}\\n\
(These are *not* unset by this script)\\n\\n"

	elif printf "$SOURCEPARAM_yesNo_result" | grep -iq "^y" ; then

		SOURCEPARAM_display_aws_filevars="true"
		printf "${SOURCEPARAM_BIYellow}${SOURCEPARAM_On_Black}\\n\
NOTE: The following AWS envvar(s) were not unset!${SOURCEPARAM_Color_Off}\\n\\n"
	fi

	if [[ "$SOURCEPARAM_aws_config_file" != "" ]] &&
		[[ "$SOURCEPARAM_display_aws_filevars" == "true" ]]; then

		printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}\
AWS_CONFIG_FILE${SOURCEPARAM_Color_Off}=${SOURCEPARAM_aws_config_file}\\n\
  To unset, execute manually: ${SOURCEPARAM_Yellow}${SOURCEPARAM_On_Black}unset AWS_CONFIG_FILE${SOURCEPARAM_Color_Off}\\n\\n"
	fi

	if [[ "$SOURCEPARAM_aws_shared_credentials_file" != "" ]] &&
		[[ "$SOURCEPARAM_display_aws_filevars" == "true" ]]; then

		printf "${SOURCEPARAM_BIWhite}${SOURCEPARAM_On_Black}\
AWS_SHARED_CREDENTIALS_FILE${SOURCEPARAM_Color_Off}=${SOURCEPARAM_aws_shared_credentials_file}\\n\
  To unset, execute manually: ${SOURCEPARAM_Yellow}${SOURCEPARAM_On_Black}unset AWS_SHARED_CREDENTIALS_FILE${SOURCEPARAM_Color_Off}\\n\\n"
	fi

	if [[ "${#SOURCEPARAM_present_aws_envvars[@]}" -eq 0 ]]; then
		printf "No other AWS envvars are present.\\n"
	fi
fi

if [[ "${#SOURCEPARAM_present_aws_envvars[@]}" -eq 0 ]] &&
	[[ "$SOURCEPARAM_aws_config_file" == "" ]] &&
	[[ "$SOURCEPARAM_aws_shared_credentials_file" == "" ]]; then

		printf "No AWS envvars are present; nothing was unset.\\n"
fi

printf "\\n"

unset SOURCEPARAM_Yellow
unset SOURCEPARAM_BIGreen
unset SOURCEPARAM_BIWhite
unset SOURCEPARAM_BIYellow
unset SOURCEPARAM_On_Black
unset SOURCEPARAM_Color_Off
unset SOURCEPARAM_monochrome
unset SOURCEPARAM_yesNo_result
unset SOURCEPARAM_this_aws_envvar
unset SOURCEPARAM_present_aws_envvars
unset SOURCEPARAM_display_aws_filevars
unset SOURCEPARAM_aws_config_file
unset SOURCEPARAM_aws_shared_credentials_file
