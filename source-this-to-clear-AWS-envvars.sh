#!/usr/bin/env bash

################################################################################
# RELEASE: 2 February 2019 - MIT license
# script version 2.3.1
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

# COLOR DEFINITIONS ===================================================================================================
Color_Off='\033[0m'       # Color reset
BIGreen='\033[1;92m'      # Green
BIRed='\033[1;91m'        # Red
BIWhite='\033[1;97m'      # White
BIYellow='\033[1;93m'     # Yellow
Green='\033[0;32m'        # Green
On_Black='\033[40m'       # Black
Red='\033[0;31m'          # Red
Yellow='\033[0;33m'       # Yellow

if [[ "$0" == "$BASH_SOURCE" ]]; then

	echo -e "\\n${BIYellow}${On_Black}\
You must source this script to clear the AWS environment variables, like so:\\n\
\\n\
${BIWhite}source ./source-to-clear-AWS-envvars.sh${Color_Off}\\n\\n"

	exit 1
fi

echo

present_aws_envvars=()

if [[ "$(env | grep AWS_PROFILE)" != "" ]]; then 
	present_aws_envvars+=('AWS_PROFILE')
fi

if [[ "$(env | grep AWS_PROFILE_IDENT)" != "" ]]; then 
	present_aws_envvars+=('AWS_PROFILE_IDENT')
fi

if [[ "$(env | grep AWS_SESSION_IDENT)" != "" ]]; then 
	present_aws_envvars+=('AWS_SESSION_IDENT')
fi

if [[ "$(env | grep AWS_ACCESS_KEY_ID)" != "" ]]; then
	present_aws_envvars+=('AWS_ACCESS_KEY_ID')
fi

if [[ "$(env | grep AWS_SECRET_ACCESS_KEY)" != "" ]]; then 
	present_aws_envvars+=('AWS_SECRET_ACCESS_KEY')
fi

if [[ "$(env | grep AWS_SESSION_TOKEN)" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_TOKEN')
fi

if [[ "$(env | grep AWS_SESSION_TYPE)" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_TYPE')
fi

if [[ "$(env | grep AWS_SESSION_EXPIRY)" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_EXPIRY')
fi

if [[ "$(env | grep AWS_DEFAULT_REGION)" != "" ]]; then
	present_aws_envvars+=('AWS_DEFAULT_REGION')
fi

if [[ "$(env | grep AWS_DEFAULT_OUTPUT)" != "" ]]; then
	present_aws_envvars+=('AWS_DEFAULT_OUTPUT')
fi

if [[ "$(env | grep AWS_CA_BUNDLE)" != "" ]]; then
	present_aws_envvars+=('AWS_CA_BUNDLE')
fi

if [[ "$(env | grep AWS_METADATA_SERVICE_TIMEOUT)" != "" ]]; then
	present_aws_envvars+=('AWS_METADATA_SERVICE_TIMEOUT')
fi

if [[ "$(env | grep AWS_METADATA_SERVICE_NUM_ATTEMPTS)" != "" ]]; then
	present_aws_envvars+=('AWS_METADATA_SERVICE_NUM_ATTEMPTS')
fi

aws_config_file=""
aws_shared_credentials_file=""

if [[ "$(env | grep AWS_CONFIG_FILE)" =~ ^(AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*.*)$ ]]; then
	aws_config_file="${BASH_REMATCH[1]}"
fi

if [[ "$(env | grep AWS_SHARED_CREDENTIALS_FILE)" =~ ^(AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*.*)$ ]]; then
	aws_shared_credentials_file="${BASH_REMATCH[1]}"
fi

if [[ "${#present_aws_envvars[@]}" -gt 0 ]]; then

	echo -e "${BIGreen}${On_Black}The following AWS_ envvars are present:${Color_Off}\\n"

	for ((i=0; i<=${#present_aws_envvars[@]}; i++))
	do
		if [[ ${present_aws_envvars[$i]} != "" ]]; then

			this_aws_envvar="$(env | grep ${present_aws_envvars[$i]})"

			if [[ $this_aws_envvar =~ ^(${present_aws_envvars[$i]})[[:space:]]*=[[:space:]]*(.*)$ ]]; then
				echo -e "${BIWhite}${On_Black}${BASH_REMATCH[2]}${Color_Off}=${BASH_REMATCH[3]}"
			fi
		fi
	done

	echo -en "\\n${BIYellow}${On_Black}Do you want to clear them? Y/N ${Color_Off}"

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	yesNo_result="$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )"
	stty "$old_stty_cfg"

	if echo "$yesNo_result" | grep -iq "^y" ; then

		for ((i=0; i<=${#present_aws_envvars[@]}; i++))
		do
			if [[ ${present_aws_envvars[$i]} != "" ]]; then
				unset ${present_aws_envvars[$i]}
			fi
		done

		echo -en "\\n${BIGreen}${On_Black}AWS environment variables cleared.${Color_Off}\\n"
	fi
fi

if [[ "$aws_config_file" != "" ]] ||
	[[ "$aws_shared_credentials_file" != "" ]]; then

	echo -e "${BIYellow}${On_Black}\\nThe following AWS envvar(s) were not unset!${Color_Off}\\n"

	if [[ "$aws_config_file" != "" ]]; then
		echo -e "${Yellow}${On_Black}   $aws_config_file${Color_Off}\\n\
     To unset, execute manually: ${BIWhite}${On_Black}unset AWS_CONFIG_FILE${Color_Off}\\n"
	fi

	if [[ "$aws_shared_credentials_file" != "" ]]; then
		echo -e "${Yellow}${On_Black}   $aws_shared_credentials_file${Color_Off}\\n\
     To unset, execute manually: ${BIWhite}${On_Black}unset AWS_SHARED_CREDENTIALS_FILE${Color_Off}\\n"
	fi
fi

if [[ "${#present_aws_envvars[@]}" -eq 0 ]] &&
	[[ "$aws_config_file" == "" ]] &&
	[[ "$aws_shared_credentials_file" == "" ]]; then

		echo -e "No AWS envvars were present; nothing was unset."
fi

echo

unset BIGreen
unset BIRed
unset BIWhite
unset BIYellow
unset Color_Off
unset Green
unset On_Black
unset Red
unset Yellow
unset yesNo_result
unset this_aws_envvar
unset present_aws_envvars
unset aws_config_file
unset aws_shared_credentials_file
