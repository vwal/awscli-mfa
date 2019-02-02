#!/usr/bin/env bash

################################################################################
# RELEASE 2 February 2019 - MIT license
# script version 2.3.0
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

disabled_envvars=()

if [[ "$(env | grep AWS_PROFILE)" != "" ]]; then 
	disabled_envvars+=('AWS_PROFILE')
	unset AWS_PROFILE
fi

if [[ "$(env | grep AWS_PROFILE_IDENT)" != "" ]]; then 
	disabled_envvars+=('AWS_PROFILE_IDENT')
	unset AWS_PROFILE_IDENT
fi

if [[ "$(env | grep AWS_SESSION_IDENT)" != "" ]]; then 
	disabled_envvars+=('AWS_SESSION_IDENT')
	unset AWS_SESSION_IDENT
fi

if [[ "$(env | grep AWS_ACCESS_KEY_ID)" != "" ]]; then
	disabled_envvars+=('AWS_ACCESS_KEY_ID')
	unset AWS_ACCESS_KEY_ID
fi

if [[ "$(env | grep AWS_SECRET_ACCESS_KEY)" != "" ]]; then 
	disabled_envvars+=('AWS_SECRET_ACCESS_KEY')
	unset AWS_SECRET_ACCESS_KEY
fi

if [[ "$(env | grep AWS_SESSION_TOKEN)" != "" ]]; then
	disabled_envvars+=('AWS_SESSION_TOKEN')
	unset AWS_SESSION_TOKEN
fi

if [[ "$(env | grep AWS_SESSION_TYPE)" != "" ]]; then
	disabled_envvars+=('AWS_SESSION_TYPE')
	unset AWS_SESSION_TYPE
fi

if [[ "$(env | grep AWS_SESSION_EXPIRY)" != "" ]]; then
	disabled_envvars+=('AWS_SESSION_EXPIRY')
	unset AWS_SESSION_EXPIRY
fi

if [[ "$(env | grep AWS_DEFAULT_REGION)" != "" ]]; then
	disabled_envvars+=('AWS_DEFAULT_REGION')
	unset AWS_DEFAULT_REGION
fi

if [[ "$(env | grep AWS_DEFAULT_OUTPUT)" != "" ]]; then
	disabled_envvars+=('AWS_DEFAULT_OUTPUT')
	unset AWS_DEFAULT_OUTPUT
fi

if [[ "$(env | grep AWS_CA_BUNDLE)" != "" ]]; then
	disabled_envvars+=('AWS_CA_BUNDLE')
	unset AWS_CA_BUNDLE
fi

if [[ "$(env | grep AWS_METADATA_SERVICE_TIMEOUT)" != "" ]]; then
	disabled_envvars+=('AWS_METADATA_SERVICE_TIMEOUT')
	unset AWS_METADATA_SERVICE_TIMEOUT
fi

if [[ "$(env | grep AWS_METADATA_SERVICE_NUM_ATTEMPTS)" != "" ]]; then
	disabled_envvars+=('AWS_METADATA_SERVICE_NUM_ATTEMPTS')
	unset AWS_METADATA_SERVICE_NUM_ATTEMPTS
fi

aws_config_file=""
aws_shared_credentials_file=""

if [[ "$(env | grep AWS_CONFIG_FILE)" =~ ^(AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*.*)$ ]]; then
	aws_config_file="${BASH_REMATCH[1]}"
fi

if [[ "$(env | grep AWS_SHARED_CREDENTIALS_FILE)" =~ ^(AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*.*)$ ]]; then
	aws_shared_credentials_file="${BASH_REMATCH[1]}"
fi

if [[ "${#disabled_envvars[@]}" -gt 0 ]]; then

	echo -e "${BIGreen}${On_Black}AWS envvars that were unset:${Color_Off}"

	for ((itr=0; itr<${#disabled_envvars[@]}; ++itr))
	do
		echo -e "${Green}${On_Black}   ${disabled_envvars[$itr]}${Color_Off}"
	done

	echo
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

if [[ "${#disabled_envvars[@]}" -eq 0 ]] &&
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
unset disabled_envvars
unset aws_config_file
unset aws_shared_credentials_file
