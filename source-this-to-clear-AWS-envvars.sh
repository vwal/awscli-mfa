#!/usr/bin/env bash

################################################################################
# RELEASE: 10 February 2019 - MIT license
# script version 2.4.2
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
[[ "$1" == "-m" || "$1" == "--monochrome" ]] && monochrome="true" || monochrome="false"

# COLOR DEFINITIONS ===================================================================================================

if [[ "$monochrome" == "false" ]]; then

	Color_Off='\033[0m'       # Color reset
	BIGreen='\033[1;92m'      # Green
	BIWhite='\033[1;97m'      # White
	BIYellow='\033[1;93m'     # Yellow
	On_Black='\033[40m'       # Black
	Yellow='\033[0;33m'       # Yellow

else  # monochrome == "true"

	# Reset
	Color_Off=''    # Color reset
	Yellow=''       # Yellow
	On_Black=''     # Black
	BIGreen=''      # Green
	BIYellow=''     # Yellow
	BIWhite=''      # White

fi

# enable zsh support
[[ -n $ZSH_VERSION ]] && setopt BASH_REMATCH

# 'exists' for commands
exists() {
	# $1 is the command being checked

	[[ "$DEBUG" == "true" ]] && echo -e "\\n${BIYellow}${On_Black}[function exists] command: ${1}${Color_Off}"

	# returns a boolean
	command -v "$1" >/dev/null 2>&1
}

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

if [[ "$0" == "$BASH_SOURCE" ]]; then

	echo -e "\\n${BIYellow}${On_Black}\
You must source this script to clear the AWS environment variables, like so:\\n\
\\n\
${BIWhite}source ./source-to-clear-AWS-envvars.sh${Color_Off}\\n\\n"

	exit 1
fi

echo

present_aws_envvars=()

if [[ "$(env | grep '^AWS_PROFILE[[:space:]]*=.')" != "" ]]; then 
	present_aws_envvars+=('AWS_PROFILE')
fi

if [[ "$(env | grep '^AWS_PROFILE_IDENT[[:space:]]*=.*')" != "" ]]; then 
	present_aws_envvars+=('AWS_PROFILE_IDENT')
fi

if [[ "$(env | grep '^AWS_SESSION_IDENT[[:space:]]*=.*')" != "" ]]; then 
	present_aws_envvars+=('AWS_SESSION_IDENT')
fi

if [[ "$(env | grep '^AWS_ACCESS_KEY_ID[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_ACCESS_KEY_ID')
fi

if [[ "$(env | grep '^AWS_SECRET_ACCESS_KEY[[:space:]]*=.*')" != "" ]]; then 
	present_aws_envvars+=('AWS_SECRET_ACCESS_KEY')
fi

if [[ "$(env | grep '^AWS_SESSION_TOKEN[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_TOKEN')
fi

if [[ "$(env | grep '^AWS_SESSION_TYPE[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_TYPE')
fi

if [[ "$(env | grep '^AWS_SESSION_EXPIRY[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_SESSION_EXPIRY')
fi

if [[ "$(env | grep '^AWS_DEFAULT_REGION[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_DEFAULT_REGION')
fi

if [[ "$(env | grep '^AWS_DEFAULT_OUTPUT[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_DEFAULT_OUTPUT')
fi

if [[ "$(env | grep '^AWS_CA_BUNDLE[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_CA_BUNDLE')
fi

if [[ "$(env | grep '^AWS_METADATA_SERVICE_TIMEOUT[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_METADATA_SERVICE_TIMEOUT')
fi

if [[ "$(env | grep '^AWS_METADATA_SERVICE_NUM_ATTEMPTS[[:space:]]*=.*')" != "" ]]; then
	present_aws_envvars+=('AWS_METADATA_SERVICE_NUM_ATTEMPTS')
fi

aws_config_file=""
aws_shared_credentials_file=""

if [[ "$(env | grep '^AWS_CONFIG_FILE[[:space:]]*=.*')" =~ ^AWS_CONFIG_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
	aws_config_file="${BASH_REMATCH[2]}"

	if [[ $aws_config_file != "" ]] &&
		[[ ! -f "$aws_config_file" ]]; then

		# file does not exist; clear the filevar
		aws_config_file=""

		# defined file does not exist; remove the envvar
		present_aws_envvars+=('AWS_CONFIG_FILE')
	fi
fi

if [[ "$(env | grep '^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=.*')" =~ ^AWS_SHARED_CREDENTIALS_FILE[[:space:]]*=[[:space:]]*(.*)$ ]]; then
	aws_shared_credentials_file="${BASH_REMATCH[2]}"

	if [[ $aws_shared_credentials_file != "" ]] &&
		[[ ! -f "$aws_shared_credentials_file" ]]; then

		# file does not exist; clear the filevar
		aws_shared_credentials_file=""

		# defined file does not exist; remove the envvar
		present_aws_envvars+=('AWS_SHARED_CREDENTIALS_FILE')	
	fi
fi

if [[ "${#present_aws_envvars[@]}" -gt 0 ]]; then

	echo -e "${BIGreen}${On_Black}The following AWS_ envvars are present:${Color_Off}\\n"

	for ((i=0; i<=${#present_aws_envvars[@]}; i++))
	do
		this_aws_envvar="$(env | grep "^${present_aws_envvars[$i]}[[:space:]]*=.*$")"

		if [[ $this_aws_envvar =~ ^(${present_aws_envvars[$i]})[[:space:]]*=[[:space:]]*(.*)$ ]]; then
			if [[ "$OS" != "WSL_Linux" ]]; then
				echo -e "${BIWhite}${On_Black}${BASH_REMATCH[2]}${Color_Off}=${BASH_REMATCH[3]}"
			else
				echo -e "${BIWhite}${On_Black}${BASH_REMATCH[1]}${Color_Off}=${BASH_REMATCH[2]}"
			fi
		fi
	done

	if [[ "$aws_config_file" != "" ]]; then
		echo -e "${BIWhite}${On_Black}AWS_CONFIG_FILE${Color_Off}=${aws_config_file} ${Yellow}${On_Black}(file exists; envvar will not be unset)${Color_Off}"
	fi

	if [[ "$aws_shared_credentials_file" != "" ]]; then
		echo -e "${BIWhite}${On_Black}AWS_SHARED_CREDENTIALS_FILE${Color_Off}=${aws_shared_credentials_file} ${Yellow}${On_Black}(file exists; envvar will not be unset)${Color_Off}"
	fi

	echo -en "\\n${BIYellow}${On_Black}Do you want to clear them? Y/N ${Color_Off}"

	old_stty_cfg="$(stty -g)"
	stty raw -echo
	yesNo_result="$( while ! head -c 1 | grep -i '[yn]' ;do true ;done )"
	stty "$old_stty_cfg"

	if echo "$yesNo_result" | grep -iq "^y" ; then

		for ((i=0; i<=${#present_aws_envvars[@]}; i++))
		do
			if [[ ${present_aws_envvars[$i]} != "" ]]; then
				unset "${present_aws_envvars[$i]}"
			fi
		done

		echo -en "\\n${BIGreen}${On_Black}AWS environment variables cleared.${Color_Off}\\n"
	fi
fi

if [[ "$aws_config_file" != "" ]] ||
	[[ "$aws_shared_credentials_file" != "" ]]; then

	display_aws_filevars="false"

	if [[ "${#present_aws_envvars[@]}" -eq 0 ]]; then

		display_aws_filevars="true"
		echo -e "${BIGreen}${On_Black}\
The following AWS_ envvars are present:${Color_Off}\\n\
(These are *not* unset by this script)\\n"

	elif echo "$yesNo_result" | grep -iq "^y" ; then

		display_aws_filevars="true"
		echo -e "${BIYellow}${On_Black}\\n\
NOTE: The following AWS envvar(s) were not unset!${Color_Off}\\n"
	fi

	if [[ "$aws_config_file" != "" ]] &&
		[[ "$display_aws_filevars" == "true" ]]; then

		echo -e "${BIWhite}${On_Black}\
AWS_CONFIG_FILE${Color_Off}=${aws_config_file}\\n\
  To unset, execute manually: ${Yellow}${On_Black}unset AWS_CONFIG_FILE${Color_Off}\\n"
	fi

	if [[ "$aws_shared_credentials_file" != "" ]] &&
		[[ "$display_aws_filevars" == "true" ]]; then

		echo -e "${BIWhite}${On_Black}\
AWS_SHARED_CREDENTIALS_FILE${Color_Off}=${aws_shared_credentials_file}\\n\
  To unset, execute manually: ${Yellow}${On_Black}unset AWS_SHARED_CREDENTIALS_FILE${Color_Off}\\n"
	fi

	if [[ "${#present_aws_envvars[@]}" -eq 0 ]]; then
		echo -e "No other AWS envvars are present."
	fi
fi

if [[ "${#present_aws_envvars[@]}" -eq 0 ]] &&
	[[ "$aws_config_file" == "" ]] &&
	[[ "$aws_shared_credentials_file" == "" ]]; then

		echo -e "No AWS envvars are present; nothing was unset."
fi

echo

unset Yellow
unset BIGreen
unset BIWhite
unset BIYellow
unset On_Black
unset Color_Off
unset yesNo_result
unset this_aws_envvar
unset present_aws_envvars
unset display_aws_filevars
unset aws_config_file
unset aws_shared_credentials_file
