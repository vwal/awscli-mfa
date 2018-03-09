#!/usr/bin/env bash

# todo: detect AWS_* envvars in the environment and offer to copy the purge command
# 		to the clipboard before proceeding (otherwise executing as the selected profile
# 		which may or may not be active is using a session variable)

# todo: store the session init times if there is no other way to obtain
#       the remaining session length.


DEBUG="false"
# uncomment below to enable the debug output
#DEBUG="true"

# Set the session length in seconds below;
# note that this only sets the client-side
# validity of the MFA session token; 
# the maximum length of a valid session
# is enforced in the IAM policy, and
# is unaffected by this value.
#
# The minimum valid session length
# is 900 seconds.
MFA_SESSION_LENGTH_IN_SECONDS=900

# defined the standard location of the AWS credentials file
CREDFILE=~/.aws/credentials

## FUNCTIONS

# workaround function for lack of 
# macOS bash's assoc arrays
idxLookup() {
	# $1 is _ret (returns the index)
	# $2 is the array
	# $3 is the item to be looked up in the array

	declare -a arr=("${!2}")
	local key=$3
 	local result=""

 	maxIndex=${#arr[@]}
 	((maxIndex--))

	for (( i=0; i<=${maxIndex}; i++ ))
	do 
		if [[ "${arr[$i]}" == "$key" ]]; then
			result=$i
			break
		fi
	done

	eval "$1=$result"
}


## PREREQUISITES CHECK

# `exists` for commands
exists() {
	command -v "$1" >/dev/null 2>&1
}

# is AWS CLI installed?
if ! exists aws ; then
	printf "\n******************************************************************************************************************************\n\
This script requires the AWS CLI. See the details here: http://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html\n\
******************************************************************************************************************************\n\n"
	exit 1
fi 

# check for ~/.aws directory, and ~/.aws/{config|credentials} files
if [ ! -d ~/.aws ]; then
	echo
	echo -e "'~/.aws' directory not present.\nMake sure it exists, and that you have at least one profile configured\nusing the 'config' and 'credentials' files within that directory."
	echo
	exit 1
fi

if [[ ! -f ~/.aws/config && ! -f ~/.aws/credentials ]]; then
	echo
	echo -e "'~/.aws/config' and '~/.aws/credentials' files not present.\nMake sure they exist. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
elif [ ! -f ~/.aws/config ]; then
	echo
	echo -e "'~/.aws/config' file not present.\nMake sure it and '~/.aws/credentials' files exists. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
elif [ ! -f ~/.aws/credentials ]; then
	echo
	echo -e "'~/.aws/credentials' file not present.\nMake sure it and '~/.aws/config' files exists. See http://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html for details on how to set them up."
	echo
	exit 1
fi

# read the credentials file and make sure that at least one profile is configured
ONEPROFILE="false"
while IFS='' read -r line || [[ -n "$line" ]]; do
	[[ "$line" =~ ^\[(.*)\].* ]] &&
		profile_ident=${BASH_REMATCH[1]}

		if [ $profile_ident != "" ]; then
			ONEPROFILE="true"
		fi 
done < $CREDFILE

if [[ "$ONEPROFILE" == "false" ]]; then
	echo
	echo -e "NO CONFIGURED AWS PROFILES FOUND.\nPlease make sure you have '~/.aws/config' (profile configurations),\nand '~/.aws/credentials' (profile credentials) files, and at least\none configured profile. For more info, see AWS CLI documentation at:\nhttp://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html"
	echo

else

	# get default region and output format
	# (since at least one profile should exist at this point, and one should be selected)
	default_region=$(aws --profile default configure get region)
	default_output=$(aws --profile default configure get output)

	if [[ "$default_region" == "" ]]; then
		echo
		echo -e "DEFAULT REGION HAS NOT BEEN CONFIGURED.\nPlease set the default region in '~/.aws/config', for example, like so:\naws configure set region \"us-east-1\""
		echo
		exit 1
	fi

	if [[ "$default_output" == "" ]]; then
		aws configure set output "table"
	fi

	# Check OS for some supported platforms
	OS="`uname`"
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
			echo "** NOTE: THIS SCRIPT HAS NOT BEEN TESTED ON YOUR CURRENT PLATFORM."
			echo
			;;
	esac

	# make sure ~/.aws/credentials has a linefeed in the end
	c=$(tail -c 1 "$CREDFILE")
	if [ "$c" != "" ]; then
		echo "" >> "$CREDFILE"
	fi

	## PREREQS PASSED; PROCEED..

	# define profiles arrays
	declare -a profiles_ident
	declare -a profiles_type
	declare -a profiles_key_id
	declare -a profiles_secret_key
	declare -a profiles_session_token
	declare -a profiles_session_init_time
	profiles_iterator=0
	profiles_init=0

	# ugly hack to relate different values because 
	# macOS *still* does not provide bash 4.x by default,
	# so associative arrays aren't available
	while IFS='' read -r line || [[ -n "$line" ]]; do
		if [[ "$line" =~ ^\[(.*)\].* ]]; then
			_ret=${BASH_REMATCH[1]}

			if [[ $profiles_init -eq 0 ]]; then
				profiles_ident[$profiles_iterator]=$_ret
				profiles_init=1
			fi

			if [[ "$_ret" != "" ]] &&
				! [[ "$_ret" =~ -mfasession$ ]]; then

				profiles_type[$profiles_iterator]='profile'
			else
				profiles_type[$profiles_iterator]='session'
			fi

			if [[ "${profiles_ident[$profiles_iterator]}" != "$_ret" ]]; then
				((profiles_iterator++))
				profiles_ident[$profiles_iterator]=$_ret
			fi
		fi

		[[ "$line" =~ ^aws_access_key_id[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_key_id[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^aws_secret_access_key[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_secret_key[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^aws_session_token[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_session_token[$profiles_iterator]="${BASH_REMATCH[1]}"

		[[ "$line" =~ ^session_init_time[[:space:]]*=[[:space:]]*(.*)$ ]] &&
			profiles_session_init_time[$profiles_iterator]="${BASH_REMATCH[1]}"

	done < $CREDFILE

	echo
	current_aws_access_key_id="$(aws configure get aws_access_key_id)"

	idxLookup idx profiles_key_id[@] $current_aws_access_key_id
	if [[ $idx != "" ]]; then 
		currently_selected_profile_ident="${profiles_ident[$idx]}"
	else
		currently_selected_profile_ident="unknown"
	fi

	# todo: if the time is expired & env exists, prompt here for purging!

	process_user_arn="$(aws sts get-caller-identity --output text --query 'Arn' 2>&1)"
	[[ "$process_user_arn" =~ ([^/]+)$ ]] &&
		process_username="${BASH_REMATCH[1]}"
	if [[ "$process_username" =~ error ]] ||
		[[ "$currently_selected_profile_ident" == "unknown" ]]; then
		echo "Default/selected profile is not functional; the script may not work as expected."
		echo "Check the Default profile in your '~/.aws/credentials' file, as well as any 'AWS_' environment variables!"
	else
		echo "Executing this script as the AWS/IAM user \"$process_username\" (profile \"$currently_selected_profile_ident\")."
	fi
	echo

	# declare the arrays
	declare -a cred_profiles
	declare -a cred_profile_status
	declare -a cred_profile_user
	declare -a cred_profile_arn
	declare -a profile_region
	declare -a profile_output
	declare -a mfa_profiles
	declare -a mfa_arns
	declare -a mfa_profile_status
	cred_profilecounter=0

	echo -n "Please wait"

	# read the credentials file
	while IFS='' read -r line || [[ -n "$line" ]]; do
		[[ "$line" =~ ^\[(.*)\].* ]] &&
		profile_ident=${BASH_REMATCH[1]}

		# only process if profile identifier is present,
		# and if it's not a mfasession profile 
		# (mfasession profiles have '-mfasession' postfix)
		if [[ "$profile_ident" != "" ]] &&
			! [[ "$profile_ident" =~ -mfasession$ ]]; then

			# store this profile ident
			cred_profiles[$cred_profilecounter]=$profile_ident

			# store this profile region and output format
			profile_region[$cred_profilecounter]=$(aws --profile $profile_ident configure get region)
			profile_output[$cred_profilecounter]=$(aws --profile $profile_ident configure get output)

			# get the user ARN; this should be always
			# available for valid profiles
			user_arn="$(aws sts get-caller-identity --profile $profile_ident --output text --query 'Arn' 2>&1)"
			if [[ "$user_arn" =~ ^arn:aws ]]; then
				cred_profile_arn[$cred_profilecounter]=$user_arn
			else
				# must be a bad profile
				cred_profile_arn[$cred_profilecounter]=""
			fi

			# get the actual username
			# (may be different from the arbitrary profile ident)
			[[ "$user_arn" =~ ([^/]+)$ ]] &&
				profile_username="${BASH_REMATCH[1]}"
			if [[ "$profile_username" =~ error ]]; then
				cred_profile_user[$cred_profilecounter]=""
			else
				cred_profile_user[$cred_profilecounter]="$profile_username"
			fi

			# find the existing MFA sessions for the current profile
			# (profile with profilename + "-mfasession" postfix)
			while IFS='' read -r line || [[ -n "$line" ]]; do
				[[ "$line" =~ \[(${profile_ident}-mfasession)\]$ ]] &&
				mfa_profile_ident="${BASH_REMATCH[1]}"
			done < $CREDFILE
			mfa_profiles[$cred_profilecounter]="$mfa_profile_ident"

			# check to see if this profile has access currently
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set, this should produce
			# a reliable result)
			profile_check="$(aws iam get-user --output text --query "User.Arn" --profile $profile_ident 2>&1)"
			if [[ "$profile_check" =~ ^arn:aws ]]; then
				cred_profile_status[$cred_profilecounter]="OK"
			else
				cred_profile_status[$cred_profilecounter]="LIMITED"
			fi

			# get MFA ARN if available
			# (obviously not available if a MFA device
			# isn't configured for the profile)
			mfa_arn="$(aws iam list-mfa-devices --profile $profile_ident --user-name ${cred_profile_user[$cred_profilecounter]} --output text --query "MFADevices[].SerialNumber" 2>&1)"
			if [[ "$mfa_arn" =~ ^arn:aws ]]; then
				mfa_arns[$cred_profilecounter]="$mfa_arn"
			else
				mfa_arns[$cred_profilecounter]=""
			fi

			# if existing MFA profile was found, check its status
			# (this is not 100% as it depends on the defined IAM access;
			# however if MFA enforcement is set, this should produce
			# a reliable result)
			if [ "$mfa_profile_ident" != "" ]; then
				mfa_profile_check="$(aws iam get-user --output text --query "User.Arn" --profile $mfa_profile_ident 2>&1)"
				if [[ "$mfa_profile_check" =~ ^arn:aws ]]; then
					mfa_profile_status[$cred_profilecounter]="OK"
				elif [[ "$mfa_profile_check" =~ ExpiredToken ]]; then
					mfa_profile_status[$cred_profilecounter]="EXPIRED"
				else
					mfa_profile_status[$cred_profilecounter]="LIMITED"
				fi
			fi

			## DEBUG (enable with DEBUG="true" on top of the file)
			if [ "$DEBUG" == "true" ]; then

				echo "PROFILE IDENT: $profile_ident (${cred_profile_status[$cred_profilecounter]})"
				echo "USER ARN: ${cred_profile_arn[$cred_profilecounter]}"
				echo "USER NAME: ${cred_profile_user[$cred_profilecounter]}"
				echo "MFA ARN: ${mfa_arns[$cred_profilecounter]}"
				if [ "${mfa_profiles[$cred_profilecounter]}" == "" ]; then
					echo "MFA PROFILE IDENT:"
				else
					echo "MFA PROFILE IDENT: ${mfa_profiles[$cred_profilecounter]} (${mfa_profile_status[$cred_profilecounter]})"
				fi
				echo
			## END DEBUG
			else
				echo -n "."
			fi

			# erase variables & increase iterator for the next iteration
			mfa_arn=""
			user_arn=""
			profile_ident=""
			profile_check=""
			profile_username=""
			mfa_profile_ident=""
			mfa_profile_check=""

			cred_profilecounter=$(($cred_profilecounter+1))

		fi
	done < $CREDFILE

	# create the profile selections
	echo
	echo
	echo "AVAILABLE AWS PROFILES:"
	echo
	SELECTR=0
	ITER=1
	for i in "${cred_profiles[@]}"
	do
		if [ "${mfa_arns[$SELECTR]}" != "" ]; then
			mfa_notify=", MFA configured"
		else
			mfa_notify="" 
		fi

		echo "${ITER}: $i (${cred_profile_user[$SELECTR]}${mfa_notify})"

		if [[ "${mfa_profile_status[$SELECTR]}" == "OK" ]] ||
			[[ "${mfa_profile_status[$SELECTR]}" == "LIMITED" ]]; then
			echo "${ITER}m: $i MFA profile in ${mfa_profile_status[$SELECTR]} status"
		fi

		echo
		let ITER=${ITER}+1
		let SELECTR=${SELECTR}+1
	done

	# this is used to determine whether to trigger a MFA request for a MFA profile
	active_mfa="false"

	# this is used to determine whether to print MFA questions/details
	mfaprofile="false"

	# prompt for profile selection
	printf "SELECT A PROFILE BY THE ID: "
	read -r selprofile

	# process the selection
	if [[ "$selprofile" != "" ]]; then
		# capture the numeric part of the selection
		[[ $selprofile =~ ^([[:digit:]]+) ]] &&
			selprofile_check="${BASH_REMATCH[1]}"
		if [[ "$selprofile_check" != "" ]]; then

			# if the numeric selection was found, 
			# translate it to the array index and validate
			let actual_selprofile=${selprofile_check}-1

			profilecount=${#cred_profiles[@]}
			if [[ $actual_selprofile -ge $profilecount ||
				$actual_selprofile -lt 0 ]]; then
				# a selection outside of the existing range was specified
				echo "There is no profile '${selprofile}'."
				echo
				exit 1
			fi

			# was an existing MFA profile selected?
			[[ $selprofile =~ ^[[:digit:]]+(m)$ ]] &&
				selprofile_mfa_check="${BASH_REMATCH[1]}"

			# if this is an MFA profile, it must be in OK or LIMITED status to select
			if [[ "$selprofile_mfa_check" != "" &&
				( "${mfa_profile_status[$actual_selprofile]}" == "OK" ||
				"${mfa_profile_status[$actual_selprofile]}" == "LIMITED" ) ]]; then

				# get the parent profile name
				# transpose selection (starting from 1) to array index (starting from 0)
				mfa_parent_profile_ident="${cred_profiles[$actual_selprofile]}"

				final_selection="${mfa_profiles[$actual_selprofile]}"
				echo "SELECTED MFA PROFILE: ${final_selection} (for base profile '${mfa_parent_profile_ident}')"

				# this is used to determine whether to print MFA questions/details
				mfaprofile="true"

				# this is used to determine whether to trigger a MFA request for a MFA profile
				active_mfa="true"

			elif [[ "$selprofile_mfa_check" != "" &&
				"${mfa_profile_status[$actual_selprofile]}" == "" ]]; then
				# mfa ('m') profile was selected for a profile that no mfa profile exists
				echo "There is no profile '${selprofile}'."
				echo
				exit 1

			else
				# a base profile was selected
				if [[ $selprofile =~ ^[[:digit:]]+$ ]]; then 
					echo "SELECTED PROFILE: ${cred_profiles[$actual_selprofile]}"
					final_selection="${cred_profiles[$actual_selprofile]}"
				else
					# non-acceptable characters were present in the selection
					echo "There is no profile '${selprofile}'."
					echo
					exit 1
				fi
			fi

		else
			# no numeric part in selection
			echo "There is no profile '${selprofile}'."
			echo
			exit 1
		fi
	else
		# empty selection
		echo "There is no profile '${selprofile}'."
		echo
		exit 1
	fi

	# this is an MFA request (an MFA ARN exists but the MFA is not active)
	if [[ "${mfa_arns[$actual_selprofile]}" != "" &&
		"$active_mfa" == "false" ]]; then

		# prompt for the MFA code
		echo
		echo -e "Enter the current MFA one time pass code for profile '${cred_profiles[$actual_selprofile]}' to start/renew the MFA session,"
		echo "or leave empty (just press [ENTER]) to use the selected profile without the MFA."
		
		while :
		do
			read mfacode
			if ! [[ "$mfacode" =~ ^$ || "$mfacode" =~ [0-9]{6} ]]; then
				echo "The MFA code must be exactly six digits, or blank to bypass."
				continue
			else
				break
			fi
		done

	elif [[ "$active_mfa" == "false" ]]; then   # no MFA configured (no MFA ARN); print a notice
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"

		# reset entered MFA code (just to be safe)
		mfacode=""
		echo
		echo -e "MFA has not been set up for this profile."
	fi

	if [[ "$mfacode" != "" ]]; then
		# init an MFA session (request an MFA session token)
		AWS_USER_PROFILE=${cred_profiles[$actual_selprofile]}
		AWS_2AUTH_PROFILE=${AWS_USER_PROFILE}-mfasession
		ARN_OF_MFA=${mfa_arns[$actual_selprofile]}
		MFA_TOKEN_CODE=$mfacode
		DURATION=$MFA_SESSION_LENGTH_IN_SECONDS

		echo "NOW GETTING THE MFA SESSION TOKEN FOR THE PROFILE: $AWS_USER_PROFILE"

		read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< \
		$( aws --profile $AWS_USER_PROFILE sts get-session-token \
		  --duration $DURATION \
		  --serial-number $ARN_OF_MFA \
		  --token-code $MFA_TOKEN_CODE \
		  --output text  | awk '{ print $2, $4, $5 }')

		if [ -z "$AWS_ACCESS_KEY_ID" ]; then
			echo
			echo "Could not initialize the requested MFA session."
			echo
			exit 1
		else
			# this is used to determine whether to print MFA questions/details
			mfaprofile="true"

			## DEBUG
			if [ "$DEBUG" == "true" ]; then
				echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
				echo "AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
				echo "AWS_SESSION_TOKEN: $AWS_SESSION_TOKEN"
			fi
			## END DEBUG

			# set the temp aws_access_key_id, aws_secret_access_key, and aws_session_token for the MFA profile
			`aws --profile $AWS_2AUTH_PROFILE configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"`
			`aws --profile $AWS_2AUTH_PROFILE configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"`
			`aws --profile $AWS_2AUTH_PROFILE configure set aws_session_token "$AWS_SESSION_TOKEN"`

			# Make sure the final selection profile name has '-mfasession' suffix
			# (it's not present when going from a base profile to an MFA profile)
			if ! [[ "$final_selection" =~ -mfasession$ ]]; then
				final_selection="${final_selection}-mfasession"
			fi
		fi

	elif [[ "$active_mfa" == "false" ]]; then
		
		# this is used to determine whether to print MFA questions/details
		mfaprofile="false"
	fi

	# get region and output format for the selected profile
	get_region=$(aws --profile $final_selection configure get region)
	get_output=$(aws --profile $final_selection configure get output)

	# If the region and output format have not been set for this profile, set them 
	# For the parent/base profiles, use defaults; for MFA profiles use first the base/parent settings if present, then the defaults
	if [[ "${get_region}" == "" ]]; then
		# retrieve parent profile region if an MFA profie
		if [[ "${profile_region[$actual_selprofile]}" != "" &&
			  "${mfaprofile}" == "true" ]]; then
			set_new_region=${profile_region[$actual_selprofile]}
			echo "Region had not been configured for the selected MFA profile; it has been set to same as the parent profile ('$set_new_region')."
		fi
		if [[ "${set_new_region}" == "" ]]; then
			set_new_region=${default_region}
			echo "Region had not been configured for the selected profile; it has been set to the default region ('${default_region}')."
		fi

		get_region="${set_new_region}" 
		`aws --profile $final_selection configure set region "${set_new_region}"`
	fi

	if [ "${get_output}" == "" ]; then
		# retrieve parent profile output format if an MFA profile
		if [[ "${profile_output[$actual_selprofile]}" != "" &&
			"${mfaprofile}" == "true" ]]; then
			set_new_output=${profile_output[$actual_selprofile]}
			echo "Output format had not been configured for the selected MFA profile; it has been set to same as the parent profile ('$set_new_output')."
		fi
		if [[ "${set_new_output}" == "" ]]; then
			set_new_output=${default_output}
			echo "Output format had not been configured for the selected profile; it has been set to the default output format ('${default_output}')."
		fi

		get_output="${set_new_output}"
		`aws --profile $final_selection configure set output "${set_new_output}"`
	fi

	AWS_ACCESS_KEY_ID=$(aws --profile $final_selection configure get aws_access_key_id)
	AWS_SECRET_ACCESS_KEY=$(aws --profile $final_selection configure get aws_secret_access_key)
	AWS_SESSION_TOKEN=$(aws --profile $final_selection configure get aws_session_token)

	echo
	echo "========================================================================"
	echo
	if [[ "$mfaprofile" == "true" ]]; then
		echo "MFA profile name: '${final_selection}'"
		echo
	else
		echo "Profile name '${final_selection}'"
		echo "** NOTE: This is not an MFA session!"
		echo 
	fi
	echo "Region is set to: $get_region"
	echo "Output format is set to: $get_output"
	echo

	# print env export secrets?
	secrets_out="false"
	read -p "Do you want to export the selected profile's secrets to the environment (for s3cmd, etc)? - y[N] " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		secrets_out="true"
	fi
	echo
	echo

	if [[ "$OS" == "macOS" ]]; then

		echo "Execute the following in Terminal to activate the selected profile"
		echo "(it's already on your clipboard; just paste it and press [ENTER]):"
		echo
		echo "export AWS_PROFILE=${final_selection}"

		if [[ "$secrets_out" == "false" ]]; then
			echo "unset AWS_ACCESS_KEY_ID"
			echo "unset AWS_SECRET_ACCESS_KEY"
			echo "unset AWS_SESSION_TOKEN"
			echo -n "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN" | pbcopy
		else
			echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
			echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
			if [[ "$mfaprofile" == "true" ]]; then
				echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}" | pbcopy
			else
				echo "unset AWS_SESSION_TOKEN"
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; unset AWS_SESSION_TOKEN" | pbcopy
				echo
			fi
		fi
		echo
		echo "NOTE: Make sure to set/unset the environment with the new values as instructed above to make sure no conflicting profile/secret remains in the envrionment!"
		echo
		echo -e "To conveniently remove any AWS profile/secret information from the environment, simply source the attached script, like so:\n'source ./source-to-clear-AWS-envvars.sh'"
		echo

	elif [ "$OS" == "Linux" ]; then
		echo "Execute the following on the command line to activate this profile for the 'aws', 's3cmd', etc. commands."
		echo "NOTE: Even if you only use a named profile ('AWS_PROFILE'), it's important to execute all of the export/unset"
		echo "      commands to make sure previously set environment variables won't override the selected configuration."
		echo
		echo "export AWS_PROFILE=${final_selection}"
		echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
		echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
		if [[ "$mfaprofile" == "true" ]]; then
			echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
			if exists xclip ; then
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}" | xclip -i
				echo "(xclip found; the activation command is now on your X PRIMARY clipboard -- just paste on the command line, and press [ENTER])"
			fi
		else
			echo "unset AWS_SESSION_TOKEN"
			if exists xclip ; then
				echo -n "export AWS_PROFILE=${final_selection}; export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}; export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}; unset AWS_SESSION_TOKEN" | xclip -i
				echo "(xclip found; the activation command is now on your X PRIMARY clipboard -- just paste on the command line, and press [ENTER])"
			fi
		fi
		if ! exists xclip ; then
			echo
			echo "If you're using an X GUI on Linux, install 'xclip' to have the activation command copied to the clipboard automatically."
		fi
		echo
		echo ".. or execute the following to use named profile only, clearning any previoiusly set configuration variables:"
		echo
		echo "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN"
		echo
		echo -e "To conveniently remove any AWS profile/secret information from the environment, simply source the attached script, like so:\n'source ./source-to-clear-AWS-envvars.sh'"
		echo

	else  # not macOS, not Linux, so some other weird OS like Windows..
		echo "Execute the following on the command line to activate this profile for the 'aws', 's3cmd', etc. commands."
		echo "NOTE: Even if you only use a named profile ('AWS_PROFILE'), it's important to execute all of the export/unset"
		echo "      commands to make sure previously set environment variables won't override the selected configuration."
		echo
		echo "export AWS_PROFILE=${final_selection} \\"
		echo "export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \\"
		echo "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \\"
		if [[ "$mfaprofile" == "true" ]]; then
			echo "export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}"
		else
			echo "unset AWS_SESSION_TOKEN"
		fi
		echo
		echo "..or execute the following to use named profile only, clearning any previoiusly set configuration variables:"
		echo
		echo "export AWS_PROFILE=${final_selection}; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN"
		echo
		echo -e "To conveniently remove any AWS profile/secret information from the environment, simply source the attached script, like so:\nsource ./source-to-clear-AWS-envvars.sh"
		echo

	fi
	echo

fi
