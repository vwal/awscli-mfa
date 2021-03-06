
# awscli-mfa.sh and its companion scripts

The `awscli-mfa.sh` and its companion scripts `enable-disable-vmfa-device.sh` and `source-this-to-clear-AWS-envvars.sh` were created to make handling multi-factor sessions with AWS command line interface easy. 

These scripts create a workflow to easily and quickly create/configure a virtual MFA device ("vMFAd" for short, an app which you run on your phone) for a profile, then start an MFA or a role session, and then monitor the remaining session validity period for any of the active sessions. You can have multiple concurrent active MFA or role sessions and easily switch between them and base and root profiles (where no MFA session is used/desired) simply by re-executing the `awscli-mfa.sh` script. If you choose to persist sessions so that the session details get written into your `config` and `credentials` files (it's the default operation when starting a new MFA session) you can then use the `--profile` switch with your `aws` CLI command to temporarily select another active session or base/role profile without re-running `awscli-mfa.sh`.

### Usage, quick!

1. __(Prerequisites)__ Make sure you have `aws` CLI command installed (version 1.16.0 or newer). AWS has details for [Mac](https://docs.aws.amazon.com/cli/latest/userguide/install-macos.html) and [Linux including Ubuntu on Windows Subsystem for Linux (WSL)](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html). Although not necessary, it is also recommended to have [jq command](https://stedolan.github.io/jq/) (version 1.5 or newer) installed. It's avilable via most package managers e.g., `brew install jq` on macOS, or `apt install jq` on Ubuntu.

2. __If you don't yet have your AWS command line profile(s) configured:__ Configure the first AWS profile using `aws configure` for the first/default profile, or `aws configure --profile "SomeDescriptiveProfileName"` for a additional named profiles. You can view the any existing profiles with `cat ~/.aws/config` and `cat ~/.aws/credentials`. For an overview of the AWS configuration files, check out their [documentation page](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html). Note that while you can also put the credentials information in the `config` file, `awscli-mfa.sh` always writes the persisted session credentials in the `credentials` file per AWS recommendations. Furthermore, if there are any overlapping credentials properties (i.e. `aws_access_key_id`, `aws_secret_access_key`, or `aws_session_token`) in the two files, the entries in the `credentials` file take precedence. Thus I recommend using the `config` file for the profile configuration properties and the `credentials` file for the profile credentials (this is also what `aws configure` does automatically).

3. If you have previously set up the vMFAd for the same IAM user via the AWS Web Console, you can skip this step. __However, if you don't yet have the virtual MFA device ("vMFAd") configured__, execute `enable-disable-vmfa-device.sh` to create and enable a vMFAd with a Google Authenticator compatible app such as my favorite, [Authy](https://authy.com/) ([Android](https://play.google.com/store/apps/details?id=com.authy.authy&hl=en_US), [iOS](https://itunes.apple.com/us/app/authy/id494168017)) on your portable device. You can also use Duo Security app for this purpose, but Authy is unique in that it allows backing up the token generators for easy restore when replacing or upgrading a phone. Follow the interactive directions from the script. Note that if you happen to be on Linux without a GUI, you'll have the option to initialize the vMFAd using the seed string.

4. Execute `awscli-mfa.sh` to start an MFA session using the vMFAd you just configured. Follow the interactive directions from the script. You have couple of command line options:<br/>`-q / --quick` - "quick mode", forgoes all the upfront profile status checks for quicker access to the profile list<br/>`-m / --monochrome` - turns off the color attributes from the output

5. If you need to switch between the configured base/root profiles and/or active MFA or role sessions, re-execute `awscli-mfa.sh` and follow its prompts. If you need to disable/detach (and possibly delete) a vMFAd from your IAM user account, re-execute `enable-disable-vmfa-device.sh` and follow its interactive guidance.<br/>This script also accepts the `-m / --monochrome` switch.

6. Once you have activated a session in your current shell environment and then want to discontinue it, you can override it with a different session, simply close the shell window/tab, or execute:<br/>`source ./source-this-to-clear-AWS-envvars.sh`<br/>This script also accepts the `-m / --monochrome` switch.

Keep reading for the features, rationale, and script-specific overview...

### awscli-mfa.sh Features

- Supports any number of configured base and root profiles.
- Supports any number of configured roles.
- Supports chained roles which can only be authenticated with another role's existing role session.
- Supports cross-account roles (i.e., roles which authorize a profile in one account to assume a role in another account).
- External ID is supported in the role confziguration.
- Script automatically queries the maximum role session length for each role profile when the user permissions allow the user to do so. When this query is not allowed (such as with cross-account roles), the user can set the session length separately for each profile by using the proprietary `sessmax` property in the `config` file. This is important especially in the cases where the allowed session maximum length is below 3600 seconds (1h) as _the role session requests with a longer session length than what the role's policy allows, fail.
- When neither the local sessmax or queryable session maximum are available, the session uses the role session default length which is set by default to 3600 seconds (1h) with `ROLE_SESSION_LENGTH_IN_SECONDS` variable on top of the script.
- The maximum session length and the MFA requirement for the cross-account roles can be advertised via AWS Systems Manager (SSM) Parameter Store of the authorized profile account. Because a profile located in account `A` can not be assumed to have access to `get-role` in account `B` which hosts the role to be assumed, the critical information of the maximum role length and MFA requirement can be made available for the frequently-assumed roles by adding the corresponding key-value pairs into SSM. This information is automatically consumed by this script if available. See the end of this document for details on how to manage this information.
- The default length of MFA sessions (not role sessions!) is set to 32400 seconds (9h) with `MFA_SESSION_LENGTH_IN_SECONDS` variable on top of the script. User can similarly override the MFA session length in each profile's configuration using the `sessmax` property. Unlike with the role sessions which don't allow a greater than maximum allowed session length to be defined, the MFA session length is only informative: if it is set to a longer value than what the policy allows, the session will still start but the remaining session length indicators don't show the correct value (i.e. the session stops working before the timer runs out). For this reason, the script queries an optional parameter (`/unencrypted/mfa/session_length`) in AWS Systems Manager (SSM) Parameter Store of the account the profile is in. If found, it will override the default and configured `sessmax` for that profile. This way the account administrator can advertise the maximum allowed session length (it should be set to the same value as is set in the `EnforceMFA` policy). The commands for managing the SSM parameter value are included at the end of this document. Note that the advertised value set in SSM parameter is not the enforced value; the enforced session length is defined by `aws:MultiFactorAuthAge` set in the policy files. 
- The script doesn't require the `default` profile to be present in case you prefer to always explicitly define the profile you want to use with the `aws` command. However, the script notifies the user about the absence of the `default` profile because if it is absent, you need to define `region` and the optional `output` format for each profile individually.
- When `region` and `output` properties have not been set for a profile, the script attempts to automatically inherit them, first from the MFA/role session's source baseprofile, and then from the `default` profile, if available. A baseprofile missing these values only inherits them from the `default` profile, if available.
- Validates the profiles when executed in the full mode (use `--full`/`-f` or give no option to activate as this is the default mode).
- Provides "quick mode" (use `--quick`/`-q` to activate) that forgoes the validity checks but brings up the menu much faster; this makes the utility a lot more convenient to use especially when you have lots of profiles configured and need to frequently jump between baseprofiles or active sessions. However, it's a good idea to execute the script in the "full mode" every once in a while, and especially whenever there have been any changes to your profiles/IAM accounts as the full mode persists some of its findings for reference in the quick mode.
- Written to be portable; the script is environment-aware and has been tested in macOS (with `bash` 3.2 - 5.0), Ubuntu/Debian, RedHat/CentOS, and Windows Subsystem for Linux ("WSL") with Ubuntu. The script is `bash`-native, but has also been tested with `zsh`.
- Provides the option to either persist a started MFA/role session into the `credentials` file, or to only export the session into the environment. When executed in the `bash`, the script also provides profile/session activation strings for Windows PowerShell and Windows Command Prompt.
- Provides an ad-hoc command prefix string for the selected profile (`bash` only) to execute individual commands with a given session.
- Provides `aws_access_key_id`. `aws_secret_access_key`, and `aws_session_token` output that can be directly embedded into SQL queries executed in AWS environments (e.g., for `COPY` and `UNLOAD` operations in Redshift).
- Automatically copies the selected activation string onto the clipboard; this is a built-in in macOS and in WSL `bash`; in the Linux Desktop distros (e.g., Ubuntu) `xclip` is required for the automatic copy-to-clipboard.
- The script validates the AWS configuration files for common configuration errors such as overlapping/duplicate properties, and provides guidance on how to fix them, including providing the source profile selection for the roles which don't have a source profile configured (in the full mode only).
- The script validates the baseprofiles and the MFA/role sessions (in the full mode only). When the script detects an invalid baseprofile or an invalid MFA/role session, it tags them as "invalid" both in the `config` and `credentials` files with the last detection time (provided in UTC). The `invalid_as_of = {date stamp}` pseudo-property makes it easier to detect and remove the invalid profiles when editing the configuration files.
- The remaining validity periods are displayed for all MFA and role sessions that were started with this script (both in the full and the quick mode).
- Checks the current state of the environment on startup; if a profile/session is detected in the environment, its status and details are displayed.
- Presents a simplified interface when only a single profile plus its possible MFA session are present.
- The only hard dependency is a recent version of the `aws` command. The script checks for the presence of `aws` and its version, and instructs the user to install/upgrade it if necessary. Additionally, in Linux, `coreutils` is required (and checked for), but it is generally part of the standard Linux installations.
- The only soft dependency is `jq`. The script works without it, but with `jq` present it works faster, especially when any role profiles are present. When `jq` is not detected, the script recommends it to be installed.

### Rationale

When the presence of a multi-factor authentication session is enforced with an IAM policy, the enforcement cannot be limited to the web console operations (nor should it, but that's a different topic). This is because the AWS web console is basically a front-end to the AWS APIs, i.e., the same ones which are also accessed using the `aws` CLI command. When you log in to the AWS web console and enter an MFA code, the browser takes care of caching the credentials and the session token, and so beyond that point, in the web browser, the MFA/role session is transparent to the user until the session eventually expires, and the AWS web console prompts the user to log in again. On the command line it's different. To create, enable, or disable a virtual MFA device ("vMFAd"), or to start an MFA or a role session, complex sequences of commands are required, followed by the need to painstakingly save the session token/credentials in the `~/.aws/credentials` file, and then to either refer to that session profile by using the `--profile {session profile name}` switch in each `aws` CLI command, or to add/modify/delete various `AWS_*` environment variables by cut-and-pasting at least the aws access key id, the aws secret access key, plus for the sessions the session token. Furthermore, the only way to know that a session has expired is that the `aws` CLI commands start failing, thus making it difficult to plan long-running command execution, and potentially being confusing as to why such failures should occur.

The `awscli-mfa.sh` and its companion scripts change all this by making use of the MFA sessions with `aws` CLI command a breeze! Let's first look at what each script does on the high level.

### Overview

These scripts provide significant interactive guidance as well as user-friendly failure information when something doesn't work as expected.

The scripts have been written for macOS (with stock bash 3.2.x, and homebrew-installed bash 4.4.x or 5.x) as well as with Linux (Ubuntu/Debian, RHEL/CentOS, and WSL Ubuntu). The only dependencies are `aws` itself (required) and `jq` (recommended but not required). The scripts will notify the user if `aws` is not present.

* **awscli-mfa.sh** - Makes it easy to start MFA/role sessions with `aws`, and to switch between active sessions and base profiles. Multiple profiles are supported, but if only a single profile is in use, a simplified user interface is presented. <br><br>This is an interactive script since it prompts for the current MFA one time pass code from the Google Authenticator/Authy app. The  accepted command line arguments are: `--quick`/`-q` for the quick mode, `--full` / `-f` for the full mode (same as no arguments), and `--debug` / `-d` which enables debug output (not very useful unless you're debugging the script's internals; note that the debug mode may print your AWS credentials on the screen).<br><br>When an MFA or a role session is started with this script, it automatically records the expiration time of the session, and names the session profile with the `-mfasession` (base profiles), or `-rolesession` (roles) postfix.

* **enable-disable-vmfa-device.sh** - Makes it easy to enable/attach and disable/detach (as well as to delete) a virtual MFA device ("vMFAd"). Assumes that each IAM user can have one vMFAd configured per AWS account at a time, and that the vMFAd is named the same as their IAM username (i.e. the serial number which is known as the ARN or "Amazon Resource Name" of the vMFAd is of the format `arn:aws:iam::{AWS_account_id}:mfa/{IAM_username}` when the IAM user ARN is of the format `arn:aws:iam::{AWS_account_id}:user/{IAM_username}`). Disabling a vMFAd requires usually an active MFA session with that profile. However, you can also use another profile that is authorized to detach a vMFAd. If you no longer have access to the vMFAd in your Google Authenticator or Authy app, you either need to have access to an AWS account which is authorized to detach vMFAd for other users and/or without an active MFA session. In the absence of such, contact the admin/ops with a request to delete the vMFAd off of your account so that you can create a new one.<br><br>As with `awscli-mfa.sh`, this script supports multiple configured profiles, but if only a single profile is in use, a simplified user interface is presented to either create/enable a vMFAd if none is present, or disable/deleted a vMFAd if one is active.<br><br>Also, like `awscli-mfa.sh`, this script supports macOS, Linux, and WSL `bash`. When executed on a Linux system without a GUI, you'll have the option to initialize the vMFA using the seed-string instead of scanning a QRcode image (this requires an app that allows manual seed-string entry; for example, [Authy](https://authy.com/) offers this feature).

* **source-this-to-clear-AWS-envvars.sh** - A simple sourceable script that removes any AWS secrets/settings that may have been set in the local environment by the `awscli-mfa.sh` script. Source it, like so: `source ./source-this-to-clear-AWS-envvars.sh`, or set an alias, like so: `alias clearaws='source ~/awscli-mfa/source-this-to-clear-AWS-envvars.sh'`. The AWS envvars that are used to define alternative configuration and credentials files (`AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`) are removed from the environment _only_ if the file(s) defined by them do not exist. This is because if you are using custom `config` and/or `credentials` file locations, you likely want to keep using them more continuously rather than from session-to-session.

* **example-mfa-policies** (a subdirectory) - If you're implementing MFA enforcement, this directory contains a carefully crafted example IAM policy, `EnforceMFA.txt`, for enforcing an active MFA session for `aws` command execution. The EnforceMFA example policy was inspired by (but significantly improved from) the example policies provided by [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html) and [Trek10](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/) (both of those policies had problems which have been resolved in this example policy). Note that when an MFA enforcement is enabled on the command line using this policy, it is also enabled for the web console login. Also note that the `awscli-mfa.sh` script uses the innocuous permission for `get-access-key-last-used` as an indicator of whether MFA enforcement is in effect (besides it being harmless information security-wise it also makes sense since it's only relevant if you're using the `aws` commmand-line command where you obviously have an API key assigned and thus "access key last used" is relevant).<br/>
The two other example policies found in the directory, `AllowMFA.txt` and `OpenMFA.txt`, are examples of policies to be used for the transition period from non-enforced to endforced (`AllowMFA`), and for automated, non-interactive processes (`OpenMFA`). The `AllowMFA` policy does not enforce the MFA use, but provides the user the permissions required to manage their IAM password and the vMFAd. The only restrictions it imposes are: the user is allowed to disable the vMFAd off of their IAM user only when they have an active MFA session (this is the cornerstone requirement for the MFA validity), and they cannot access resources outside their current account even if they otherwise have permission to do so without having an active MFA session. The `OpenMFA` also provides the permissions for the password and the vMFAd management (and requires an MFA session for disabling the vMFAd), but imposes no other MFA-based restrictions as it is intended to be used with automated operations.

### Commands for managing the account-specific MFA session maximum length parameter in AWS Secrets Manager Parameter Store

**This parameter (the session length in seconds) should be set to the same value as what is being enforced in the MFA IAM policies** (look for `aws:MultiFactorAuthAge` parameter in the example policies found in the `example-mfa-policies` folder). The below set/alter/delete examples assume that the IAM account you're using has the necessary privileges to edit the parameter. Also note that the parameter path, `/unencrypted/mfa/session_length` is hardcoded in the script. Since the MFA-session lenght is account specific, only one value can be defined per AWS account.

Note that since since the AWS Parameter Store Secrets Manager (SSM) is region-specific, the default as of script version `2.7.1` uses `us-east-1` as an aggregate region for advertising this information. You can change this by modifying the value for `MFA_SESSION_LENGTH_LOOKUP_REGION_OVERRIDE` variable found near the top of the `awscli-mfa.sh` script. If you blank out the variable, the region is taken from each baseprofile, and thus if your IAM accounts lie across multiple regions, you may need to distribute this information to multiple regions (hence an aggregate region should be used if possible).

__NOTE:__ Unless you modify the `MFA_SESSION_LENGTH_LOOKUP_REGION_OVERRIDE` variable in the script, you should always use `us-east-1` for region below.

To set the parameter (here setting the advertised maximum session length to 7200 seconds, or 2 hours):
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/mfa/session_length" --value "7200" --type String
```

To alter an existing parameter (setting the value to 10800 seconds, or 3 hours):
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/mfa/session_length" --value "10800" --type String --overwrite
```

To check the current value the parameter is set to, if present:
```
aws --profile "{profile}" --region {region} ssm get-parameter --name "/unencrypted/mfa/session_length" --query "Parameter.Value" --output text
```

To delete the parameter:
```
aws --profile "{profile}" --region {region} ssm delete-parameter --name "/unencrypted/mfa/session_length"
```

### Commands for managing the cross-account role details in AWS Secrets Manager Parameter Store of the account hosting the profile authorized to assume the cross-account roles elsewhere

The SSM parameters (keys) recognized by `awcli-mfa.sh` are as follows:

MFA required:
```
/unencrypted/roles/{remote account number}/{remote account role name}/mfa_required
```

Maximum role session length:
```
/unencrypted/roles/{remote account number}/{remote account role name}/session_length
```

Remote account alias (if defined, this is used in full mode instead of the account number; only set this to the same alias you have defined for the account in AWS!). Only one alias per remote account number can be defined:
```
/unencrypted/roles/{remote account number}/alias
```

#### Examples

Note that since since the AWS Parameter Store Secrets Manager (SSM) is region-specific, the default as of script version `2.7.1` uses `us-east-1` as an aggregate region for advertising this information. You can change this by modifying the value for `XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE` variable found near the top of the `awscli-mfa.sh` script. If you blank out the variable, the region is taken from each role's source profile, and thus if your IAM accounts lie across multiple regions, you may need to distribute this information to multiple regions (hence an aggregate region should be used if possible).

__NOTE:__ Unless you modify the `XACCN_ROLE_PROPERTY_LOOKUP_REGION_OVERRIDE` variable in the script, you should always use `us-east-1` for region below.

__MAXIMUM ROLE SESSION LENGTH__

To set the maximum allowed session length for the role `OtherAccountRoleName` of account `111222333444` in seconds (here setting the role's maximum allowed session length to 1200 seconds, or 20 minutes):
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/session_length" --value "1200" --type String
```

To alter the existing maximum session length for a given role:
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/session_length" --value "2400" --type String --overwrite
```

To view the current session length for a given role:
```
aws --profile "{profile}" --region {region} ssm get-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/session_length" --output text --query 'Parameter.Value'
```

To delete the defined session length for a given role:

```
aws --profile "{profile}" --region {region} ssm delete-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/session_length"
```

__ROLE MFA REQUIREMENT__

To set MFA requirement for the role `OtherAccountRoleName` of account `111222333444` (NOTE: when the MFA is not required for a role, the value can be absent or set to 'false')
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/mfa_required" --value "true" --type String
```

To alter the MFA requirement for a given role (to remove the requirement, you can also just delete the record):
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/mfa_required" --value "false" --type String --overwrite
```

To view the MFA requirement for a given role:
```
aws --profile "{profile}" --region {region} ssm get-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/mfa_required" --output text --query 'Parameter.Value'
```

To delete the MFA requirement for a given role:

```
aws --profile "{profile}" --region {region} ssm delete-parameter --name "/unencrypted/roles/111222333444/OtherAccountRoleName/mfa_required"
```

__REMOTE ACCOUNT ALIAS__

To set the alias for the remote account `111222333444` (only one alias can be set per remote account number):
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/alias" --value "globex-production" --type String
```

To alter the alias for the remote account `111222333444`:
```
aws --profile "{profile}" --region {region} ssm put-parameter --name "/unencrypted/roles/111222333444/alias" --value "initech-production" --type String --overwrite
```

To view the currently defined alias for remote account `111222333444`:
```
aws --profile "{profile}" --region {region} ssm get-parameter --name "/unencrypted/roles/111222333444/alias" --output text --query 'Parameter.Value'
```

To delete the alias for the remote account `111222333444`:
```
aws --profile "{profile}" --region {region} ssm delete-parameter --name "/unencrypted/roles/111222333444/alias"
```
