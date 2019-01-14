
# awscli-mfa.sh and its companion scripts

The `awscli-mfa.sh` and its companion scripts `enable-disable-vmfa-device.sh` and `source-this-to-clear-AWS-envvars.sh` were created to make handling multi-factor sessions with AWS command line interface easy. 

### Usage, quick!

1. __If you don't yet have your AWS command line profile(s) configured:__ Configure the first AWS profile using `aws configure` for the first/default profile, or `aws configure --profile "SomeDescriptiveProfileName"` for a new named profile. You can view the any existing profiles with `cat ~/.aws/config` and `cat ~/.aws/credentials`. For an overview of the AWS configuration files, check out their [documentation page](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html). Note that while you can also put the credentials information in the `config` file, `awscli-mfa.sh` always writes the persisted session credentials in the `credentials` file. Furthermore, if there are any overlapping credentials properties (i.e. `aws_access_key_id`, `aws_secret_access_key`, or `aws_session_token`) in the two files, the entries in the `credentials` file take precedence. Thus I recommend using the `config` file for the profile configuration properties and the `credentials` file for the profile credentials (this is what `aws configure` does automatically).

2. __If you don't yet have the virtual MFA device ("vMFAd") configured__ (if you have previously set up the vMFAd for the same IAM user in the AWS Web Console, this step is not needed): Execute `enable-disable-vmfa-device.sh` to create and enable a vMFAd with a Google Authenticator compatible app such as my favorite, Authy ([Android](https://play.google.com/store/apps/details?id=com.authy.authy&hl=en_US), [iOS](https://itunes.apple.com/us/app/authy/id494168017)) on your portable device. You can also use Duo Security app for this purpose. Follow the interactive directions from the script.

3. Execute `awscli-mfa.sh` to start an MFA session using the vMFAd you just configured. Follow the interactive directions from the script.

4. View the status and the remaining validity periods for the current MFA sessions  using the `mfastatus.sh` script. __THIS SCRIPT HAS NOT YET BEEN UPDATED FOR v2__, however, `awscli-mfa.sh` now also displays the session status and remaining validity periods. Whether a separate script will be offered for this is still under consideration.

5. If you need to switch between the configured base profiles and/or active MFA or role sessions, re-execute `awscli-mfa.sh` and follow its prompts. If you need to disable/detach (and possibly delete) a vMFAd from an IAM user, re-execute `enable-disable-vmfa-device.sh` and follow its interactive guidance.

Keep reading for the features, rationale, overview, and in-depth usage information...

### awscli-mfa.sh Features

- Supports any number of configured baseprofiles.
- Supports any number of configured roles.
- Supports chained roles which can only be authenticated with another role's existing role session.
- External ID is supported in the roles.
- Session maximum length can be set per-session using the proprietary `sessmax` property in a profile's configuration in the `config` file; when the effective IAM policy allows querying profile details, the `sessmax` is set automatically when it differs from the AWS default of 3600 seconds (1h). When the IAM policy doesn't allow retrievals of the role configuration (such as perhaps with third-party roles), the value can be set manually by the user. This is important especially in the cases where the allowed session maximum length is below 3600 seconds (1h) as the role session requests with a longer session length than what the role's policy allows, fail.
- Doesn't require the `default` profile to be present in case you prefer to always explicitly define the profile you want to use with the `aws` command.
- When `region` and `output` properties have not been set for a profile, the script attempts to automatically inherit them, first from the MFA/role session's source profile, and then from the `default` profile, if available. A baseprofile missing these values only inherits them from the `default` profile, if available.
- Validates the profiles when executed in the full mode (use `--full`/`-f` or give no option to activate as this is the default mode).
- Provides "quick mode" (use `--quick`/`-q` to activate) that forgoes the validity checks but brings up the menu much faster; this makes the utility a lot more convenient to use especially when you have lots of profiles configured and need to frequently jump between baseprofiles or active sessions. However, it's a good idea to execute the script in the "full mode" every once in a while, and especially whenever there have been any changes to your profiles/IAM accounts as the full mode persists some of its findings for reference in the quick mode.
- Written to be portable; the script is environment-aware and has been tested in macOS (with bash 3.2 - 5.0), Ubuntu/Debian, RedHat/CentOS, and Windows Subsystem for Linux ("WSL") with Ubuntu. The script is bash-native, but has also been tested with zsh.
- Provides the option to either persist a started MFA/role session into the `credentials` file, or to only export the session into the environment. When executed in the bash, the script also provides profile/session activation strings for Windows PowerShell and Windows Command Prompt.
- Provides a single-command prefix string for the selected profile (bash only).
- Automatically copies the selected activation string onto the clipboard; this is a built-in in macOS and in WSL bash; in the Linux Desktop distros (e.g., Ubuntu) `xclip` is required for the automatic copy-to-clipboard.
- The script validates the AWS configuration files for the common configuration errors and provides guidance on how to fix them, including providing the source profile selection for the roles which don't have a source profile configured (full mode only).
- The script validates the baseprofiles and the MFA/role sessions (full mode only). When the script detects an invalid baseprofile or an invalid MFA/role session, it tags them as "invalid" both in the `config` and `credentials` files with the last detection time (provided in UTC). The `invalid_as_of = {date stamp}` pseudo-property makes it easier to detect and remove the invalid profiles when editing the configuration files.
- The remaining validity periods are displayed for all MFA and role sessions that were started with this script (both in full and quick mode).
- Checks the current state of the environment on startup; if a profile/session is detected in the environment, its status and details are displayed.
- Presents a simplified interface when only a single profile plus its possible MFA session are present.
- The only hard dependency is a recent version of the `aws` command. The script checks for the presence of `aws` and its version, and instructs the user to install/upgrade it if necessary. Additionally, in Linux, `coreutils` is required (and checked for), but it is generally part of the standard Linux installations.
- The only soft dependency is `jq`. The script works without it, but with `jq` present it works faster, especially when any role profiles are present. When `jq` is not detected, the script recommends it to be installed.

### Rationale

When the presence of a multi-factor authentication session is enforced with an IAM policy, the enforcement cannot be limited to the web console operations (nor should it, but that's a different topic). This is because the AWS web console is basically a front-end to the AWS APIs, i.e., the same ones which are also accessed using the `aws` CLI command. When you log in to the AWS web console and enter an MFA code, the browser takes care of caching the credentials and the session token, and so beyond that point, in the web browser, the MFA/role session is transparent to the user until the session eventually expires, and the AWS web console prompts the user to log in again. On the command line it's different. To create, enable, or disable a virtual MFA device (vMFAd), or to start an MFA or a role session, complex sequences of commands are required, followed by the need to painstakingly save the session token/credentials in the `~/.aws/credentials` file, and then to either refer to that session profile by using the `--profile {session profile name}` switch in each `aws` CLI command, or to add/modify/delete various `AWS_*` environment variables by cut-and-pasting at least the aws access key id, the aws secret access key, plus for the sessions the session token. Furthermore, the only way to know that a session has expired is that the `aws` CLI commands start failing, thus making it difficult to plan long-running command execution, and potentially being confusing as to why such failures should occur.

The `awscli-mfa.sh` and its companion scripts change all this by making use of the MFA sessions with `aws` CLI command a breeze! Let's first look at what each script does on the high level.

### Overview

These scripts provide significant interactive guidance as well as user-friendly failure information when something doesn't work as expected.

The scripts have been written for macOS (with stock bash 3.2.x, and homebrew-installed bash 4.4.x or 5.x) as well as with Linux (Ubuntu/Debian, RHEL/CentOS, and WSL Ubuntu). The only dependencies are `aws` itself (required) and `jq` (recommended but not required). The scripts will notify the user if `aws` is not present.

* **awscli-mfa.sh** - Makes it easy to start MFA/role sessions with `aws`, and to switch between active sessions and base profiles. Multiple profiles are supported, but if only a single profile is in use, a simplified user interface is presented. <br><br>This is an interactive script since it prompts for the current MFA one time pass code from the Google Authenticator/Authy app. The  accepted command line arguments are: `--quick`/`-q` for the quick mode, `--full` / `-f` for the full mode (same as no arguments), and `--debug` / `-d` which enables debug output (not very useful unless you're debugging the script's internals).<br><br>When an MFA or a role session is started with this script, it automatically records the expiration time of the session, and names the session profile with the `-mfasession` postfix.

* **enable-disable-vmfa-device.sh** - Makes it easy to enable/attach and disable/detach (as well as to delete) a virtual MFA device ("vMFAd"). Assumes that each IAM user can have one vMFAd configured at a time, and that the vMFAd is named the same as their IAM username (i.e. the serial number which is known as the ARN or "Amazon Resource Name" of the vMFAd is of the format `arn:aws:iam::{AWS_account_id}:mfa/{IAM_username}` when the IAM user ARN is of the format `arn:aws:iam::{AWS_account_id}:user/{IAM_username}`). Disabling a vMFAd requires usually an active MFA session with that profile. However, you can also use another profile that is authorized to detach a vMFAd. If you no longer have access to the vMFAd in your Google Authenticator or Authy app, you either need to have access to an AWS account which is authorized to detach vMFAd for other users and/or without an active MFA session. In the absence of such, contact the admin/ops with a request to delete the vMFAd off of your account so that you can create a new one.<br><br>As with `awscli-mfa.sh`, this script supports multiple configured profiles, but if only a single profile is in use, a simplified user interface is presented to either create/enable a vMFAd if none is present, or disable/deleted a vMFAd if one is active.

* **mfastatus.sh** - Displays the currently active MFA sessions and their remaining validity period. Also indicates expired persistent (or in-environment) profiles with "EXPIRED" status. __THIS SCRIPT HAS NOT YET BEEN UPDATED FOR v2__, however, `awscli-mfa.sh` now also displays the session status and remaining validity periods. Whether a separate script will be offered for this is still under consideration.

* **source-this-to-clear-AWS-envvars.sh** - A simple sourceable script that removes any AWS secrets/settings that may have been set in the local environment by the `awscli-mfa.sh` script. Source it, like so: `source ./source-this-to-clear-AWS-envvars.sh`, or set an alias, like so: `alias clearaws='source ~/awscli-mfa/source-this-to-clear-AWS-envvars.sh'`. The two AWS envvars that this script does _not_ remove are: `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`. This is because if you are using custom `config` and `credentials` file locations, you likely want to keep using them more continuously rather than from session-to-session.

* **example-MFA-enforcement-policy.txt** - An example IAM policy to enforce an active MFA session to allow `aws` command execution. This policy has been carefully crafted to work with the above scripts, and it has been inspired by (but improved from) the example policies provided by [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html) and [Trek10](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/) (both of those policies had problems which have been resolved in this example policy). Note that when a MFA is enabled on the command line using this script, it is also enabled for the web console login. Also note that the `awscli-mfa.sh` script uses the innocuous permission for `get-access-key-last-used` as an indicator of whether MFA enforcement is in effect (besides it being harmless information security-wise it also makes sense since it's only relevant if you're using the `aws` commmand-line command where you obviously have an API key assigned).

_---UPDATED for v2 TO THIS POINT---_

### Usage (the long form)

These scripts create a workflow to easily and quickly create/configure a virtual MFA device vMFAd for a profile, then start an MFA session, and then monitor the remaining session validity period for any of the active sessions. You can have multiple concurrent active MFA sessions and easily switch between them (and the base profiles where no MFA session is used/desired) by re-executing the `awscli-mfa.sh` script. Or, if you create 'persistent' sessions (it's the default when starting a new MFA session), you can always use the `--profile` switch with your `aws` CLI command to temporarily select another active session or base profile without running `awscli-mfa.sh`. Here is how it works:

First make sure you have `aws` CLI command installed. AWS has details for [Mac](https://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html) and [Linux](https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-linux.html).

1. You have received a set of AWS credentials, so add them to your `~/.aws/credentials` file first. If that file doesn't exist yet, or if there are no credentials present, configure the default profile with `aws configure`. If you already have existing profiles in the `~/.aws/credentials` file, configure a named profile with:

    `aws configure --profile "SomeDescriptiveProfileName"`<br>
.. and you will be prompted for the AWS Access Key ID, AWS Secret Access Key, Default Region name, and Default output format. An example (these are of course not valid, so enter your own :-) 

        AWS Access Key ID [None]: AKIAIL3VDLRPTXVU3ART
        AWS Secret Access Key [None]: hlR98dzjwFKW3rZLNf32sdjRkelLPdrRh2H4hzn8
        Default region name [None]: us-east-1
        Default output format [None]: table

2. Make sure you have Authy installed on your portable device. It is available for [Android](https://play.google.com/store/apps/details?id=com.authy.authy&hl=en_US) and [iOS](https://itunes.apple.com/us/app/authy/id494168017). Now execute `enable-disable-vmfa-device.sh`. If you have only one profile present and you don't have a vMFAd configured yet for it, the process will be like so (the in-line comments indicated with '///'). If something goes wrong with the vMFAd activation process, the script gives a hopefully clear/obvious guidance.

        Executing this script as the AWS/IAM user 'mfa-test-user' (profile 'default').

        Please wait.

        You have one configured profile: default (IAM: mfa-test-user)
        .. but it doesn't have a virtual MFA device attached/enabled.

        Do you want to attach/enable a vMFAd? Y/N 

        ///
        /// ANSWERED 'Y'
        ///

        Preparing to enable the vMFAd for the profile...

        No available vMFAd found; creating new...

        A new vMFAd has been created. Please scan
        the QRCode with Authy to add the vMFAd on
        your portable device.

        NOTE: The QRCode file, "default vMFAd QRCode.png",
        is on your DESKTOP!

        /// OPENED THE QRCODE FILE MENTIONED ABOVE AND SCANNED IT IN AUTHY:
        /// In Authy, select "Add Account" in the top right menu, then click
        /// "Scan QR Code", and once scanned, give the profile a descriptive
        /// name and click on "DONE"

        Press 'x' once you have scanned the QRCode to proceed.

        NOTE: Anyone who gains possession of the QRCode file
              can initialize the vMFDd like you just did, so
              optimally it should not be kept around.

        Do you want to delete the QRCode securely? Y/N

        /// ANSWERED 'Y'. DON'T KEEP THE QRCODE FILE AROUND
        /// UNLESS YOU NEED TO INITIALIZE THE SAME vMFAd ON
        /// ANOTHER DEVICE! NOTE THAT THE QRCODE FILE IS EQUAL
        /// TO A PASSWORD AND SHOULD BE STORED SECURELY IF NOT
        /// DELETED.

        QRCode file deleted securely.

        Enabling the newly created virtual MFA device:
        arn:aws:iam::123456789123:mfa/mfa-test-user

        Please enter two consecutively generated authcodes from your
        GA/Authy app for this profile. Enter the two six-digit codes
        separated by a space (e.g. 123456 456789), then press enter
        to complete the process.

        >>> 923558 212566

        vMFAd successfully enabled for the profile 'default' (IAM user name 'mfa-test-user').

        You can now use the 'awscli-mfa.sh' script to start an MFA session for this profile!

    If you have more than one profile configured, or one or more active MFA sessions, you'll be presented with a menu (below). If you select a base profile you have the option to not enter an MFA pass code in which case the base profile is used rather than initiating an MFA session for it. If you select an existing active MFA profile (indicated with the `m` postfix), then the MFA code is not requested and just the envvar exports are copied on the clipboard for pasting on the command line to activate that profile:

        Executing this script as the AWS/IAM user 'mfa-test-user' (profile 'default').
        
        Please wait..
        
        AVAILABLE AWS PROFILES:

        1: default (IAM: mfa-test-user; vMFAd enabled)
        1m: default MFA profile (07h:17m:17s remaining)

        2: profile OtherProfile (IAM: mfa-test-user; vMFAd enabled)

        You can switch to a base profile to use it as-is, start an MFA session
        for a profile if it is marked as "vMFAd enabled", or switch to an existing
        active MFA session if any are available (indicated by the letter 'm' after
        the profile ID, e.g. '1m'; NOTE: the expired MFA sessions are not shown).

        SELECT A PROFILE BY THE ID:


3. Now execute `awscli-mfa.sh` to start the first MFA session. The process for a single configured profile looks like this (again, the in-line comments indicated with '///'):

        Executing this script as the AWS/IAM user 'mfa-test-user' (profile 'default').

        Please wait.

        You have one configured profile: default (IAM: mfa-test-user)
            .. its vMFAd is enabled
            .. but no active persistent MFA sessions exist

        Do you want to:
        1: Start/renew an MFA session for the profile mentioned above?
        2: Use the above profile as-is (without MFA)?

        ///
        /// ANSWERED '1'
        ///

        Starting an MFA session..
        SELECTED PROFILE: default

        Enter the current MFA one time pass code for the profile 'default'
        to start/renew an MFA session, or leave empty (just press [ENTER])
        to use the selected profile without the MFA.

        >>> 764257

        Acquiring MFA session token for the profile: default...
        MFA session token acquired.

        Make this MFA session persistent? (Saves the session in /Users/ville/.aws/credentials
        so that you can return to it during its validity period, 09h:00m:00s.)
        Yes (default) - make peristent; No - only the envvars will be used [Y]/N

        /// PRESSED 'ENTER' FOR THE DEFAULT 'Y'; THE MFA SESSION IS MADE PERSISTENT
        /// BY SAVING IT IN `~/.aws/credentials` FILE WITH '{baseprofile}-mfasession'
        /// PROFILE NAME. THIS MAKES IT POSSIBLE TO SWITCH BETWEEN THE ACTIVE MFA
        /// SESSIONS AND BASE PROFILES, AND ALSO RETURN TO THE MFA SESSION AFTER
        /// SYSTEM REBOOT WITHOUT REACQUIRING A MFA SESSION.

        NOTE: Region had not been configured for the selected MFA profile;
              it has been set to same as the parent profile ('us-east-1').
        NOTE: Output format had not been configured for the selected MFA profile;
              it has been set to same as the parent profile ('table').

        /// THE SCRIPT AUTOMATICALLY SETS THE REGION AND THE DEFAULT OUTPUT
        /// FORMAT IF THEY WEREN'T PREVIOUSLY SET. THE BASE PROFILE SETTINGS
        /// ARE USED BY DEFAULT FOR ITS MFA SESSIONS. IF THE BASE PROFILE DOESN'T
        /// HAVE THEM SET EITHER, THE DEFAULT SETTINGS ARE USED.

                            * * * PROFILE DETAILS * * *

        MFA profile name: 'default-mfasession'

        Region is set to: us-east-1
        Output format is set to: table

        Do you want to export the selected profile's secrets to the environment (for s3cmd, etc)? - Y/[N]

        /// PRESSED 'ENTER' FOR THE DEFAULT 'N'. BY DEFAULT ONLY THE MFA PROFILE
        /// REFERENCE IS EXPORTED TO THE ENVIRONMENT. IF YOU SELECT 'Y', THEN ALSO
        /// THE `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, AND `AWS_SESSION_TOKEN`
        /// ARE EXPORTED. THIS MAY BE DESIRABLE IF YOU ARE USING AN APPLICATION SUCH
        /// AS s3cmd WHICH READS THE ACCESS CREDENTIALS FROM THE ENVIRONMENT RATHER
        /// THAN FROM THE `~/.aws/credentials` FILE.

        *** It is imperative that the following environment variables are exported/unset
        as specified below in order to activate your selection! The required
        export/unset commands have already been copied on your clipboard!
        Just paste on the command line with Command-v, then press [ENTER]
        to complete the process!

        export AWS_PROFILE="default-mfasession"
        unset AWS_ACCESS_KEY_ID
        unset AWS_SECRET_ACCESS_KEY
        unset AWS_DEFAULT_REGION
        unset AWS_DEFAULT_OUTPUT
        unset AWS_SESSION_INIT_TIME
        unset AWS_SESSION_DURATION
        unset AWS_SESSION_TOKEN


        *** Make sure to export/unset all the new values as instructed above to
            make sure no conflicting profile/secrets remain in the envrionment!

        *** You can temporarily override the profile set/selected in the environment
            using the "--profile AWS_PROFILE_NAME" switch with awscli. For example:
            aws sts get-caller-identity --profile default

        *** To easily remove any all AWS profile settings and secrets information
            from the environment, simply source the included script, like so:
            source ./source-this-to-clear-AWS-envvars.sh

        PASTE THE PROFILE ACTIVATION COMMAND FROM THE CLIPBOARD
        ON THE COMMAND LINE NOW, AND PRESS ENTER! THEN YOU'RE DONE!

        ~$ export AWS_PROFILE="default-mfasession"; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT

        /// PASTED ON THE COMMAND LINE THE EXPORT COMMAND THAT THE SCRIPT PLACED
        /// ON THE CLIPBOARD AND PRESSED ENTER TO EXPORT/CLEAR THE AWS_* ENVIRONMENT
        /// VARIABLES TO ACTIVATE THIS NEWLY INITIALIZED MFA PROFILE.

    TIP: If you use [**s3cmd**](http://s3tools.org/s3cmd), it's a good practice to not keep the AWS credentials in `~/.s3cfg`. Instead, use `awscli-mfa.sh` to select a profile, even if you want to use a non-MFA base profile. When using a base profile, simply leave the MFA one time pass code empty and press Enter. Then choose 'Yes' when asked if you want to export the selected profile's secrets to the environment (and paste then paste/enter in Terminal to export). That way `s3cmd` will pick up the credentials from the environment instead of its own configuration file. This also makes it easy to switch between the profiles when using `s3cmd`. 

    The Route53 utility [**cli53**](https://github.com/barnybug/cli53) honors the profile selector envvar (`AWS_PROFILE`); so for it you don't need to select "export secrets".

4. Now you can execute `mfastatus.sh` to view the remaining activity period on the MFA session:

        ENVIRONMENT
        ===========

        ENVVAR 'AWS_PROFILE' SELECTING A PERSISTENT MFA SESSION (as below): default-mfasession


        PERSISTENT MFA SESSIONS (in /Users/ville/.aws/credentials)
        ==========================================================

        MFA SESSION IDENT: default-mfasession (IAM user: 'mfa-test-user')
          MFA SESSION REMAINING TO EXPIRATION: 08h:13m:48s


        NOTE: Execute 'awscli-mfa.sh' to renew/start a new MFA session,
              or to select (switch to) an existing active MFA session.

5. A sourceable `source-this-to-clear-AWS-envvars.sh` is provided to make it easy to clear out any any `AWS_*` envvars, like so: `source ./source-this-to-clear-AWS-envvars.sh`. This purges any secrets and/or references to persistent profiles from the local environment.

6. If you want to detach/disable (and maybe delete) a vMFAd off of an account, you can run `enable-disable-vmfa-device.sh` script again. Below also a situation with more than one base profile is shown:

        ~$ ./enable-disable-vmfa-device.sh

        ** NOTE: THE FOLLOWING AWS_* ENVIRONMENT VARIABLES ARE CURRENTLY IN EFFECT:

           AWS_PROFILE: default-mfasession

        Executing this script as the AWS/IAM user 'mfa-test-user' (profile 'default-mfasession').

        Please wait..

         AWS PROFILES WITH NO ATTACHED/ENABLED VIRTUAL MFA DEVICE (vMFAd):
         Select a profile to which you want to attach/enable a vMFAd.
         A new vMFAd is created/initialized if one doesn't exist.

        1: OtherProfile (IAM: my-real-IAM-username)

         AWS PROFILES WITH ACTIVE (ENABLED) VIRTUAL MFA DEVICE (vMFAd):
         Select a profile whose vMFAd you want to detach/disable.
         Once detached, you'll have the option to delete the vMFAd.
         NOTE: A profile must have an active MFA session to disable!

        2: default (IAM: mfa-test-user)

        SELECT A PROFILE BY THE NUMBER: 2

        Preparing to disable the vMFAd for the profile...

        vMFAd disabled/detached for the profile 'default'.

        Do you want to DELETE the disabled/detached vMFAd? Y/N

        /// SELECTED 'Y' 

        vMFAd deleted for the profile 'default'.

        To set up a new vMFAd, run this script again.

    Note: If configured on the AWS side, an automated process may delete the detached virtual MFA devices that have been left unattached for some period of time (but this script automatically creates a new vMFAd if none are found). When a vMFAd is deleted, the entry on GA/Authy becomes void.<br><br>Note: In order to disable/detach a vMFAd off of a profile that profile must have an active MFA session. If the script doesn't detect an MFA session, the following message is displayed:

        Preparing to disable the vMFAd for the profile...

        No active MFA session found for the profile 'OtherProfile'.

        To disable/detach a vMFAd from the profile, you must have
        an active MFA session established with it. Use the 'awscli-mfa.sh'
        script to establish an MFA session for the profile first, then
        run this script again.

        If you do not have possession of the vMFAd for this profile
        (in GA/Authy app), please request ops to disable the vMFAd
        for your profile, or if you have admin credentials for AWS,
        use them outside this script to disable the vMFAd for this
        profile.

### Session Activity Period

Because the MFA session expiration time is encoded in the encrypted AWS session token, there is no way to retrieve the expiration time for a specific session from the AWS. To keep track of the remaining activity period, the following variables are used:

* `MFA_SESSION_LENGTH_IN_SECONDS` - This __user-configurable__ variable is set on top of the `awscli-mfa.sh`, `enable-disable-vmfa-device.sh`, and `mfastatus.sh` scripts. It needs to equal to the maximum length for MFA sessions defined by your IAM policy in seconds (see the two `"aws:MultiFactorAuthAge": "32400"` entries in `example-MFA-enforcement-policy.txt`). If you decide on a different maximum session length than 9h (32400 seconds), make sure to adjust both your active IAM MFA enforcement policy and the above mentioned variable in the three scripts.

* `mfasec` - An __optional, user-configurable__ proprietary variable may be defined in `~/.aws/config` for any base profile (i.e. any profile whose name doesn't end in `-mfasession`). It sets the profile-specific session length, and as such overrides the default `MFA_SESSION_LENGTH_IN_SECONDS`. This makes it possible for different AWS profiles (and thus often different AWS accounts) to have their MFA session enforcement policy be set to different maximum session lengths. If you're not an AWS admin, ask your DevOps/admin contact what the enforced MFA session lifetime is set to. There is no way to find out this value otherwise as it is an arbitrary number between 900 seconds (15 minutes) and 129000 seconds (36 hours) decided by the AWS account administrator. Note: The valid session length for the root (non-IAM) account is limited to 900-3600 seconds, but you should not use - and preferably delete - the access keys for the root/account as they are considered a security risk.<br><br>The optional `mfasec` value in `~/.aws/config` looks as follows (here the session length of the MFA sessions started for the `test-user` base profile are set to 21600 seconds, or 6 hours):

    ```
    [profile test-user]
    region = us-east-1
    output = table
    mfasec = 21600
    ```

* `aws_session_init_time` - This __automatically configured__ proprietary variable is set in `~/.aws/credentials` file for the persistent MFA profiles (indicated by the `-mfasession` postfix in the profile name). It is a timestamp of the initialization time of the session in question. __This value is never adjusted by the user__, and it looks like this:

    ```
    [test-user-mfasession]
    aws_session_init_time = 1522910812  <---
    aws_access_key_id = XXXXXXXXXXXXXXXXXXXX
    aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    aws_session_token = FQoDYXdzEHAaDENknHJokLPf40ffGCKwAQUGXOPjUl9m8j3q+ZbwyfRAUoQa8lMYy+ubhgKaYes5ZC+NuQGV98v5r1OEMABBYqAfCx2e+0wXBKicG/HetxrG1PP43242lNN1IyVxHbJLKjn9YM5m3MJTZjR7+BcZQfafugcdwzkgPD7yfKoDbqU8j5lCHWk0KkLPLIWFhi0nQPLoL1a4zDc8ibxXhezKJiWOrrmteTuRIK7jiZQB5CzjfQsQ0BI5mM8AOzwdY/LWKNOMl9YF
    ```

### Alternative Configuration Files

These scripts recognize and honor custom configuration and credentials file locations set with `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` envvars, respectively. Only if the named/default profile such such files is not valid, the scripts let the user know, and then revert to the default files `~/.aws/config` and `~/.aws/credentials`.

### Debugging

Enable the debugging output temporarily by using a command line switch `-d` or `--debug`, or by uncommeting `DEBUG=true` on top of `awscli-mfa.sh` or `enable-disable-vmfa-device.sh` files. The debugging output displays the raw `aws cli` returns in `awscli-mfa.sh` and `enable-disable-vmfa-device.sh` files, so you'll be able to see any results/error messages as-is. Note that key ids, keys, or session tokens may be included in the debugging output! 
