
# awscli-mfa and its companion scripts

The `awscli-mfa.sh` and its companion scripts `enable-disable-vmfa-device.sh` `mfastatus.sh`, and `source-to-clear-AWS-envvars.sh` were created to make handling AWS MFA sessions on the command line easy. 

### Usage, quick!

These scripts create a workflow to easily and quickly create/configure a virtual MFA device vMFAd for a profile, then start an MFA session, and then monitor the remaining session validity period for any of the active sessions. You can have multiple concurrent active MFA sessions and easily switch between them (and the base profiles where no MFA session is used/desired) by re-executing the `awscli-mfa.sh` script. Or, if you create 'persistent' sessions (it's the default when starting a new MFA session), you can always use the `--profile` switch with your `aws cli`  command to temporarily select another active session or base profile without running `awscli-mfa.sh`. Here is how it works:

First make sure you have `aws cli` installed. AWS has details for [Mac](https://docs.aws.amazon.com/cli/latest/userguide/cli-install-macos.html) and [Linux](https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-linux.html).

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
            source ./source-to-clear-AWS-envvars.sh

        PASTE THE PROFILE ACTIVATION COMMAND FROM THE CLIPBOARD
        ON THE COMMAND LINE NOW, AND PRESS ENTER! THEN YOU'RE DONE!

        ~$ export AWS_PROFILE="default-mfasession"; unset AWS_ACCESS_KEY_ID; unset AWS_SECRET_ACCESS_KEY; unset AWS_SESSION_TOKEN; unset AWS_SESSION_INIT_TIME; unset AWS_SESSION_DURATION; unset AWS_DEFAULT_REGION; unset AWS_DEFAULT_OUTPUT

        /// PASTED ON THE COMMAND LINE THE EXPORT COMMAND THAT THE SCRIPT PLACED
        /// ON THE CLIPBOARD AND PRESSED ENTER TO EXPORT/CLEAR THE AWS_* ENVIRONMENT
        /// VARIABLES TO ACTIVATE THIS NEWLY INITIALIZED MFA PROFILE.

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

5. Finally, a sourceable `source-to-clear-AWS-envvars.sh` is provided to make it easy to clear out any any `AWS_*` envvars, like so: `source ./source-to-clear-AWS-envvars.sh`. This purges any secrets and/or references to persistent profiles from the local environment.

### Rationale

When the presence of a multi-factor authentication session to execute AWS commands (i.e. not just the login to the web console) is enforced using an IAM policy, the enforcement cannot be limited to the web console operations. This is because the AWS web console is basially a front-end to the AWS APIs which can also be accessed using the `aws cli`. When you log in to the web console and enter an MFA code, the browser takes care of caching the credentials and the session token, and so beyond that point the MFA session is transparent to the user until the session eventually expires, and the AWS web console prompts the user to log in again. On the command line it's different. To register a virtual MFA device (vMFAd), or to start a session, a complex sequence of commands are required, followed by the need to painstakingly save the session token/credentials in the `~/.aws/credentials` file, and then either refer to that session profile by using the `--profile` switch on each `aws cli` command, or set various `aws_*` environment variables by cut-and-pasting at least the key id, the secret key, and the session token. Furthermore, the only way to know that the session has expired is that the `aws cli` commands start failing, thus making it difficult to plan long-running command execution, and potentially being confusing as to why such failures should occur.

The `awscli-mfa.sh` and its companion scripts change all this by making use of the MFA sessions with `aws cli` a breeze! Let's first look at what each script does on the high level.

### Overview

These scripts provide significant interactive guidance as well as user-friendly failure information when something doesn't work as expected.

The scripts have been tested in macOS (High Sierra with stock bash 3.2.x) as well as with Linux (Ubuntu 16.04 with modern default bash 4.3.x). The only dependency is `aws cli`, and the scripts will notify the user if `aws cli` is not present.

* **awscli-mfa.sh** - Makes it easy to start MFA sessions with `aws cli`, and to switch between active sessions and base profiles. Multiple profiles are supported, but if only a single profile ("default") is in use, a simplified user interface is presented. <br><br>This is an interactive script since it prompts for the current MFA one time pass code from the Google Authenticator/Authy app, and as such it does not take command line arguments. The script was originally written for macOS, but compatibility for Linux has been added.<br><br>When an MFA session is started with this script, it automatically records the initialization time of the session and names the MFA session with the `-mfasession` postfix.<br><br>For more details, read [my blog post](https://random.ac/cess/2017/10/29/easy-mfa-and-profile-switching-in-aws-cli/) about this script.

* **enable-disable-vmfa-device.sh** - Makes it easy to enable/attach and disable/detach (as well as to delete) a virtual MFA device ("vMFAd"). Assumes that each IAM user can have one vMFAd configured at a time, and that it is named the same as their IAM username (i.e. the serial number, Arn, of the vMFAd is of the format `arn:aws:iam::{AWS_account_id}:mfa/{IAM_username}` when the IAM user Arn is of the format `arn:aws:iam::{AWS_account_id}:user/{IAM_username}`). Disabling a vMFAd requires an active MFA session with that profile; if you no longer have access to the vMFAd in your Google Authenticator or Authy app, you either need to have admin privileges to the AWS account, or contact the admin/ops with a request to delete the vMFAd off of your account so that you can create a new one.<br><br>As with `awscli-mfa.sh`, this script supports multiple configured profiles, but if only a single profile ("default") is in use, a simplified user interface is presented to either create/enable a vMFAd if none is present, or disable/deleted a vMFAd if one is active.

* **mfastatus.sh** - Displays the currently active MFA sessions and their remaining activity period. Also indicates expired persistent (or in-environment) profiles with "EXPIRED" status.

* **source-to-clear-AWS-envvars.sh** - A simple sourceable script that removes any AWS secrets/settings that may have been set in the local environment by the `awscli-mfa.sh` script. Source it, like so: `source ./source-to-clear-AWS-envvars.sh`, or set an alias, like so: `alias clearaws='source ~/awscli-mfa/source-to-clear-AWS-envvars.sh`

* **example-MFA-enforcement-policy.txt** - An example IAM policy to enforce an active MFA session to allow `aws cli` command execution. This policy has been carefully crafted to work with the above scripts, and it has been inspired by (but improved from) the example policies provided by [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html) and [Trek10](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/) (both of those policies had problems which have been resolved in this example policy). Note that when a MFA is enabled on the command line using this script, it is also enabled for the web console login.

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



