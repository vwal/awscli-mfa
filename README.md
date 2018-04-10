
# awscli-mfa and its companion scripts

The `awscli-mfa.sh` and its companion scripts `enable-disable-vmfa-device.sh` `mfastatus.sh`, and `source-to-clear-AWS-envvars.sh` were created to make handling AWS MFA sessions easy on the command line. 

When the presence of multi-factor authentication session to execute AWS commands (i.e. not just the login to the web console) is enforced using an IAM policy, it cannot be limited to the web console operations. This is because the AWS web console is basially a front-end to the AWS APIs that can also be accessed using the `aws cli`. When you log in to the web console and enter an MFA code, the browser takes care of caching the session credentials, and so beyond that point it is transparent to the user until the session eventually expires, and the AWS web console prompts you to log in again. On the command line it is different. To register a virtual MFA device, or to start a session, a complex sequence of `aws cli` commands would be required, followed by painstakingly saving the session credentials to the `~/.aws/credentials` file, and then referring to them using the `--profile` switch on each `aws cli` command. Furthermore, the only way to know that the session has ended would be when the `aws cli` commands would start failing, thus making it difficult to plan command execution, and potentially being confusing as to why such failures would occur.

The `awscli-mfa.sh` and its companion scripts change all this making use of MFA sessions with `aws cli` a breeze. Let's first look at what each script does on the high level.

### Overview

All scripts provide significant interactive guidance as well as user-friendly failure information when something doesn't work as expected.

All scripts have been tested in macOS (High Sierra with stock bash 3.2.x) as well as with Linux (Ubuntu 16.04 with modern default bash 4.3.x). The only dependency is `awscli`.

* **awscli-mfa.sh** - Makes it easy to start MFA sessions with `aws cli`, and to switch between active sessions. Multiple profiles are supported, but if only a single profile ("default") is in use, a simplified user interface is presented. <br><br>This is an interactive script since it prompts for the current MFA one time pass code, and as such it does not take arguments. The script was originally written for macOS, but compatibility for Linux has been added.<br><br>When an MFA session is started with this script, it automatically records the initialization time of the session, and names the MFA session with the `-mfasession` postfix.<br><br>For more details, read [my blog post](https://random.ac/cess/2017/10/29/easy-mfa-and-profile-switching-in-aws-cli/) about this script.

* **enable-disable-vmfa-device.sh** - Makes it easy to enable/attach and disable/detach (as well as to delete) a virtual MFA device ("vMFAd"). Assumes that each IAM user can have one vMFAd configured at a time, and that is named the same as their IAM username (i.e. the serial number of the vMFAd is of format `arn:aws:iam::XXXXXXXXXXXX:mfa/{IAMusername}` when the IAM user Arn is `arn:aws:iam::XXXXXXXXXXXX:user/{IAMusername}`). Disabling a vMFAd requires an active MFA session with that profile; if you no longer have acess to the vMFAd in your Google Authenticator or Authy app, you either need to have admin privileges to the AWS account, or contact the ops with a request to delete the vMFAd so that you can create a new one.<br><br>As with `awscli-mfa.sh`, this script supports multiple configured profiles, but if only a single profile ("default") is in use, a simplified user interface is presented. 

* **mfastatus.sh** - Displays the currently active MFA sessions and their remaining activity period. Also indicates expired persistent (or in-environment) profiles in "EXPIRED" status.

* **source-to-clear-AWS-envvars.sh** - A simple sourceable script that removes any AWS secrets/settings that may have been set in the local environment by the `awscli-mfa.sh` script. Source this like so: `source ./source-to-clear-AWS-envvars.sh`, or set an alias, like so: `alias clearaws='source ~/awscli-mfa/source-to-clear-AWS-envvars.sh`

* **example-MFA-enforcement-policy.txt** - An example IAM policy to enforce active MFA session to allow command execution. This policy has been carefully crafted to work with the above scripts, and it has been inspired by (but improved from) the example policies provided by [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html) and [Trek10](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/) (both of those policies had problems which have been resolved in this example policy)

### Session Activity Period

Because the MFA session expiration time is encoded in the encrypted AWS session token, there is no way to retrieve the expiration time from AWS. To keep track of the remaining activity period, the following values are used:

* `MFA_SESSION_LENGTH_IN_SECONDS` - This user-configurable variable is set on top of the `awscli-mfa.sh`, `enable-disable-vmfa-device.sh`, and `mfastatus.sh` scripts, and it needs to equal to the length of an MFA session in seconds defined by your IAM policy (see the two `"aws:MultiFactorAuthAge": "32400"` entries in `example-MFA-enforcement-policy.txt` that you should fashion your MFA session enforcement policy after). If you decide on a different maximum session length than 9h (32400 seconds), make sure to adjust both your active IAM MFA enforcement policy and the variable in the three scripts.

* `aws_session_init_time =` - This automatically configured proprietary variable is set in `~/.aws/credentials` file for the persistent MFA profiles (indicated by the `-mfasession` postfix in the profile name). It is a timestamp of the initialization time of the session in question. This value is never adjusted by the user, and it looks like this:

```
[test-user-mfasession]
aws_session_init_time = 1522910812
aws_access_key_id = XXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aws_session_token = FQoDYXdzEHAaDENknHJokLPf40ffGCKwAQUGXOPjUl9m8j3q+ZbwyfRAUoQa8lMYy+ubhgKaYes5ZC+NuQGV98v5r1OEMABBYqAfCx2e+0wXBKicG/HetxrG1PP43242lNN1IyVxHbJLKjn9YM5m3MJTZjR7+BcZQfafugcdwzkgPD7yfKoDbqU8j5lCHWk0KkLPLIWFhi0nQPLoL1a4zDc8ibxXhezKJiWOrrmteTuRIK7jiZQB5CzjfQsQ0BI5mM8AOzwdY/LWKNOMl9YF
```

* `mfasec =` - An optional, user-configurable variable sets the profile-specific session length. If defined in `~/.aws/config` for a profile, it overrides the default `MFA_SESSION_LENGTH_IN_SECONDS`, and thus makes it possible for different AWS profiles (and thus often different AWS accounts) to have their MFA session enforcement policy to be set to different maximum session lengths. If you're not an AWS admin, ask your DevOps/admin contact what the MFA session lifetime is set to. There is no way to know it otherwise as it is an arbitrary value that cannot be queried via the `aws cli`. The optional `mfasec` value in `~/.aws/config` looks like this (here the `test-user-mfasession` MFA session is set to last 21600 seconds, or 6 hours (NOTE: `mfasec` is defined for the base profile for which you wish to start an MFA session; the MFA session profile names have the `-mfasession` postfix which the base profiles do not have):

```
[profile test-user]
region = us-east-1
output = table
mfasec = 21600
```

### Usage

[coming soon]


