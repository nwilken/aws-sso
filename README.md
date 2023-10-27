## Assume role in AWS using ASU Single Sign-On

### Usage:

#### Method 1 (standard).
`docker run -it --rm -v ~/.aws:/root/.aws asuuto/aws-sso:latest`

(or `-v %userprofile%\.aws:/root/.aws` when running on Windows)

#### Method 2 (using optional args).
`docker run -it --rm -v ~/.aws:/root/.aws asuuto/aws-sso:latest <username> <password> <duration> <organization>`

(or `-v %userprofile%\.aws:/root/.aws` when running on Windows)

When using this method, all four of the following must be defined:

- `username` : the SSO user intended to assume the role.
- `password` : the password of the SSO user intended to assume the role.
  - It is recommended that this be sourced from a file or environment variable (IE: `$(cat /path/to/password/file)`.
- `duration` : length of time that the SSO user will have the role (in seconds).
  - This value must be less than or equal to the maximum session duration of the assumed role.
- `organization` : use 'production'.

If either of the above methods completed successfully, you should be able to run commands using AWS CLI.

Example:

`aws --profile saml s3 ls`

or, if you don't have the aws cli installed locally:

`docker run -it --rm -v ~/.aws:/root/.aws asuuto/awscli:latest aws --profile saml s3 ls`

---

If you don't already have a `~/.aws/credentials` file, start with this one

```
[default]
output = json
region = us-west-2
aws_access_key_id = 
aws_secret_access_key = 
```

### Side Effects:

* Creates/updates a `saml` profile in `~/.aws/credentials`
* Creates/updates `~/.aws/sso_session_cookies` to cache your ASU SSO and MFA sessions

### Build:

```
docker build --pull -t asuuto/aws-sso:latest .
docker push asuuto/aws-sso:latest
```

### Known issues:
- An error may be thrown if you have access to only one AWS account/role
- Process fails if you are being prompted to change your password at login
- A validation error will occur if the duration is greater than the `MaxSessionDuration`.
