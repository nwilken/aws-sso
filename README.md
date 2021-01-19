## Assume role in AWS using ASU Single Sign-On

#### Usage:

`docker run -it --rm -v ~/.aws:/root/.aws asuuto/aws-sso:latest`

(or `-v %userprofile%\.aws:/root/.aws` when running on Windows)

then you can, for example

`aws --profile saml s3 ls *`

or, if you don't have the aws cli installed locally

`docker run -it --rm -v ~/.aws:/root/.aws asuuto/awscli:latest aws --profile saml s3 ls *`

if you don't already have a `~/.aws/credentials` file, start with this one

```
[default]
output = json
region = us-west-2
aws_access_key_id = 
aws_secret_access_key = 
```

#### Side Effects:

* Creates/updates a `saml` profile in `~/.aws/credentials`
* Creates/updates `~/.aws/sso_session_cookies` to cache your ASU SSO and MFA sessions

#### Build:

```
docker build --pull -t asuuto/aws-sso:latest .
docker push asuuto/aws-sso:latest
```
