# okta-aws-login: A cli tool for generating temporary AWS credentials using your Okta login.

## Installing

Download lastest release [0.0.2](https://marshallbrekka.github.io/okta-aws-login/releases/okta-aws-login-0.0.2.zip) and unzip it.

Place the unpacked binary on your path `mv okta-aws-login /usr/local/bin`

## Configuring

The first time you run the tool it will prompt for your AWS IDP URL. You can find this by loging in to your Okta dashboard, and right-clicking on the AWS link and copying the link location.

It will also prompt you for what AWS region you want to set your profile to target.

You can configure these options again by running `okta-aws-login --configure`.
