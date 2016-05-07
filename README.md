aws-cloudformation-ami
======================

Summary
-------

This project aims to create a clean, easy to use CloudFormation template
to create an Amazon Machine Image (AMI).  The template is designed in
such a way that it can be used as a nested stack and the output of the
template could be used to specify the image ID for resources that require
such an ID.

The primary focus is to create a CentOS 7 minimal installation AMI with
additional security tightening applied.  However, once this is done the
goal is to create an extensible framework so any distribution could be
easily added.

The use case for this template is to unbind templates from the hardcoded
dependency on the AMI IDs.  It is also a useful reference for some
non-standard, outside-the-box approaches one could employ when they design
CloudFormation templates.

Synopsis
--------

```shell
aws cloudformation create-stack --stack-name <name> \
	--capabilities CAPABILITY_IAM \
	--template-body file:///path/to/bootstrap.template \
	--parameters ParameterKey=SubnetId,ParameterValue=<subnet_id> \
		[ParameterKey=<parameter>,ParameterValue=<value>]
```

Stack parameters
----------------

Parameter             | Type    | Required | Default    | Description
--------------------- |:-------:|:--------:| ---------- | -----------
BootstrapImage        | String  |    No    | ""         | AMI for the bootstrap instance, should be using 'yum' and support 'cloud-init' (if empty will use Amazon Linux AMI)
BootstrapInstanceType | String  |    No    | "t2.micro" | Instance type to use for the bootstrap image
BootstrapScriptUrl    | String  |    No    | ""         | An URL of the alternative bootstrap script
BootstrapVolumeSize   | Number  |    No    | 10         | Size of the bootstrap volume that would be used as for the root filesystem (in GB)
KeyName               | String  |    No    | ""         | Key pair name to install on the bootstrap image in case you need to debug the bootstrap process
SubnetId              | String  |    Yes   |            | The ID of the Subnet where the bootstrap instance is going to be launched (must have Internet connectivity to download packages!)
UserData              | String  |    No    | ""         | Additional commands to execute just before the image is going to be created
VpcId                 | String  |    No    | ""         | VPC where the bootstrap instance will be launched.  If you do not specify this parameter you need to ensure that the default security group allows outbound traffic on tcp/80 and tcp/443
PreserveStack         | Boolean |    No    | "False"    | Whether this stack should be preserved after generation of the image or not (this should be used for debug purposes only)
ParentStackId         | String  |    No    | ""         | The ID of the parent stack.  Required if this stack is nested in another stack
UpdateTrigger         | String  |    No    | ""         | Every time this parameter changes the associated stack would go through CloudFormation update routine, so if you want to regenerate the resulting AMI provide a different value each time you run the stack update

Description
-----------

The template generates an Amazon image using another AMI as a bootstrap
instance.  By default it uses a hardcoded list of Amazon Linux AMI
(AMIs defined for all Amazon Regions) and that hardcoded default will
be used if no BootstrapImage parameter is provided to the stack.

In order to perform the installation of the operating system the
bootstrap instance needs Internet access.  Due to limitations of the
CloudFormation template language and the desire to avoid unnecessary
parameter requirements it was decided to implement the following logic:

1. if no VPC ID was specified during the stack creation, the template
will instantiate the bootstrap instance with the default security group
assigned to it;
2. if the VPC ID was provided at the stack creation time, the template
will create a temporary security group allowing the outbound traffic to
tcp/80 and tcp/443 anywhere.

It is worth it to mention that the bootstrap instance must be launched
into the subnet where Internet connectivity is provided (either via NAT
instance, NAT gateway, or the gateway if subnet is "public").

The bootstrap instance is configured to request the public IP to be
assigned to it unconditionally during the creation of the instance.
This was done to allow the instance to communicate with the upstream
servers in case the instance was deployed into the "public" subnet.

It usually takes approximately from 30 to 60 minutes to create the AMI
using this template.  However, caching was also implemented and if the
resulting AMI is matching any of the previously created AMIs the AMI
build stage is skipped and the id of the previously created AMI is
returned in the stack output instead.  In this case it usually takes
approximately 5 minutes to run through the template.

