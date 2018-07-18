#!/usr/bin/env python
from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import re

'''
Create a new account
'''
def create_account(
        org_client,
        account_name,
        account_email,
        admin_account_role,
        access_to_billing,
        organization_unit_id):

    # Create the account
    try:
        print("Creating account: " + account_name)
        create_account_response = org_client.create_account(Email=account_email,
                                                            AccountName=account_name,
                                                            RoleName=admin_account_role,
                                                            IamUserAccessToBilling=access_to_billing)
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    print('Waiting while the account is created..')
    time.sleep(10)

    # check the account successfully creates
    account_status = 'IN_PROGRESS'
    while account_status == 'IN_PROGRESS':
        create_account_status_response = org_client.describe_create_account_status(CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        #print("Create account status "+str(create_account_status_response))
        account_status = create_account_status_response.get('CreateAccountStatus').get('State')
    if account_status == 'SUCCEEDED':
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    elif account_status == 'FAILED':
        print("Account creation failed: " + create_account_status_response.get('CreateAccountStatus').get('FailureReason'))
        sys.exit(1)

    # Move account into an organizational unit
    if organization_unit_id is not None:
        try:
            print("Moving account: " + account_id + " into organization unit: " + organization_unit_id)
            root_id = org_client.list_roots().get('Roots')[0].get('Id')
            describe_organization_response = org_client.describe_organizational_unit(OrganizationalUnitId=organization_unit_id)
            move_account_response = org_client.move_account(AccountId=account_id,
                                                        SourceParentId=root_id,
                                                        DestinationParentId=organization_unit_id)
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r} "
            message = template.format(type(ex).__name__, ex.args)
            print(message)
            sys.exit(1)

    return account_id

'''
Create admin user, group and attach policy
'''
def create_admin_user_group_and_policy(
        master_iam_client,
        account_name,
        account_id,
        admin_login_password,
        output_debug_messages):

    try:

        # create admin user
        path = '/'
        admin_user_name = b'Admin%s' % account_name
        admin_user_response = master_iam_client.create_user(
            Path=path,
            UserName=admin_user_name
        )

        # create admin group
        admin_group_name = b'Organizations%sAdmin' % account_name
        admin_group_response = master_iam_client.create_group(
            Path=path,
            GroupName=admin_group_name
        )

        # create admin policy
        admin_policy_name = b'Organizations%sAccountAdminAccess' % account_name
        admin_policy_document = b'{"Version":"2012-10-17","Statement":[{"Sid":"AllowAdminAccessToOrganizationAccount","Effect":"Allow","Action":["sts:AssumeRole"],"Resource":["arn:aws:iam::%s:role/OrganizationAccountAdminAccessRole"]}]}' % account_id
        description = b'Admin Access Role for Account ID=%s' % account_id

        admin_access_policy_response = master_iam_client.create_policy(
            PolicyName=admin_policy_name,
            Path=path,
            PolicyDocument=admin_policy_document,
            Description=description
        )
        admin_access_policy_arn = admin_access_policy_response['Policy']['Arn']

        # attach the policy to the group
        print("Attaching admin policy: " + admin_access_policy_arn + " to admin group " + admin_group_name)
        group_attach_policy_response = master_iam_client.attach_group_policy(
            GroupName=admin_group_name,
            PolicyArn=admin_access_policy_arn
        )

        # add the admin user to the admin group
        add_admin_user_to_group_response = master_iam_client.add_user_to_group(
            GroupName=admin_group_name,
            UserName=admin_user_name
        )

        # create the access key/secret
        admin_access_key_response = master_iam_client.create_access_key(
            UserName=admin_user_name
        )

        # create login profile
        admin_login_profile_response = master_iam_client.create_login_profile(
            UserName=admin_user_name,
            Password=admin_login_password,
            PasswordResetRequired=True
        )

        return admin_access_key_response, admin_user_name, admin_login_profile_response

    except Exception as ex:

        template = "An exception of type {0} occurred. Arguments:\n{1!r} "
        message = template.format(type(ex).__name__, ex.args)
        print(message)
        sys.exit(1)

'''
Create readonly user, group and attach policy
'''
def create_readonly_user_group_and_policy(
        master_iam_client,
        account_name,
        account_id,
        readonly_login_password,
        output_debug_messages):

    try:

        # create readonly user
        path = '/'
        readonly_user_name = b'ReadOnly%s' % account_name
        readonly_user_response = master_iam_client.create_user(
            Path=path,
            UserName=readonly_user_name
        )

        # create readonly group
        readonly_group_name = b'Organizations%sReadOnly' % account_name
        readonly_group_response = master_iam_client.create_group(
            Path=path,
            GroupName=readonly_group_name
        )

        # ----

        readonly_policy_name = b'Organizations%sAccountReadOnlyAccess' % account_name
        readonly_policy_document = b'{"Version":"2012-10-17","Statement":[{"Sid":"AllowReadOnlyAccessToOrganizationAccount","Effect":"Allow","Action":["sts:AssumeRole"],"Resource":["arn:aws:iam::%s:role/OrganizationAccountReadOnlyAccessRole"]}]}' % account_id
        description = b'Read Only Access Role for Account ID=%s' % account_id

        # create readonly policy
        readonly_access_policy_response = master_iam_client.create_policy(
            PolicyName=readonly_policy_name,
            Path=path,
            PolicyDocument=readonly_policy_document,
            Description=description
        )
        readonly_access_policy_arn = readonly_access_policy_response['Policy']['Arn']

        # ----

        # attach the policy to the readonly group
        group_attach_policy_response = master_iam_client.attach_group_policy(
            GroupName=readonly_group_name,
            PolicyArn=readonly_access_policy_arn
        )

        # ----

        # add the readonly user to the admin group
        add_readonly_user_to_group_response = master_iam_client.add_user_to_group(
            GroupName=readonly_group_name,
            UserName=readonly_user_name
        )

        # ----

        # create readonly access key
        readonly_access_key_response = master_iam_client.create_access_key(UserName=readonly_user_name)

        # ----

        # create readonly login profile
        readonly_login_profile_response = master_iam_client.create_login_profile(
            UserName=readonly_user_name,
            Password=readonly_login_password,
            PasswordResetRequired=True
        )

        return readonly_access_key_response, readonly_user_name, readonly_login_profile_response

    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r} "
        message = template.format(type(ex).__name__, ex.args)
        print(message)
        sys.exit(1)

'''
Assume the temporary role as admin of the account
'''
def assume_admin_role(
        account_id,
        account_role):

    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(RoleArn=role_arn,
                                                       RoleSessionName="NewAdminRole")
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(10)

    return assumedRoleObject['Credentials']

'''
Create the ReadOnly role in the new account
'''
def create_read_only_role_in_account(
        account_iam_client,
        current_account_id,
        readonly_account_role,
        output_debug_messages):

    try:
        path = '/'
        assume_role_policy_document = b'{"Version":"2012-10-17","Statement":[{ "Action":"sts:AssumeRole","Effect":"Allow","Condition":{},"Principal":{"AWS":"arn:aws:iam::%s:root"}}]}' % current_account_id
        description = b'Organization Read Only Access Role for Account ID=%s' % current_account_id

        create_read_only_role_response = account_iam_client.create_role(
            Path=path,
            RoleName=readonly_account_role,
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description=description
        )

        aws_read_only_policy_arn = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        attach_aws_read_only_policy_response = account_iam_client.attach_role_policy(
            RoleName=readonly_account_role,
            PolicyArn=aws_read_only_policy_arn
        )

        return create_read_only_role_response

    except botocore.exceptions.ClientError as e:
        assuming_role = True
        print(e)
        print("Retrying...")
        time.sleep(10)

'''
Print out all the details of the account
'''
def publish(
        account_name,
        account_id,
        account_email,
        admin_account_role,
        readonly_account_role,
        admin_access_key_response,
        admin_user_name,
        admin_login_password,
        readonly_access_key_response,
        readonly_user_name,
        readonly_login_password):

    print("")
    print("---------------")
    print("Account Details")
    print("---------------")
    print("%s" % account_name)
    print('%s - %s' % (account_id, account_email))
    print("")
    print("%s" % admin_account_role)
    print("https://signin.aws.amazon.com/switchrole?roleName=%s&account=%s" % (admin_account_role, account_id))
    print("")
    print("%s" % readonly_account_role)
    print("https://signin.aws.amazon.com/switchrole?roleName=%s&account=%s" % (readonly_account_role, account_id))
    print("")
    print("---------------")
    print("Admin Login Details")
    print("---------------")
    print("Admin Access Key ID: %s " % (admin_access_key_response.get('AccessKey').get('AccessKeyId')))
    print("Admin Access Secret: %s " % ( admin_access_key_response.get('AccessKey').get('SecretAccessKey')))
    print("Admin Console Login Username: %s " % (admin_user_name))
    print("Admin Console Login Password: %s " % (admin_login_password))
    print("")
    print("---------------")
    print("Read-Only Login Details")
    print("---------------")
    print("Read-Only Access Key: %s " % (readonly_access_key_response.get('AccessKey').get('AccessKeyId')))
    print("Read-Only Secret: %s " % (readonly_access_key_response.get('AccessKey').get('SecretAccessKey')))
    print("Read-Only Console Login Username: %s " % (readonly_user_name))
    print("Read-Only Console Login Password: %s " % (readonly_login_password))
    print("")

'''
Output any debug messages
'''
def debug_output(debug_message, output_debug_messages):
    print (debug_message if output_debug_messages else 0)

'''
Its the main event..
'''
def main():

    output_debug_messages = False # True

    # Prepare the AWS clients
    aws_profile = raw_input("Which AWS profile to use (leave empty for 'default') ") or "default"
    boto3.setup_default_session(profile_name=aws_profile)
    org_client = boto3.client('organizations')
    master_iam_client = boto3.client('iam')
    sts = boto3.client("sts")
    current_account_id = sts.get_caller_identity()["Account"]

    # gather the input parameters
    account_name = raw_input("Please enter Account Name (leave empty for 'MyTestAccount'): ") or "MyTestAccount"
    # validation
    if not re.match(r"^[a-zA-Z0-9\+\=\,\.\@\_\-\'\,]+$", account_name):
        print("Account name: %s is not alpha-numeric and/or +=,.@_-'," % account_name)
        sys.exit(1)
    account_email = raw_input("Please enter Email Address for Account (leave empty for 'phpchap@gmail.com'): ") or "phpchap@gmail.com"
    # validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", account_email):
        print("Account email: %s is not valid" % account_email)
        sys.exit(1)
    admin_account_role = raw_input("Please enter Admin Account Role Name (leave empty for: 'OrganizationAccountAdminAccessRole'): ") or "OrganizationAccountAdminAccessRole"
    admin_login_password = raw_input("Please enter Admin Web Console Password: ") or "3vdF+40vhjxCK"
    readonly_login_password = raw_input("Please enter Read-Only Web Console Password: ") or "jC$DK6Te6nICj"
    readonly_account_role = 'OrganizationAccountReadOnlyAccessRole'

    # set the account create variables
    access_to_billing = "DENY"
    organization_unit_id = None # set this if you want to map to an organisation unit

    # create the account
    print("Creating new account: " + account_name + " (" + account_email + ") account role: " + admin_account_role)
    account_id = create_account(org_client, account_name, account_email, admin_account_role, access_to_billing, organization_unit_id)
    print("Created acount: " + account_id)

    # assume the role of administrator in the new account
    print("Assuming admin role for account_id")
    credentials = assume_admin_role(account_id, admin_account_role)
    account_iam_client = boto3.client(
        'iam',
        aws_access_key_id = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token = credentials['SessionToken'],
    )

    # create a read only role in the account
    print("Creating read only role in account: " + account_id)
    read_only_role_response = create_read_only_role_in_account(account_iam_client, current_account_id, readonly_account_role, output_debug_messages)

    # create admin user, group and policy and get the access details
    print("Creating admin user, group, policy and getting the access details for account : " + account_id)
    admin_access_key_response, admin_user_name, admin_login_profile_response = create_admin_user_group_and_policy(
        master_iam_client,
        account_name,
        account_id,
        admin_login_password,
        output_debug_messages)

    # create read only user, group and policy and get the access details
    print("Creating read only user, group, policy and getting the access details for account : " + account_id)
    readonly_access_key_response, readonly_user_name, readonly_login_profile_response = create_readonly_user_group_and_policy(
        master_iam_client,
        account_name,
        account_id,
        readonly_login_password,
        output_debug_messages)

    # publish results
    publish(account_name,
        account_id,
        account_email,
        admin_account_role,
        readonly_account_role,
        admin_access_key_response,
        admin_user_name,
        admin_login_password,
        readonly_access_key_response,
        readonly_user_name,
        readonly_login_password)

if __name__ == '__main__':
    sys.exit(main())