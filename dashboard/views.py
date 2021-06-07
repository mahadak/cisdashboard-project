from logging import DEBUG
from re import template
import re, datetime
from typing import Dict, List
from django.contrib.auth import get_user
from django.db.models.fields import NOT_PROVIDED
from django.http.response import JsonResponse
from django.shortcuts import redirect, render
from django.utils.timezone import now
from django.views import View
from django.shortcuts import render
import boto3, requests
import webbrowser
from dashboard.models import User, UserAWS, ScanReports, ServicesReport
from principalmapper.common import Graph, Node, Edge
from principalmapper.visualizing import graph_writer
from django.http import HttpResponse
from wsgiref.util import FileWrapper
import environ
env = environ.Env()
environ.Env.read_env()
# Create your views here.

class DashboardView(View):
    """Dashboard View for main landing"""
    template_name = "dashboard/dashboard.html"

    def get(self, request):
        user = request.user
        context = {'name': user.name}
        useraws = UserAWS.objects.filter(user=user)
        context['established_connections'] = len(useraws)
        return render(request, self.template_name, context)


class CrossSignInAWS(View):

    def post(self, request):
        user = request.user

        role_arn = request.POST.get('role_arn')    
        # Step 1: Prompt user for target account ID and name of role to assume
        
        AWS_CREDS = {
            "aws_access_key_id": env("AWS_ACCESS_KEY"),
            "aws_secret_access_key": env("AWS_SECRET_KEY")
        }        
        
        # Step 2: Connect to AWS STS and then call AssumeRole. This returns 
        # temporary security credentials.
        sts_connection = boto3.client('sts', **AWS_CREDS)
        assumed_role_object = sts_connection.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession",
        )

        role_arn1 = role_arn.split('::')
        role_id =  None
        for role in role_arn1:
            role_id = role
        acc_number = role_id[0:12]

        useraws = UserAWS.objects.create(user=user, roleArn=role_arn, account_number=acc_number)
        useraws.save()
        return redirect("../connections")

class ConnectionsView(View):
    template_name = "dashboard/connection.html"
    
    def get(self, request):
        user = request.user
        useraws = list(UserAWS.objects.filter(user=user))
        context = {"object_list": useraws}
        return render(request, self.template_name, context)



class ScanConnectionView(View):

    def post(self, request):
        uuid = request.POST.get('uuid')
        useraws = UserAWS.objects.get(uuid=uuid)
        AWS_CREDS = {
            "aws_access_key_id": env("AWS_ACCESS_KEY"),
            "aws_secret_access_key": env("AWS_SECRET_KEY")
        }        
        
        # Step 2: Connect to AWS STS and then call AssumeRole. This returns 
        # temporary security credentials.

        sts_connection = boto3.client('sts', **AWS_CREDS)
        assumed_role_object = sts_connection.assume_role(
            RoleArn=useraws.roleArn,
            RoleSessionName="AssumeRoleSession",
        )

        access_key = assumed_role_object.get('Credentials').get('AccessKeyId')
        secret_key = assumed_role_object.get('Credentials').get('SecretAccessKey')
        session_token = assumed_role_object.get('Credentials').get('SessionToken')
        
        AWS_TEMP_CREDS = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "aws_session_token": session_token
        }  
        scan_report = ScanReports.objects.create(account=useraws)
        scan_report.save()

        # Iam Checks
        iam_cred_test_check = "unknown"
        iam_policy_test_check = "unknown"
        iam_root_user_account_access_key_check = "unknown"
        iam_mfa_test_check = "unknown"
        iam_mfa_hardware_test_check = "unknown"
        iam_pass_policy_test_check = "unknown"
        iam_pass_reuse_test_check = "unknown"
        iam_one_active_key_test_check = "unknown"
        iam_user_perm_check = "unknown"
        iam_support_role_check = "unknown"
        iam_server_expiration_test_check = "unknown"
        iam_support_role = "fail"
        json_list_iam_cred =[]
        json_list_iam_policy =[]
        json_list_root_user_acc =[]
        json_list_mfa =[]
        json_list_mfa_hardware =[]
        json_list_pass_policy =[]
        json_list_pass_reuse =[]
        json_list_active_key_one =[]
        json_list_iam_user_perm =[]
        json_list_iam_support_role =[]
        json_list_server_expiry =[]
        try:
            iam_client = boto3.client('iam', **AWS_TEMP_CREDS)
            users_list = iam_client.list_users()
            for users in users_list['Users']:
                temp_access_key_list = []
                access_keys = iam_client.list_access_keys(UserName=users['UserName'])
                for keys in access_keys['AccessKeyMetadata']:
                    try:
                        date = iam_client.get_access_key_last_used(AccessKeyId=keys['AccessKeyId'])['AccessKeyLastUsed']['LastUsedDate']
                        t = datetime.datetime.now(datetime.timezone.utc) - date
                        if t.days >= 90:
                            iam_cred_test = "fail"
                        else:
                            iam_cred_test = "pass"                                                    
                    except Exception as e:
                        iam_cred_test = "pass"      
                    if keys['Status'] == "Active":
                        temp_access_key_list.append(keys['AccessKeyId'])
                if len(temp_access_key_list) > 1:
                    iam_one_active_key_test = "fail"
                else:
                    iam_one_active_key_test = "pass"
                user_attached_policies = iam_client.list_attached_user_policies(UserName=users['UserName'])['AttachedPolicies']
                user_policies = iam_client.list_user_policies(UserName=users['UserName'])['PolicyNames']
                if len(user_policies) > 0 or len(user_attached_policies) > 0:
                    iam_user_perm = "fail"                    
                else:
                    iam_user_perm = "pass"
                iam_cred_test_check = "done"
                iam_one_active_key_test_check = "done"
                iam_user_perm_check = "done"
                json_list_iam_cred.append({"service": "iam_credentials_check", "name": users['UserName'], "test": iam_cred_test, "severity": "Low"})
                json_list_active_key_one.append({"service": "iam_one_active_access_key_check", "name": users['UserName'], "test": iam_one_active_key_test, "severity": "Low"})
                json_list_iam_user_perm.append({"service": "iam_user_permission", "name": users['UserName'], "test": iam_user_perm, "severity": "Low"})
            temp_list_policy = []
            policies = iam_client.list_policies()
            for policy in policies['Policies']:
                try:
                    policy_doc = iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
                    policy_doc = policy_doc['PolicyVersion']['Document']['Statement']
                    for pol in policy_doc:
                        if pol['Action'] == "*" or pol['Resource'] == "*":
                            iam_policy_test = "fail"
                        else:
                            iam_policy_test = "pass"
                    iam_policy_test_check = "done"   
                    arn = policy['Arn'].split('/')
                    temp_list_policy.append(arn[1])                    
                    json_list_iam_policy.append({"service": "iam_policy_check", "name": policy['PolicyName'], "test": iam_policy_test, "severity": "Medium"})
                except:
                    pass
            if 'AWSSupportAccess' in temp_list_policy:
                pol = iam_client.list_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess')
                if pol['PolicyRoles']: 
                    iam_support_role = "pass"
                else:
                    iam_support_role = "fail"
            iam_support_role_check = "done"
            json_list_iam_support_role.append({"service": "iam_support_role", "name": 'Support Policy', "test": iam_support_role, "severity": "Low"})
            servers = iam_client.list_server_certificates()
            for certificate in servers['ServerCertificateMetadataList']:
                if "Expiration" in certificate:
                    expiry_date = certificate['Expiration']
                    if expiry_date - datetime.datetime.now() > 0:
                        iam_server_expiration_test = "pass"
                    else:
                        iam_server_expiration_test = "fail"
                    json_list_server_expiry.append({"service": "iam_server_certificate_expiry", "name": certificate['ServerCertificateName'], "test": iam_server_expiration_test, "severity": "Low"})

            else:
                iam_server_expiration_test = "pass"
            iam_server_expiration_test_check = "done"
            json_list_server_expiry.append({"service": "iam_server_certificate_expiry", "name": "No Expiry Certificates", "test": iam_server_expiration_test, "severity": "low"})


            summary = iam_client.get_account_summary()
            summary_val = summary['SummaryMap']
            root_user_access_key = summary_val['AccountAccessKeysPresent']
            if root_user_access_key == 0:
                iam_root_acc_test = 'pass'
            else:
                iam_root_acc_test = "fail"
            iam_root_user_account_access_key_check = 'done'
            json_list_root_user_acc.append({"service": "iam_root_account_access_key", "name": "Root User Access Key Existance", "test": iam_root_acc_test, "severity": "Low"})
            mfa_enabled = summary_val['AccountMFAEnabled']
            if mfa_enabled == 1:
                iam_mfa_test = "pass"
                mfa_ver = iam_client.list_virtual_mfa_devices()
                mfa_ver = mfa_ver['VirtualMFADevices']
                for mfv in mfa_ver:
                    if mfv['SerialNumber']:
                        iam_mfa_hardware_test = 'fail'
                else:
                    iam_mfa_hardware_test = "pass"
            else:
                iam_mfa_test = "fail"
            iam_mfa_test_check = "done"
            iam_mfa_hardware_test_check = "done"
            json_list_mfa_hardware.append({"service": "iam_mfa_hardware_enabled", "name": "IAM MFA Hardware Enabled", "test": iam_mfa_hardware_test, "severity": "Medium"})
            json_list_mfa.append({"service": "iam_mfa_enabled", "name": "IAM MFA Enabled", "test": iam_mfa_test, "severity": "Low"})
            try:
                password_policy = iam_client.get_account_password_policy()
                p_policy = password_policy['PasswordPolicy']                    
                if p_policy['MinimumPasswordLength'] >=14:
                    iam_pass_policy_test = "pass"
                else:
                    iam_pass_policy_test = "fail"
                iam_pass_policy_test_check = "done"
                if "PasswordReusePrevention" in p_policy:
                    iam_pass_reuse_test = "pass"
                else:
                    iam_pass_reuse_test = "fail"
                iam_pass_reuse_test_check = "done"
                json_list_pass_policy.append({"service": "iam_pass_policy", "name": "IAM Password Policy", "test": iam_pass_policy_test, "severity": "Low"})
                json_list_pass_reuse.append({"service": "iam_pass_reuse", "name": "IAM Password Reuse Prevention", "test": iam_pass_reuse_test, "severity": "Low"})
            except Exception as e:
                pass


        except Exception as e:
            pass
        report_iam = ServicesReport.objects.create(service="IAM Credentials Test", scan=scan_report, report=json_list_iam_cred, test_status=iam_cred_test_check)
        report_iam_2 = ServicesReport.objects.create(service="IAM Policy Test", scan=scan_report, report=json_list_iam_policy, test_status=iam_policy_test_check)
        report_iam_3 = ServicesReport.objects.create(service="IAM Root Account Access Key Existance", scan=scan_report, report=json_list_root_user_acc, test_status=iam_root_user_account_access_key_check)
        report_iam_4 = ServicesReport.objects.create(service="IAM MFA Enabled Test", scan=scan_report, report=json_list_mfa, test_status=iam_mfa_test_check)
        report_iam_5 = ServicesReport.objects.create(service="IAM MFA Hardware Enabled Test", scan=scan_report, report=json_list_mfa_hardware , test_status=iam_mfa_hardware_test_check)
        report_iam_6 = ServicesReport.objects.create(service="IAM Password Policy Test", scan=scan_report, report=json_list_pass_policy , test_status=iam_pass_policy_test_check)
        report_iam_7 = ServicesReport.objects.create(service="IAM Password Reuse Test", scan=scan_report, report=json_list_pass_reuse , test_status=iam_pass_reuse_test_check)
        report_iam_8 = ServicesReport.objects.create(service="IAM User One Active Access Key", scan=scan_report, report=json_list_active_key_one , test_status=iam_one_active_key_test_check)
        report_iam_9 = ServicesReport.objects.create(service="IAM User Permission", scan=scan_report, report=json_list_iam_user_perm , test_status=iam_user_perm_check)
        report_iam_10 = ServicesReport.objects.create(service="IAM Support Role", scan=scan_report, report=json_list_iam_support_role , test_status=iam_support_role_check)
        report_iam_11 = ServicesReport.objects.create(service="IAM Server Certificates Expiry", scan=scan_report, report=json_list_server_expiry , test_status=iam_server_expiration_test_check)

        AWS_TEMP_CREDS["region_name"] = "us-east-1"

        # s3 bucket checks
        json_list_enc = []
        s3_bucket_enc_test = "unknown"
        s3_bucket_ssl_test = "unknown"
        s3_public_block_test_check = "unknown"
        json_list_ssl = []
        json_list_public_block = []
        try:
            s3_client = boto3.client('s3', **AWS_TEMP_CREDS)
            s3_buckets_res = s3_client.list_buckets()
            buckets_list = s3_buckets_res['Buckets']
            for bucket in buckets_list:
                s3_bucket_enc = "pass"
                s3_bucket_ssl = "pass"
                try:
                    s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                    s3_bucket_enc = "pass"
                except Exception as e:
                    s3_bucket_enc = "fail"
                s3_bucket_enc_test = "done"
                json_list_enc.append({"service": "s3_bucket_encryption_check", "name": bucket['Name'], "test": s3_bucket_enc, "severity": "Medium"})
                try:
                    bucket_policy = s3_client.get_bucket_policy(Bucket=bucket['Name'])
                    policy = bucket_policy['policy']
                    if "AllowSSLRequestsOnly" in policy:
                        s3_bucket_ssl = "pass"
                except Exception as e:
                    s3_bucket_ssl = "fail"
                s3_bucket_ssl_test = "done"
                json_list_ssl.append({"service": "s3_bucket_ssl_check", "name": bucket['Name'], "test": s3_bucket_ssl, "severity": "Medium"})
                try:
                    access = s3_client.get_public_access_block(Bucket=bucket['Name'])                    
                    s3_public_block_test = "pass"                    
                except:
                    s3_public_block_test = "fail"
                s3_public_block_test_check = 'done'
                json_list_public_block.append({"service": "s3_bucket_public_block_access_check", "name": bucket['Name'], "test": s3_public_block_test, "severity": "High"})

        except Exception as e:
            pass
        report_ss3 = ServicesReport.objects.create(service="S3 Bucket Encryption", scan=scan_report, report=json_list_enc, test_status=s3_bucket_enc_test)
        report_ss3_2 = ServicesReport.objects.create(service="S3 SSL Security", scan=scan_report, report=json_list_ssl, test_status=s3_bucket_ssl_test)
        report_ss3_3 = ServicesReport.objects.create(service="S3 Public Block Access", scan=scan_report, report=json_list_public_block, test_status=s3_public_block_test_check)
        
        # ec2 instances
        json_ec2 = []
        ec2_test = "unknown"
        try:                
            ec2_client = boto3.client('ec2', **AWS_TEMP_CREDS)
            instances = ec2_client.describe_instances()
            for res in instances['Reservations']:
                for instance in res['Instances']: 
                    try:
                        for sg in instance['SecurityGroups']:
                            gid = sg['GroupId']
                            sg = ec2_client.describe_security_groups(GroupIds=[gid,])
                            for securityGroup in sg['SecurityGroups']:
                                for rule in securityGroup['IpPermissions']:
                                    for ip in rule['IpRanges']:
                                        if ip['CidrIp'] == '0.0.0.0/0':
                                            ec2_open_traffic = "fail"
                    except Exception as e:
                        ec2_open_traffic = "pass"
                    ec2_test = "done"                    
                    json_list_ssl.append({"service": "ec2_instance_security_check_for_open_traffic", "name": instance['KeyName'], "test": ec2_open_traffic, "severity": "High"})
        except Exception as e:
            pass
        report_ec2 = ServicesReport.objects.create(service="EC2 Instance Open Traffic", scan=scan_report, report=json_ec2, test_status=ec2_test)

        # ebs checks
        ec2_client = boto3.client('ec2', **AWS_TEMP_CREDS)
        ebs_vol_encrypt_test = "unknown"
        ebs_vol_snaphot_test = "unknown"
        json_list_ebs_encrypt = []
        json_list_ebs_snapshot = []
        try:
            response = ec2_client.describe_instances() 
            ec2tags = ec2_client.describe_tags()
            for item in response['Reservations']:
                for instance_id in item['Instances']:
                    for volumes in instance_id['BlockDeviceMappings']:
                        vol_list = [vol['Ebs']['VolumeId'] for vol in instance_id['BlockDeviceMappings']]

                    volume_infos = ec2_client.describe_volumes(VolumeIds=vol_list)

                    for vol in volume_infos['Volumes']:
                        if vol['Encrypted'] == True:
                            ebs_vol_encrypt = "pass"
                            ebs_vol_snaphot = "pass"
                            ebs_vol_encrypt_test = "done"
                            ebs_vol_snaphot_test = "done"
                            json_list_ebs_encrypt.append({"service": "ebs_volume_encrypt_check", "name": instance_id['KeyName'], "test": ebs_vol_encrypt, "severity": "High"})
                            json_list_ebs_snapshot.append({"service": "ebs_volume_snapshot_check", "name": instance_id['KeyName'], "test": ebs_vol_snaphot, "severity": "High"})
        except Exception as e:
            ebs_vol_encrypt = "fail"
            ebs_vol_snaphot = "fail"
        report_ebs_1 = ServicesReport.objects.create(service="EBS Volume Encrypt", scan=scan_report, report=json_list_ebs_encrypt, test_status=ebs_vol_encrypt_test)
        report_ebs_2 = ServicesReport.objects.create(service="EBS Volume Snapshot", scan=scan_report, report=json_list_ebs_snapshot, test_status=ebs_vol_snaphot_test)

        # rds checks
        json_list_rds_encrypt = []
        json_list_rds_snapshot = []
        rds_encrypt_test = "unknown"
        rds_snapshot_test = "unknown"
        try:
            rds_client = boto3.client('rds', **AWS_TEMP_CREDS)
            rds_instances = rds_client.describe_db_instances()
            try: 
                for instance in rds_instances['DBInstances']:
                    if instance['StorageEncrypted'] == True:
                        rds_db_encrypted = "pass"
                        rds_db_subnet = "pass"
                    else:
                        rds_db_encrypted = "fail"
                        rds_db_subnet = "fail"
                    rds_encrypt_test = "done"
                    rds_snapshot_test = "done"
                    json_list_rds_encrypt.append({"service": "rds_db_encrypt_check", "name": instance['DBInstanceIdentifier'], "test": rds_db_encrypted, "severity": "High"})
                    json_list_rds_snapshot.append({"service": "rds_db_snapshot_check", "name": instance['DBInstanceIdentifier'], "test": rds_db_subnet, "severity": "High"})

            except Exception as e:
                rds_db_encrypted = "pass"
                rds_db_subnet = "pass"
        except Exception as e:
            pass
        report_rds_1 = ServicesReport.objects.create(service="RDS DB Encrypt", scan=scan_report, report=json_list_rds_encrypt, test_status=rds_encrypt_test)
        report_rds_2 = ServicesReport.objects.create(service="RDS DB Snapshot", scan=scan_report, report=json_list_rds_snapshot, test_status=rds_snapshot_test)
        
        # eks checks

        eks_check_test = "unknown"
        json_list_eks = []
        try:
            eks_client = boto3.client('eks', **AWS_TEMP_CREDS)
            eks_clusters = eks_client.list_clusters()
            for cluster in eks_clusters['clusters']:
                eks_test = "fail"
                json_list_eks.append({"service": "eks_cluster_check", "name": str(cluster), "test": eks_test, "severity": "Medium"})
        except Exception as e:
            eks_test = "pass"
        report_eks = ServicesReport.objects.create(service="EKS Cluster", scan=scan_report, report=json_list_eks, test_status=eks_check_test)
        
        # lambda checks
        json_list_lambda_func = []
        json_list_lambda_unique = []
        lambda_func_check = "unknown"
        lambda_unique_check = "unknown"
        try:
            lambda_func_test = "pass"
            lambda_unique_test = "fail"
            try:
                lambda_cleint = boto3.client('lambda', **AWS_TEMP_CREDS)
                lm_func = lambda_cleint.list_functions()
                for func in lm_func['Functions']:
                    lambda_func_test = "fail"
                    lambda_unique_test = "fail"
                    lambda_func_check = "done"
                    lambda_unique_check = "done"
                    json_list_lambda_func.append({{"service": "lambda_function_check", "name": func['Name'], "test": lambda_func_test, "severity": "High"}})
                    json_list_lambda_unique.append({{"service": "lambda_unique_check", "name": func['Name'], "test": lambda_unique_test, "severity": "Medium"}})
            except Exception as e:
                lambda_func_test = "pass"
                lambda_unique_test = "pass"
        except Exception as e:
            pass
        report_lambda_1 = ServicesReport.objects.create(service="Lambda Function", scan=scan_report, report=json_list_lambda_func, test_status=lambda_func_check)
        report_lambda_2 = ServicesReport.objects.create(service="Lambda Unique", scan=scan_report, report=json_list_lambda_unique, test_status=lambda_unique_check)
        
        report_elb_1 = ServicesReport.objects.create(service="ELB Acceess Logs", scan=scan_report, report=[], test_status="unknown")
        report_elb_2 = ServicesReport.objects.create(service="ELB Configuration", scan=scan_report, report=[], test_status="unknown")
        report_cloudtrial = ServicesReport.objects.create(service="CloudTrial", scan=scan_report, report=[], test_status="unknown")        

        return JsonResponse({"message": True})

class ScanReportsView(View):
    template_name = "dashboard/scanReport.html"

    def get(self, request):
        user = request.user
        useraws_ids = list(UserAWS.objects.filter(user=user).values_list('id', flat=True))
        scan_reports = list(ScanReports.objects.filter(account_id__in=useraws_ids).order_by('-created_at'))
        return render(request, self.template_name, {"object_list": scan_reports})

class ScanReportDetailView(View):
    template_name = "dashboard/reportdetail.html"

    def get(self, request, uuid=None):
        scan_report = ScanReports.objects.get(uuid=uuid)
        services = ServicesReport.objects.filter(scan=scan_report)
        return render(request, self.template_name, {'object_list': services, "created_at": scan_report.created_at})

class ReportDetailView(View):
    template_name = "dashboard/detail.html"

    def get(self, request, uuid=None):
        services = ServicesReport.objects.get(uuid=uuid)
        object_list = services.report
        return render(request, self.template_name, {'object_list': object_list})   

class IamPolicyView(View):
    template_name = "dashboard/iampolicies.html"

    def get(self, request):
        user = request.user
        useraws = UserAWS.objects.filter(user=user)
        return render(request, self.template_name, {"object_list": useraws})


class NodeClass(Node):
    def __init__(self, arn: str, id_value: str, attached_policies: list, group_memberships: list, trust_policy: dict, instance_profile: list, num_access_keys: int, active_password: bool, is_admin: bool, permissions_boundary: str, has_mfa: bool, tags: dict):
        super().__init__(arn, id_value, attached_policies, group_memberships, trust_policy, instance_profile, num_access_keys, active_password, is_admin, permissions_boundary, has_mfa, tags)

class EdgeClass(Edge):
    def __init__(self, source, destination, reason: str, short_reason: str):
        super().__init__(source, destination, reason, short_reason)

class PolicyClass(object):
    def __init__(self, arn: str, name: str, policy_doc: dict):
        self.arn = arn
        self.name= name
        self.policy_doc = policy_doc

class GroupClass(object):
    def __init__(self, arn: str, attached_policies: list):
        self.arn = arn
        self.attached_policies = attached_policies

class IamPolicyGraphicalView(View):

    # template_name = "dashboard/iamgraphical.html"

    def get(self, request, uuid=None):
        useraws = UserAWS.objects.get(uuid=uuid)
        AWS_CREDS = {
            "aws_access_key_id": env("AWS_ACCESS_KEY"),
            "aws_secret_access_key": env("AWS_SECRET_KEY")
        }        
        
        # Step 2: Connect to AWS STS and then call AssumeRole. This returns 
        # temporary security credentials.
        sts_connection = boto3.client('sts', **AWS_CREDS)
        assumed_role_object = sts_connection.assume_role(
            RoleArn=useraws.roleArn,
            RoleSessionName="AssumeRoleSession",
        )

        access_key = assumed_role_object.get('Credentials').get('AccessKeyId')
        secret_key = assumed_role_object.get('Credentials').get('SecretAccessKey')
        session_token = assumed_role_object.get('Credentials').get('SessionToken')
        
        AWS_TEMP_CREDS = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "aws_session_token": session_token
        }
        try:
            iam_client = boto3.client('iam', **AWS_TEMP_CREDS)
            nodes = []
            users = iam_client.list_users()
            for user in users['Users']:
                policy = iam_client.list_attached_user_policies(UserName=user['UserName'])
                group = iam_client.list_groups_for_user(UserName=user['UserName'])
                nodes.append(NodeClass(arn=user['Arn'], is_admin=True, id_value=user['UserId'], active_password=True, has_mfa=False, num_access_keys=639695405324, attached_policies=policy['AttachedPolicies'], group_memberships=group['Groups'], trust_policy=None, instance_profile=None, permissions_boundary=None, tags=None))
            roles = iam_client.list_roles()
            for role in roles['Roles']:
                policy = iam_client.list_attached_role_policies(RoleName=role['RoleName'])
                nodes.append(NodeClass(arn=role['Arn'], is_admin=True, id_value=role['RoleId'], active_password=True, has_mfa=False, num_access_keys=639695405324, attached_policies=policy['AttachedPolicies'], group_memberships=None, trust_policy=role['AssumeRolePolicyDocument'], instance_profile=None, permissions_boundary=None, tags=None))
            edges = []
            for x in range(len(nodes)):
                for y in range(len(nodes)):
                    edges.append(EdgeClass(source=nodes[x], destination=nodes[y], reason="Connect the iam policies", short_reason="Connectivity"))
            groups_list = []
            groups = iam_client.list_groups()
            for group in groups['Groups']:
                policy = iam_client.list_attached_group_policies(GroupName=group['GroupName'])
                groups_list.append(GroupClass(arn=group['Arn'], attached_policies=policy['AttachedPolicies']))
            policies = iam_client.list_policies()
            policy_list = []
            for policy in policies['Policies']:
                policy_list.append(PolicyClass(arn=policy['Arn'], name=policy['PolicyName'], policy_doc=None))
            AWS_TEMP_CREDS["account_id"]= useraws.account_number
            AWS_TEMP_CREDS["pmapper_version"] = "1.1.1"
            metadata = AWS_TEMP_CREDS
            g1 = Graph(nodes, edges, policy_list, groups_list, metadata)
            graph_writer.handle_request(g1, "/home/ubuntu/Images/graph.png", "png")
            local_image = "/home/ubuntu/Images/graph.png"
            AWS_CREDS['region_name'] = "us-east-1"
            s3 = boto3.client('s3', **AWS_CREDS)
            s3.upload_file(local_image, 'cisbucket2021', 'graph.png')
            url = "https://cisbucket2021.s3.amazonaws.com/graph.png"
            context = {"message": True, "url": url}
        except Exception as e:
            context = {'message': str(e)}
        return JsonResponse(context)