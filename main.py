import json
import pandas as pd
import subprocess
import uuid
from rapidfuzz import fuzz
import boto3
import datetime
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
import getpass
import glob
from pathlib import Path

session = None

regions = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "me-south-1",
    "me-central-1",
    "af-south-1",
    "sa-east-1"
]

CONTROLS = [

# ---------- CUSTOM CONTROLS ----------

{
"id": 1,
"name": "Ensure root account has MFA enabled",
"type": "custom",
"function": "check_root_mfa",
"rationale": "Root account has unrestricted privileges and must be strongly protected using multi-factor authentication.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
},

{
"id": 3,
"name": "Ensure unused IAM credentials are disabled after 45 days",
"type": "custom",
"function": "check_unused_iam_credentials",
"rationale": "Unused credentials increase the risk of unauthorized access and should be disabled if inactive for extended periods.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"
},

{
"id": 4,
"name": "Ensure IAM password policy expires passwords ≤90 days",
"type": "custom",
"function": "check_password_expiry",
"rationale": "Regular password rotation reduces the risk of compromised credentials being used for long periods.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
},

{
"id": 5,
"name": "Ensure IAM access keys are rotated every 90 days",
"type": "custom",
"function": "check_access_key_rotation",
"rationale": "Regular rotation of access keys limits the impact of compromised credentials.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
},

{
"id": 6,
"name": "Ensure ACM certificates are not close to expiration",
"type": "custom",
"function": "check_acm_expiry",
"rationale": "Expired certificates may cause service disruptions and security warnings for users.",
"reference": "https://docs.aws.amazon.com/acm/latest/userguide/acm-bestpractices.html"
},

{
"id": 7,
"name": "Ensure CloudTrail is enabled in all regions and integrates with CloudWatch",
"type": "custom",
"function": "check_cloudtrail_multi_region",
"rationale": "CloudTrail logging ensures visibility into API activity across the AWS account for auditing and incident response.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html"
},

{
"id": 14,
"name": "Ensure there are no SNS topics unencrypted",
"type": "custom",
"function": "check_sns_encryption",
"rationale": "Encryption protects sensitive notification data stored within SNS topics.",
"reference": "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html"
},

{
"id": 15,
"name": "Enable termination protection for CloudFormation stacks",
"type": "custom",
"function": "check_cf_termination_protection",
"rationale": "Termination protection prevents accidental deletion of critical infrastructure deployed via CloudFormation.",
"reference": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html"
},

{
"id": 16,
"name": "Ensure AWS WAFv2 Web ACL logging is enabled",
"type": "custom",
"function": "check_waf_logging",
"rationale": "WAF logging enables monitoring of blocked and allowed traffic for threat detection and forensic analysis.",
"reference": "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html"
},

{
"id": 17,
"name": "Ensure CloudWatch log groups are encrypted using KMS CMKs",
"type": "custom",
"function": "check_loggroup_encryption",
"rationale": "Encrypting CloudWatch log groups ensures that sensitive log data is protected at rest.",
"reference": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html"
},

{
"id": 19,
"name": "Remove unused security groups",
"type": "custom",
"function": "check_unused_security_groups",
"rationale": "Unused security groups increase management overhead and may introduce unintended exposure if misconfigured.",
"reference": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
},

{
"id": 20,
"name": "DynamoDB table should have point in recovery enabled",
"type": "custom",
"function": "check_dynamodb_pitr",
"rationale": "Point-in-time recovery allows restoration of DynamoDB tables after accidental writes or deletions.",
"reference": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html"
},

{
"id": 24,
"name": "Secrets should be rotated periodically",
"type": "custom",
"function": "check_secrets_rotation",
"rationale": "Regular secret rotation reduces the impact of compromised credentials.",
"reference": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html"
},

# ---------- PROWLER CONTROLS ----------

{
"id": 2,
"name": "Ensure MFA is enabled for all IAM users with console access",
"type": "prowler",
"match": ["IAM user has MFA enabled"],
"rationale": "Multi-factor authentication adds an additional layer of protection against credential compromise.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"
},

{
"id": 9,
"name": "Ensure S3 buckets are not publicly accessible",
"type": "prowler",
"match": ["S3 bucket policy does not allow public"],
"rationale": "Public S3 buckets can expose sensitive data and should be restricted unless explicitly required.",
"reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
},

{
"id": 10,
"name": "Ensure S3 bucket versioning is enabled",
"type": "prowler",
"match": ["S3 bucket versioning"],
"rationale": "Versioning protects against accidental deletion or overwriting of objects.",
"reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
},

{
"id": 11,
"name": "Security group does not have all ports open to the Internet",
"type": "prowler",
"match": ["Security group does not have all ports open"],
"rationale": "Allowing all ports from the Internet increases the attack surface and should be restricted.",
"reference": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
},

{
"id": 12,
"name": "Security group does not allow ingress from 0.0.0.0/0 to high-risk ports",
"type": "prowler",
"match": ["Security group allows ingress from internet"],
"rationale": "Restricting high-risk ports such as SSH and RDP prevents unauthorized remote access.",
"reference": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
},

{
"id": 13,
"name": "Ensure RDS Multi-AZ deployment is enabled",
"type": "prowler",
"match": ["RDS instance has Multi-AZ enabled"],
"rationale": "Multi-AZ deployments improve database availability and resilience.",
"reference": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"
},

{
"id": 22,
"name": "ECR registry scan on push enabled",
"type": "prowler",
"match": ["ECR repository scan on push"],
"rationale": "Image scanning helps detect vulnerabilities before deployment.",
"reference": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
},

{
"id": 23,
"name": "Ensure there are no Public Accessible RDS instances",
"type": "prowler",
"match": ["RDS instance is publicly accessible"],
"rationale": "Databases exposed to the public Internet increase the risk of unauthorized access.",
"reference": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
},

{
"id": 25,
"name": "Ensure IAM password policy requires minimum length ≥14",
"type": "prowler",
"match": ["passwords to be at least 14 characters"],
"rationale": "Longer passwords significantly reduce the risk of brute-force attacks.",
"reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
},

{
"id": 26,
"name": "Ensure CloudTrail log file validation is enabled",
"type": "prowler",
"match": ["CloudTrail trail has log file validation enabled"],
"rationale": "Log file validation ensures the integrity of CloudTrail logs.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
},

{
"id": 27,
"name": "Ensure CloudTrail logs are encrypted using KMS",
"type": "prowler",
"match": ["CloudTrail trail logs are encrypted"],
"rationale": "Encrypting audit logs protects sensitive activity data from unauthorized access.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-encryption.html"
},

{
"id": 28,
"name": "Ensure S3 bucket server-side encryption is enabled",
"type": "prowler",
"match": ["S3 bucket has default server-side encryption"],
"rationale": "Server-side encryption ensures that stored data is protected at rest.",
"reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
},

{
"id": 29,
"name": "Ensure S3 access logging is enabled",
"type": "prowler",
"match": ["S3 bucket has server access logging"],
"rationale": "Access logging provides visibility into requests made to S3 buckets.",
"reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
},

{
"id": 30,
"name": "Ensure S3 lifecycle policies are configured",
"type": "prowler",
"match": ["S3 bucket lifecycle"],
"rationale": "Lifecycle policies help manage storage costs and enforce data retention policies.",
"reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"
},

{
"id": 31,
"name": "Ensure VPC Flow Logs are enabled",
"type": "prowler",
"match": ["VPC flow logs are enabled"],
"rationale": "VPC Flow Logs provide network visibility for troubleshooting and security monitoring.",
"reference": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
},

{
"id": 32,
"name": "Ensure EC2 instances do not use public IP unless required",
"type": "prowler",
"match": ["EC2 instance does not have a public IP"],
"rationale": "Limiting public IP usage reduces exposure to the Internet.",
"reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html"
},

{
"id": 33,
"name": "Ensure EBS volumes are encrypted",
"type": "prowler",
"match": ["EBS volume is encrypted"],
"rationale": "Encryption protects data stored on EBS volumes.",
"reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
},

{
"id": 34,
"name": "Ensure EBS snapshots are encrypted",
"type": "prowler",
"match": ["EBS snapshot is encrypted"],
"rationale": "Encrypting snapshots ensures backups are protected.",
"reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html"
},

{
"id": 35,
"name": "Ensure EC2 instances have monitoring enabled",
"type": "prowler",
"match": ["EC2 instance has detailed monitoring"],
"rationale": "Detailed monitoring provides improved operational visibility.",
"reference": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html"
},

{
"id": 36,
"name": "Ensure RDS storage encryption is enabled",
"type": "prowler",
"match": ["RDS DB instance storage is encrypted"],
"rationale": "Encryption protects database storage from unauthorized access.",
"reference": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
},

{
"id": 37,
"name": "Ensure RDS deletion protection is enabled",
"type": "prowler",
"match": ["RDS instance has deletion protection"],
"rationale": "Deletion protection prevents accidental removal of critical databases.",
"reference": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"
},

{
"id": 38,
"name": "Ensure CloudWatch alarms for unauthorized API calls",
"type": "prowler",
"match": ["unauthorized API calls"],
"rationale": "Monitoring unauthorized API calls helps detect potential security incidents.",
"reference": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
},

{
"id": 39,
"name": "Ensure CloudWatch alarms for root account usage",
"type": "prowler",
"match": ["root account usage"],
"rationale": "Root account usage should be monitored due to its high privileges.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"
},

{
"id": 40,
"name": "Ensure CloudWatch alarms for IAM policy changes",
"type": "prowler",
"match": ["IAM policy changes"],
"rationale": "Monitoring IAM policy changes helps detect unauthorized privilege escalation.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"
},

{
"id": 41,
"name": "Ensure CloudWatch alarms for security group changes",
"type": "prowler",
"match": ["security group changes"],
"rationale": "Monitoring security group changes helps detect potential network exposure.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"
},

{
"id": 42,
"name": "Ensure CloudWatch alarms for CloudTrail configuration changes",
"type": "prowler",
"match": ["CloudTrail configuration changes"],
"rationale": "Monitoring CloudTrail configuration changes ensures logging cannot be tampered with unnoticed.",
"reference": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html"
},

{
"id": 43,
"name": "Ensure CloudWatch alarms for AWS Config changes",
"type": "prowler",
"match": ["AWS Config configuration changes"],
"rationale": "Monitoring AWS Config changes helps ensure compliance monitoring remains enabled.",
"reference": "https://docs.aws.amazon.com/config/latest/developerguide/monitor-config.html"
},

# ---------- MANUAL CONTROL ----------

{
"id": 8,
"name": "Ensure Lambda environment variables do not store secrets",
"type": "manual",
"rationale": "Sensitive credentials should not be stored in Lambda environment variables; use Secrets Manager instead.",
"reference": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html"
}

]


def parse_results(json_file):

    findings = []

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:

        resources = item.get("Resources", [{}])
        resource = resources[0] if resources else {}

        service = (
            item.get("ProductFields", {}).get("ServiceName")
            or resource.get("Type", "")
        )

        region = item.get("Region") or resource.get("Region", "")

        finding = {
            "CHECK_TITLE": item.get("Title", ""),
            "STATUS": item.get("Compliance", {}).get("Status", ""),
            "SEVERITY": item.get("Severity", {}).get("Label", "").upper(),
            "SERVICE": service,
            "RESOURCE_TYPE": resource.get("Type", ""),
            "RESOURCE_ID": resource.get("Id", ""),
            "REGION": region,
            "DESCRIPTION": item.get("Description", ""),
            "REMEDIATION": item.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
            "REFERENCE": item.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
        }

        findings.append(finding)

    df = pd.DataFrame(findings)

    # Remove NaN → prevents black Excel cells
    df = df.fillna("")

    return df


def run_prowler(access_key, secret_key, region):

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_DEFAULT_REGION"] = region

    cmd = [
    "python", "-m", "prowler", "aws",
    "--region", region,
    "--output-formats", "json-asff",
    "--output-directory", ".",
    "--no-banner"
]

    print("\nExecuting command:")
    print(" ".join(cmd))

    process = subprocess.Popen(cmd, env=env)
    process.wait()

    print("\nProwler scan finished.")


def generate_full_report(df):

    report_name = f"prowler_full_report_{uuid.uuid4().hex[:6]}.xlsx"

    df.to_excel(report_name, index=False)

    return report_name


import pandas as pd
import uuid


def generate_client_audit_report(df):

    # Run controls
    control_results, covered_checks = run_controls(df)

    # Get additional findings
    prowler_findings = get_high_critical_findings(df, covered_checks)

    findings_output = []

    row_counter = 1

    # -------------------------------
    # SECTION 1: FTR CONTROLS
    # -------------------------------
    findings_output.append({
        "#": "",
        "Identified": "SECTION 1 — Foundational Technical Review Controls",
        "Comments/Rationale": "",
        "AnkerCloud Effort": "",
        "Reference Links": "",
        "Affected resource": ""
    })

    for result in control_results:

        resources = [r for r in result.get("resources", []) if r]

        if resources and resources != ["Manual Review Required"]:
            resource_text = "- " + "\n- ".join(resources)
        else:
            resource_text = "Manual review required"

        findings_output.append({
            "#": row_counter,
            "Identified": result.get("control", ""),
            "Comments/Rationale": result.get("rationale", ""),
            "AnkerCloud Effort": "",
            "Reference Links": result.get("reference", ""),
            "Affected resource": resource_text
        })

        row_counter += 1

    # Spacer row
    findings_output.append({
        "#": "",
        "Identified": "",
        "Comments/Rationale": "",
        "AnkerCloud Effort": "",
        "Reference Links": "",
        "Affected resource": ""
    })

    # -------------------------------
    # SECTION 2: ADDITIONAL FINDINGS
    # -------------------------------
    findings_output.append({
        "#": "",
        "Identified": "SECTION 2 — Additional High / Critical Security Findings",
        "Comments/Rationale": "",
        "AnkerCloud Effort": "",
        "Reference Links": "",
        "Affected resource": ""
    })

    for result in prowler_findings:

        resources = [r for r in result.get("resources", []) if r]

        if resources:
            resource_text = "- " + "\n- ".join(resources)
        else:
            resource_text = "N/A"

        findings_output.append({
            "#": row_counter,
            "Identified": result.get("control", ""),
            "Comments/Rationale": result.get("description", ""),
            "AnkerCloud Effort": "",
            "Reference Links": "",
            "Affected resource": resource_text
        })

        row_counter += 1

    # Convert to DataFrame
    audit_df = pd.DataFrame(findings_output)

    report_name = f"Client_Audit_Report_{uuid.uuid4().hex[:6]}.xlsx"

    with pd.ExcelWriter(report_name, engine="xlsxwriter") as writer:

        audit_df.to_excel(writer, index=False, sheet_name="Audit Report")

        workbook = writer.book
        worksheet = writer.sheets["Audit Report"]

        header_format = workbook.add_format({
            "bold": True,
            "font_color": "white",
            "bg_color": "black",
            "align": "center",
            "valign": "vcenter"
        })

        section_format = workbook.add_format({
            "bold": True,
            "font_size": 12
        })

        wrap_format = workbook.add_format({
            "text_wrap": True
        })

        # Header styling
        for col_num, column in enumerate(audit_df.columns):
            worksheet.write(0, col_num, column, header_format)

        # Apply section formatting
        for row_num in range(1, len(audit_df) + 1):
            value = audit_df.iloc[row_num - 1]["Identified"]
            if "SECTION" in str(value):
                worksheet.set_row(row_num, None, section_format)

        # Column widths
        worksheet.set_column("A:A", 5)
        worksheet.set_column("B:B", 50)
        worksheet.set_column("C:C", 70, wrap_format)
        worksheet.set_column("D:D", 20)
        worksheet.set_column("E:E", 50)
        worksheet.set_column("F:F", 50, wrap_format)

    return report_name

def run_scan(access_key, secret_key, region):

    run_prowler(access_key, secret_key, region)

    json_files = glob.glob("*.json")

    global session

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    if not json_files:
        raise Exception("No Prowler JSON results found")

    latest_json = max(json_files, key=os.path.getctime)

    df = parse_results(latest_json)

    # Normalize ASFF → flat columns
    df["SEVERITY"] = df.get("Severity.Label", df.get("SEVERITY", "UNKNOWN"))
    df["STATUS"] = df.get("Compliance.Status", df.get("STATUS", "UNKNOWN"))
    df["CHECK_TITLE"] = df.get("Title", df.get("CHECK_TITLE", "UNKNOWN"))

    def extract_resource(r):
        try:
            if isinstance(r, list) and len(r) > 0:
                return r[0].get("Id", "UNKNOWN")
        except:
            return "UNKNOWN"
        return "UNKNOWN"

    if "Resources" in df.columns:
        df["RESOURCE_ID"] = df["Resources"].apply(extract_resource)

    # ================== END BLOCK ==================

    full_report = generate_full_report(df)
    audit_report = generate_client_audit_report(df)

    return full_report, audit_report



os.environ["PYTHONIOENCODING"] = "utf-8"


def check_root_mfa():

    iam = session.client("iam")
    summary = iam.get_account_summary()

    if summary["SummaryMap"]["AccountMFAEnabled"] == 1:
        return "PASSED", []

    return "FAILED", ["Root account"]


def check_unused_iam_credentials():

    iam = boto3.client("iam")
    users = iam.list_users()["Users"]

    failed = []

    for user in users:

        user_name = user["UserName"]

        access_keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

        for key in access_keys:

            last_used = iam.get_access_key_last_used(
                AccessKeyId=key["AccessKeyId"]
            )

            last_used_date = last_used["AccessKeyLastUsed"].get("LastUsedDate")

            if last_used_date:
                age = (datetime.datetime.now(datetime.timezone.utc) - last_used_date).days

                if age > 45:
                    failed.append(user_name)

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_password_expiry():

    iam = boto3.client("iam")

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MaxPasswordAge", 999) <= 90:
            return "PASSED", []

        return "FAILED", ["Password policy"]

    except:
        return "FAILED", ["Password policy not configured"]


def check_access_key_rotation():

    iam = boto3.client("iam")
    users = iam.list_users()["Users"]

    failed = []

    for user in users:

        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]

        for key in keys:

            age = (datetime.datetime.now(datetime.timezone.utc) - key["CreateDate"]).days

            if age > 90:
                failed.append(user["UserName"])

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_acm_expiry():

    acm = session.client("acm")

    certs = acm.list_certificates()["CertificateSummaryList"]

    failed = []

    for cert in certs:

        detail = acm.describe_certificate(
            CertificateArn=cert["CertificateArn"]
        )

        certificate = detail.get("Certificate", {})

        # Skip certificates not issued
        if certificate.get("Status") != "ISSUED":
            continue

        expiry = certificate.get("NotAfter")

        if not expiry:
            continue

        days = (expiry - datetime.datetime.now(datetime.timezone.utc)).days

        if days < 30:
            failed.append(cert["DomainName"])

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_cloudtrail_multi_region():

    cloudtrail = session.client("cloudtrail")

    trails = cloudtrail.describe_trails()["trailList"]

    failed = []

    for trail in trails:

        if not trail.get("IsMultiRegionTrail"):
            failed.append(trail["Name"])

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_sns_encryption():

    sns = session.client("sns")
    topics = sns.list_topics()["Topics"]

    failed = []

    for topic in topics:

        attr = sns.get_topic_attributes(
            TopicArn=topic["TopicArn"]
        )

        if "KmsMasterKeyId" not in attr["Attributes"]:
            failed.append(topic["TopicArn"])

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_cf_termination_protection():

    cf = session.client("cloudformation")

    failed = []

    try:

        stacks = cf.list_stacks()["StackSummaries"]

        for stack in stacks:

            stack_name = stack.get("StackName")
            stack_status = stack.get("StackStatus")

            # Skip deleted stacks
            if stack_status == "DELETE_COMPLETE":
                continue

            try:

                detail = cf.describe_stacks(StackName=stack_name)

                termination = detail["Stacks"][0].get("EnableTerminationProtection", False)

                if not termination:
                    failed.append(stack_name)

            except Exception:
                continue

    except Exception as e:

        print(f"CloudFormation check failed: {e}")
        return "PASSED", []

    if failed:
        return "FAILED", failed

    return "PASSED", []



def check_waf_logging():

    waf = session.client("wafv2")

    failed = []

    try:

        acls = waf.list_web_acls(
            Scope="REGIONAL"
        )["WebACLs"]

        for acl in acls:

            logging = waf.get_logging_configuration(
                ResourceArn=acl["ARN"]
            )

            if not logging.get("LoggingConfiguration"):
                failed.append(acl["Name"])

    except:
        pass

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_loggroup_encryption():

    logs = session.client("logs")

    groups = logs.describe_log_groups()["logGroups"]

    failed = []

    for g in groups:

        if "kmsKeyId" not in g:
            failed.append(g["logGroupName"])

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_unused_security_groups():

    ec2 = session.client("ec2")

    failed = []

    try:

        groups = ec2.describe_security_groups()["SecurityGroups"]

        for g in groups:

            group_id = g.get("GroupId")
            group_name = g.get("GroupName")

            # Skip default security groups
            if group_name == "default":
                continue

            ingress = g.get("IpPermissions", [])
            egress = g.get("IpPermissionsEgress", [])

            # If both ingress and egress rules are empty → likely unused
            if not ingress and not egress:
                failed.append(group_id)

    except Exception as e:
        print(f"Security group check failed: {e}")
        return "PASSED", []

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_dynamodb_pitr():

    dynamodb = session.client("dynamodb")

    tables = dynamodb.list_tables()["TableNames"]

    failed = []

    for table in tables:

        backup = dynamodb.describe_continuous_backups(
            TableName=table
        )

        status = backup["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]

        if status != "ENABLED":
            failed.append(table)

    if failed:
        return "FAILED", failed

    return "PASSED", []


def check_secrets_rotation():

    sm = session.client("secretsmanager")

    secrets = sm.list_secrets()["SecretList"]

    failed = []

    for secret in secrets:

        if not secret.get("RotationEnabled"):
            failed.append(secret["Name"])

    if failed:
        return "FAILED", failed

    return "PASSED", []

from concurrent.futures import ThreadPoolExecutor


def run_controls(df):

    covered_checks = set()
    results = []

    # ---------- PROWLER CONTROLS ----------

    for control in CONTROLS:

        if control["type"] == "prowler":
            
            covered_checks.update(control["match"])
            matches = df[
                df["CHECK_TITLE"].str.contains(
                    "|".join(control["match"]),
                    case=False,
                    na=False
                )
            ]

            failed = matches[matches["STATUS"] == "FAILED"]

            if not failed.empty:

                resources = []

                for _, row in failed.iterrows():

                    resource = str(row["RESOURCE_ID"])

                    if "/" in resource:
                        resource = resource.split("/")[-1]

                    resources.append(resource)

                resources = sorted(list(set(resources)))

                results.append({
                    "control": control["name"],
                    "rationale": control.get("rationale", ""),
                    "reference": control.get("reference", ""),
                    "description": failed.iloc[0]["DESCRIPTION"],
                    "resources": resources
                })

    # ---------- CUSTOM CONTROLS (PARALLEL EXECUTION) ----------

    custom_controls = [c for c in CONTROLS if c["type"] == "custom"]

    with ThreadPoolExecutor(max_workers=8) as executor:

        futures = {}

        for control in custom_controls:

            func = globals()[control["function"]]

            futures[executor.submit(func)] = control

        for future in futures:

            control = futures[future]

            try:

                status, resources = future.result()

                if status == "FAILED":

                    results.append({
                        "control": control["name"],
                        "rationale": control.get("rationale", ""),
                        "reference": control.get("reference", ""),
                        "resources": resources,
                    })

            except Exception as e:

                print(f"Custom check failed for '{control['name']}': {e}")

                results.append({
                    "control": control["name"],
                    "rationale": control.get("rationale", ""),
                    "reference": control.get("reference", ""),
                    "resources": ["Check failed during execution"]
                })

    # ---------- MANUAL CONTROLS ----------

    for control in CONTROLS:

        if control["type"] == "manual":

            results.append({
                "control": control["name"],
                "resources": ["Manual Review Required"]
            })

    return results, covered_checks

def get_high_critical_findings(df, covered_checks):

    findings = []

    # ✅ Safe filtering (handles FAIL / FAILED / casing issues)
    filtered = df[
        (df["SEVERITY"].astype(str).str.upper().isin(["HIGH", "CRITICAL"])) &
        (df["STATUS"].astype(str).str.upper().isin(["FAIL", "FAILED"]))
    ]

    # 🧪 Debug (optional – remove later)
    print("DEBUG - Filtered High/Critical Count:", len(filtered))

    # ✅ Group by check title
    grouped = filtered.groupby("CHECK_TITLE")

    for title, group in grouped:

        # ✅ Skip controls already covered in Section 1
        if any(match.lower() in str(title).lower() for match in covered_checks):
            continue

        resources = []

        for r in group["RESOURCE_ID"].dropna().unique():

            r = str(r)

            if "/" in r:
                r = r.split("/")[-1]

            resources.append(r)

        findings.append({
            "control": str(title),
            "resources": resources if resources else ["No resource identified"],
            "description": str(group.iloc[0].get("DESCRIPTION", "")),
            "rationale": "",
            "reference": ""
        })

    return findings

def main():

    try:
        print("=== AWS FTR Tool ===\n")

        access_key = input("Enter AWS Access Key: ").strip()
        secret_key = input("Enter AWS Secret Key: ").strip()

        # Valid AWS regions (you can expand later if needed)
        valid_regions = [
            "us-east-1","us-east-2","us-west-1","us-west-2",
            "ap-south-1","ap-south-2","ap-southeast-1","ap-southeast-2",
            "ap-northeast-1","ap-northeast-2","ap-northeast-3",
            "eu-west-1","eu-west-2","eu-west-3",
            "eu-central-1","eu-central-2",
            "eu-north-1","eu-south-1",
            "me-south-1","me-central-1",
            "af-south-1","sa-east-1"
        ]

        # 🔁 Keep asking until valid region is entered
        while True:
            region = input("Enter AWS region (e.g. us-east-1): ").strip()

            if region in valid_regions:
                break
            else:
                print("❌ Invalid region. Please try again.\n")

        print("\n🚀 Running scan... please wait...\n")

        # Run scan
        full_report, audit_report = run_scan(access_key, secret_key, region)

        print("✅ Scan completed successfully!\n")
        print(f"Full Prowler Report:\n{full_report}\n")
        print(f"Audited Security Report:\n{audit_report}\n")

    except Exception as e:
        print("❌ Scan failed:\n")
        print(str(e))


if __name__ == "__main__":
    main()