"""Read-only AWS checks. Never retrieves secret values or changes resources."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys


class CheckError(Exception):
    pass


def aws_call(region, profile, *args):
    command = ['aws', *args, '--region', region, '--output', 'json', '--no-cli-pager']
    if profile:
        command += ['--profile', profile]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60,
                                env={**os.environ, 'AWS_PAGER': '', 'AWS_CLI_AUTO_PROMPT': 'off'})
    except FileNotFoundError as exc:
        raise CheckError('AWS CLI v2 is not installed or not on PATH') from exc
    except subprocess.TimeoutExpired as exc:
        raise CheckError('AWS request timed out') from exc
    if result.returncode:
        code = re.search(r'\(([A-Za-z0-9_.-]+)\) when calling', result.stderr)
        # Raw AWS errors can contain account IDs and resource names; do not publish them.
        raise CheckError('AWS CLI error: ' + (code.group(1) if code else 'request failed'))
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckError('AWS CLI returned invalid JSON') from exc


def fresh(timestamp, now, hours=24):
    if not timestamp:
        return False
    try:
        if isinstance(timestamp, (float, int)):
            observed = datetime.fromtimestamp(timestamp, timezone.utc)
        else:
            observed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return 0 <= (now - observed).total_seconds() <= hours * 3600
    except (ValueError, TypeError, OverflowError):
        return False


def verify(call, stack, expected_account, now=None):
    now = now or datetime.now(timezone.utc)
    report = {'checked_at_utc': now.isoformat(), 'mode': 'live-read-only', 'checks': [],
              'limits': ['No secret retrieval or MFA enforcement test',
                         'No CloudTrail digest validation or event-content correlation',
                         'No vulnerability scan or phishing campaign',
                         'No budget alert delivery test; no compliance certification']}
    checks = report['checks']

    def check(name, predicate):
        try:
            passed = predicate()
            checks.append({'check': name, 'status': 'PASS' if passed else 'FAIL'})
        except (CheckError, KeyError, IndexError, TypeError, ValueError):
            checks.append({'check': name, 'status': 'ERROR', 'detail': 'Request failed or required data missing'})

    identity = call('sts', 'get-caller-identity')
    if identity.get('Account') != expected_account:
        raise CheckError('Account mismatch; stopped before inspecting lab resources')
    stacks = call('cloudformation', 'describe-stacks', '--stack-name', stack)['Stacks']
    if len(stacks) != 1:
        raise CheckError('Expected exactly one stack')
    details = stacks[0]
    out = {item['OutputKey']: item['OutputValue'] for item in details.get('Outputs', [])}
    params = {item['ParameterKey']: item.get('ParameterValue') for item in details.get('Parameters', [])}
    if any(params.get(key) not in {'true','false'} for key in ('EnableConfig','EnableGuardDuty','MultiRegionTrail')):
        raise CheckError('Required baseline feature parameters are missing or invalid')
    required = {'LogBucketName','EvidenceBucketName','KeyArn','TrailArn','SecretArn'}
    if not required <= out.keys():
        raise CheckError('Required baseline stack outputs are missing')
    check('Stack reached a successful deployment state', lambda: details.get('StackStatus') in
          {'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'IMPORT_COMPLETE'})
    bpa_flags = ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')
    def account_bpa():
        settings = call('s3control','get-public-access-block','--account-id',expected_account)['PublicAccessBlockConfiguration']
        return all(settings.get(flag) is True for flag in bpa_flags)
    check('Account S3 Block Public Access', account_bpa)
    for output, label in [('LogBucketName','Log bucket'),('EvidenceBucketName','Evidence bucket')]:
        bucket = out[output]
        def bpa(bucket=bucket):
            settings = call('s3api','get-public-access-block','--bucket',bucket)['PublicAccessBlockConfiguration']
            return all(settings.get(flag) is True for flag in bpa_flags)
        check(label + ' Block Public Access', bpa)
        check(label + ' policy not public', lambda bucket=bucket:
              call('s3api','get-bucket-policy-status','--bucket',bucket)['PolicyStatus']['IsPublic'] is False)
        def encryption(bucket=bucket):
            rules = call('s3api','get-bucket-encryption','--bucket',bucket)['ServerSideEncryptionConfiguration']['Rules']
            return len(rules) == 1 and rules[0]['ApplyServerSideEncryptionByDefault'] == {
                'SSEAlgorithm':'aws:kms','KMSMasterKeyID':out['KeyArn']}
        check(label + ' default SSE-KMS with lab key', encryption)
        check(label + ' versioning', lambda bucket=bucket:
              call('s3api','get-bucket-versioning','--bucket',bucket).get('Status') == 'Enabled')
    check('KMS key enabled', lambda: call('kms','describe-key','--key-id',out['KeyArn'])['KeyMetadata']['KeyState'] == 'Enabled')
    check('KMS rotation enabled', lambda: call('kms','get-key-rotation-status','--key-id',out['KeyArn']).get('KeyRotationEnabled') is True)
    def trail_config():
        trail = call('cloudtrail','get-trail','--name',out['TrailArn'])['Trail']
        return (trail.get('LogFileValidationEnabled') is True and trail.get('KmsKeyId') == out['KeyArn']
                and trail.get('S3BucketName') == out['LogBucketName'] and trail.get('S3KeyPrefix') == 'cloudtrail'
                and trail.get('IncludeGlobalServiceEvents') is True)
    check('CloudTrail encrypted destination and digest configuration', trail_config)
    def trail_delivery():
        status = call('cloudtrail','get-trail-status','--name',out['TrailArn'])
        return (status.get('IsLogging') is True and not status.get('LatestDeliveryError')
                and fresh(status.get('LatestDeliveryTime'), now))
    check('CloudTrail logging and delivery within 24 hours', trail_delivery)
    def management_events():
        selectors = call('cloudtrail','get-event-selectors','--trail-name',out['TrailArn']).get('EventSelectors', [])
        return any(s.get('IncludeManagementEvents') is True and s.get('ReadWriteType') == 'All'
                   and not s.get('ExcludeManagementEventSources') for s in selectors)
    check('CloudTrail read and write management events', management_events)
    if params.get('MultiRegionTrail') == 'true':
        check('CloudTrail multi-Region setting', lambda:
              call('cloudtrail','get-trail','--name',out['TrailArn'])['Trail'].get('IsMultiRegionTrail') is True)
    else:
        checks.append({'check':'CloudTrail multi-Region coverage','status':'SKIP','detail':'Single-Region scope selected'})
    check('Secret uses lab KMS key', lambda:
          call('secretsmanager','describe-secret','--secret-id',out['SecretArn']).get('KmsKeyId') == out['KeyArn'])
    if params.get('EnableConfig') == 'true':
        def recorder():
            recorders = call('configservice','describe-configuration-recorder-status',
                             '--configuration-recorder-names',out['RecorderName'])['ConfigurationRecordersStatus']
            return len(recorders) == 1 and recorders[0].get('recording') is True and recorders[0].get('lastStatus') == 'SUCCESS'
        check('Config recorder running successfully', recorder)
        for name in ('EncryptionRuleName','PublicAccessRuleName'):
            def evaluated(name=name):
                evaluations = call('configservice','get-compliance-details-by-config-rule',
                                   '--config-rule-name',out[name]).get('EvaluationResults', [])
                relevant = [e for e in evaluations if e.get('EvaluationResultIdentifier',{}).get(
                    'EvaluationResultQualifier',{}).get('ResourceId') == out['EvidenceBucketName']]
                return bool(relevant) and all(e.get('ComplianceType') == 'COMPLIANT'
                    and fresh(e.get('ResultRecordedTime'),now) for e in relevant)
            check('Config current compliant evidence: ' + name, evaluated)
    else:
        checks.append({'check':'Config recorder and rules','status':'SKIP','detail':'Not enabled for this stack'})
    if params.get('EnableGuardDuty') == 'true':
        check('GuardDuty detector enabled', lambda:
              call('guardduty','get-detector','--detector-id',out['DetectorId']).get('Status') == 'ENABLED')
    else:
        checks.append({'check':'GuardDuty detector','status':'SKIP','detail':'Not enabled for this stack'})
    report['result'] = 'FAIL' if any(c['status'] in {'FAIL','ERROR'} for c in checks) else 'PASS_WITH_LIMITS'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--expected-account', required=True, help='Dedicated lab account ID; not written to report')
    parser.add_argument('--profile')
    parser.add_argument('--output', type=Path, required=True, help='Private local JSON report destination')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,79}', args.stack):
        parser.error('Use a stack name of 1–80 letters, digits or hyphens, starting with a letter')
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', args.region):
        parser.error('Invalid AWS Region')
    if not re.fullmatch(r'\d{12}', args.expected_account):
        parser.error('Expected account must be 12 digits')
    if args.output.exists():
        parser.error('Output already exists; choose a new filename to preserve previous evidence')
    try:
        report = verify(lambda *command: aws_call(args.region,args.profile,*command),args.stack,args.expected_account)
    except (CheckError, KeyError, TypeError, IndexError) as exc:
        print(str(exc) if isinstance(exc,CheckError) else 'Required AWS response fields missing',file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')
    print(report['result'] + '; report contains configuration checks and explicit coverage limits')
    return 1 if report['result'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
