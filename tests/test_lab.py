"""Offline regressions; fixture responses are synthetic and are not AWS execution evidence."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fnmatch
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_live',ROOT/'scripts/verify_live.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
sim_spec = importlib.util.spec_from_file_location('run_local_simulation',ROOT/'scripts/run_local_simulation.py')
simulation = importlib.util.module_from_spec(sim_spec)
sim_spec.loader.exec_module(simulation)
BASE = json.loads((ROOT/'infra/baseline.json').read_text())
AUDIT = json.loads((ROOT/'infra/iam-auditor.json').read_text())
NOW = datetime(2026,10,24,12,tzinfo=timezone.utc)
KEY = 'arn:aws:kms:ap-southeast-2:111111111111:key/synthetic'


def fixture():
    outputs = {'LogBucketName':'synthetic-logs','EvidenceBucketName':'synthetic-evidence',
               'KeyArn':KEY,'TrailArn':'synthetic-trail','SecretArn':'synthetic-secret'}
    return {
      ('sts','get-caller-identity'):{'Account':'111111111111'},
      ('cloudformation','describe-stacks'):{'Stacks':[{'StackStatus':'CREATE_COMPLETE',
          'Outputs':[{'OutputKey':k,'OutputValue':v} for k,v in outputs.items()],
          'Parameters':[{'ParameterKey':k,'ParameterValue':'false'} for k in
                        ('EnableConfig','EnableGuardDuty','MultiRegionTrail')]}]},
      ('s3control','get-public-access-block'):{'PublicAccessBlockConfiguration':dict.fromkeys(
          ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'],True)},
      ('s3api','get-public-access-block'):{'PublicAccessBlockConfiguration':dict.fromkeys(
          ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'],True)},
      ('s3api','get-bucket-policy-status'):{'PolicyStatus':{'IsPublic':False}},
      ('s3api','get-bucket-encryption'):{'ServerSideEncryptionConfiguration':{'Rules':[{
          'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms','KMSMasterKeyID':KEY}}]}},
      ('s3api','get-bucket-versioning'):{'Status':'Enabled'},
      ('kms','describe-key'):{'KeyMetadata':{'KeyState':'Enabled'}},
      ('kms','get-key-rotation-status'):{'KeyRotationEnabled':True},
      ('cloudtrail','get-trail'):{'Trail':{'LogFileValidationEnabled':True,'KmsKeyId':KEY,
          'S3BucketName':'synthetic-logs','S3KeyPrefix':'cloudtrail','IncludeGlobalServiceEvents':True,'IsMultiRegionTrail':False}},
      ('cloudtrail','get-trail-status'):{'IsLogging':True,'LatestDeliveryTime':NOW.isoformat()},
      ('cloudtrail','get-event-selectors'):{'EventSelectors':[{'IncludeManagementEvents':True,'ReadWriteType':'All'}]},
      ('secretsmanager','describe-secret'):{'KmsKeyId':KEY}}


class VerificationTests(unittest.TestCase):
    def test_behavior_runner_stops_wrong_account_before_writes(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        import verify_behavior
        calls=[]
        def wrong_account(*args):
            calls.append(args)
            return {'Account':'222222222222'}
        with self.assertRaisesRegex(verify_behavior.CheckError,'Account mismatch'):
            verify_behavior.run(wrong_account,'111111111111','aws-security-lab','ap-southeast-2')
        self.assertEqual(calls,[('sts','get-caller-identity')])

    def setUp(self):
        self.responses = fixture()
        self.calls = []

    def call(self,*args):
        self.calls.append(args)
        result = self.responses[args[:2]]
        if isinstance(result,Exception):
            raise result
        return deepcopy(result)

    def run_checks(self):
        return live.verify(self.call,'aws-security-lab','111111111111',NOW)

    def test_healthy_fixture_preserves_coverage_limits(self):
        result = self.run_checks()
        self.assertEqual(result['result'],'PASS_WITH_LIMITS')
        self.assertEqual(sum(c['status']=='SKIP' for c in result['checks']),3)
        text = json.dumps(result)
        for private in ('111111111111',KEY,'synthetic-secret','synthetic-evidence'):
            self.assertNotIn(private,text)
        self.assertNotIn(('secretsmanager','get-secret-value'),[c[:2] for c in self.calls])

    def test_wrong_account_stops_before_resource_reads(self):
        self.responses[('sts','get-caller-identity')]['Account']='222222222222'
        with self.assertRaisesRegex(live.CheckError,'Account mismatch'):
            self.run_checks()
        self.assertEqual(len(self.calls),1)

    def test_access_denied_is_error_not_pass(self):
        self.responses[('s3api','get-public-access-block')]=live.CheckError('AccessDenied')
        result=self.run_checks()
        self.assertEqual(result['result'],'FAIL')
        self.assertEqual(sum(c['status']=='ERROR' for c in result['checks']),2)

    def test_one_missing_public_access_flag_fails(self):
        del self.responses[('s3api','get-public-access-block')]['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_other_kms_key_fails(self):
        self.responses[('s3api','get-bucket-encryption')]['ServerSideEncryptionConfiguration']['Rules'][0][
            'ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']='other-key'
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_stale_delivery_fails_even_when_logging_true(self):
        self.responses[('cloudtrail','get-trail-status')]['LatestDeliveryTime']=(NOW-timedelta(days=2)).isoformat()
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_delivery_error_fails_even_with_recent_delivery(self):
        self.responses[('cloudtrail','get-trail-status')]['LatestDeliveryError']='AccessDenied'
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_excluded_management_source_fails(self):
        self.responses[('cloudtrail','get-event-selectors')]['EventSelectors'][0]['ExcludeManagementEventSources']=['kms.amazonaws.com']
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_rollback_is_not_success(self):
        self.responses[('cloudformation','describe-stacks')]['Stacks'][0]['StackStatus']='ROLLBACK_COMPLETE'
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_config_no_evaluations_cannot_pass(self):
        stack=self.responses[('cloudformation','describe-stacks')]['Stacks'][0]
        stack['Parameters'][0]['ParameterValue']='true'
        stack['Outputs'] += [{'OutputKey':k,'OutputValue':'synthetic-'+k} for k in
                             ['RecorderName','EncryptionRuleName','PublicAccessRuleName']]
        self.responses[('configservice','describe-configuration-recorder-status')]={
            'ConfigurationRecordersStatus':[{'recording':True,'lastStatus':'SUCCESS'}]}
        self.responses[('configservice','get-compliance-details-by-config-rule')]={'EvaluationResults':[]}
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_missing_stack_outputs_is_fatal(self):
        self.responses[('cloudformation','describe-stacks')]['Stacks'][0]['Outputs']=[]
        with self.assertRaisesRegex(live.CheckError,'outputs are missing'):
            self.run_checks()

    def test_missing_feature_parameters_is_fatal(self):
        self.responses[('cloudformation','describe-stacks')]['Stacks'][0]['Parameters']=[]
        with self.assertRaisesRegex(live.CheckError,'feature parameters'):
            self.run_checks()

    def test_enabled_optional_features_require_current_results(self):
        stack=self.responses[('cloudformation','describe-stacks')]['Stacks'][0]
        for parameter in stack['Parameters']:
            parameter['ParameterValue']='true'
        stack['Outputs'] += [{'OutputKey':k,'OutputValue':'synthetic-'+k} for k in
                             ['RecorderName','EncryptionRuleName','PublicAccessRuleName','DetectorId']]
        self.responses[('cloudtrail','get-trail')]['Trail']['IsMultiRegionTrail']=True
        self.responses[('configservice','describe-configuration-recorder-status')]={
            'ConfigurationRecordersStatus':[{'recording':True,'lastStatus':'SUCCESS'}]}
        self.responses[('configservice','get-compliance-details-by-config-rule')]={'EvaluationResults':[{
            'EvaluationResultIdentifier':{'EvaluationResultQualifier':{'ResourceId':'synthetic-evidence'}},
            'ComplianceType':'COMPLIANT','ResultRecordedTime':NOW.isoformat()}]}
        self.responses[('guardduty','get-detector')]={'Status':'ENABLED'}
        self.assertEqual(self.run_checks()['result'],'PASS_WITH_LIMITS')
        self.responses[('configservice','get-compliance-details-by-config-rule')]['EvaluationResults'][0]['ComplianceType']='INSUFFICIENT_DATA'
        self.assertEqual(self.run_checks()['result'],'FAIL')

    def test_future_and_naive_delivery_timestamps_fail(self):
        self.assertFalse(live.fresh((NOW+timedelta(minutes=5)).isoformat(),NOW))
        self.assertFalse(live.fresh('2026-10-24T12:00:00',NOW))
        self.assertFalse(live.fresh(None,NOW))

    @patch.object(live.subprocess,'run')
    def test_cli_uses_argument_array_and_redacts_errors(self,run):
        run.return_value=subprocess.CompletedProcess([],1,'','An error occurred (AccessDenied) when calling Get: private-secret')
        with self.assertRaisesRegex(live.CheckError,'^AWS CLI error: AccessDenied$'):
            live.aws_call('ap-southeast-2',None,'sts','get-caller-identity')
        args,kwargs=run.call_args
        self.assertIsInstance(args[0],list)
        self.assertNotIn('shell',kwargs)


def condition_matches(conditions,context):
    """Small test model for these policies only; not an IAM simulator."""
    for operator,entries in conditions.items():
        for key,expected in entries.items():
            value=context.get(key)
            if operator=='Null': ok=(value is None)==(expected=='true')
            elif operator=='StringEquals': ok=value==expected
            elif operator=='StringNotEquals': ok=value!=expected
            elif operator=='Bool': ok=value==expected
            elif operator=='StringLike': ok=value is not None and fnmatch.fnmatchcase(value,expected)
            else: raise AssertionError(operator)
            if not ok: return False
    return True


class PolicyBoundaryTests(unittest.TestCase):
    def test_config_recorder_waits_for_channel_before_start(self):
        # Create the stopped recorder, then its channel; start recording after both exist.
        self.assertIs(BASE['Resources']['Recorder']['Properties']['StartedOnCreate'],False)
        self.assertIn('Recorder',BASE['Resources']['DeliveryChannel']['DependsOn'])

    def test_simulation_refuses_external_tracking_targets(self):
        self.assertEqual(simulation.safe_click('http://gophish:8080/?rid=synthetic123'),
                         'http://gophish:8080/?rid=synthetic123')
        for url in ('http://example.com/?rid=abc','http://gophish:8080.evil.test/?rid=abc',
                    'https://gophish:8080/?rid=abc','http://gophish:8080/?rid=a&next=evil',
                    'http://gophish:8080/admin?rid=abc'):
            with self.assertRaises(ValueError):
                simulation.safe_click(url)

    def test_evidence_encryption_headers(self):
        statements=BASE['Resources']['EvidenceBucketPolicy']['Properties']['PolicyDocument']['Statement'][1:]
        rendered=json.loads(json.dumps(statements).replace(json.dumps({'Fn::GetAtt':['LabKey','Arn']}),'"expected-key"'))
        def denied(headers):
            context={'s3:'+k:v for k,v in headers.items()}
            return any(condition_matches(s['Condition'],context) for s in rendered)
        self.assertFalse(denied({})) # Bucket default applies.
        self.assertFalse(denied({'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':'expected-key'}))
        self.assertTrue(denied({'x-amz-server-side-encryption':'AES256'}))
        self.assertTrue(denied({'x-amz-server-side-encryption':'aws:kms'}))
        self.assertTrue(denied({'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':'other-key'}))

    def test_mfa_trust_rejects_missing_false_and_other_account(self):
        trust=AUDIT['Resources']['Auditor']['Properties']['AssumeRolePolicyDocument']['Statement'][0]
        condition=json.loads(json.dumps(trust['Condition']).replace(json.dumps({'Ref':'AWS::AccountId'}),'"111111111111"'))
        for mfa in (None,'false'):
            self.assertFalse(condition_matches(condition,{'aws:MultiFactorAuthPresent':mfa,'aws:PrincipalAccount':'111111111111'}))
        self.assertFalse(condition_matches(condition,{'aws:MultiFactorAuthPresent':'true','aws:PrincipalAccount':'222222222222'}))
        self.assertTrue(condition_matches(condition,{'aws:MultiFactorAuthPresent':'true','aws:PrincipalAccount':'111111111111'}))

    def test_auditor_cannot_write_or_read_secret(self):
        statements=AUDIT['Resources']['Auditor']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        actions={a for s in statements for a in ([s['Action']] if isinstance(s['Action'],str) else s['Action'])}
        self.assertEqual(actions,{'s3:ListBucket','s3:GetObject','kms:Decrypt'})
        self.assertTrue(all(s['Resource']!='*' for s in statements))

    def test_trail_service_grants_require_specific_trail(self):
        statements=BASE['Resources']['LabKey']['Properties']['KeyPolicy']['Statement']
        for sid in ('TrailEncrypt','TrailDescribe'):
            grant=next(s for s in statements if s.get('Sid')==sid)
            self.assertIn('aws:SourceArn',grant['Condition']['StringEquals'])

    def test_paid_optional_features_off_and_evidence_retained(self):
        for key in ('EnableConfig','EnableGuardDuty','MultiRegionTrail'):
            self.assertEqual(BASE['Parameters'][key]['Default'],'false')
        for name in ('LabKey','LogBucket','EvidenceBucket','LabSecret'):
            self.assertEqual(BASE['Resources'][name]['DeletionPolicy'],'Retain')
        for bucket in ('LogBucket','EvidenceBucket'):
            self.assertEqual(set(BASE['Resources'][bucket]['Properties']['PublicAccessBlockConfiguration'].values()),{True})


if __name__=='__main__':
    unittest.main()
