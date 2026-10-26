"""Writes one harmless lab object; checks encryption denials and administrator secret retrieval.

Does not print secret values or establish restricted-identity/MFA enforcement.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from urllib.error import HTTPError
from urllib.request import urlopen
from uuid import uuid4
from verify_live import aws_call, CheckError


def run(call, expected_account, stack, region):
    identity=call('sts','get-caller-identity')
    if identity.get('Account')!=expected_account:
        raise CheckError('Account mismatch; no test object written')
    details=call('cloudformation','describe-stacks','--stack-name',stack)['Stacks'][0]
    outputs={v['OutputKey']:v['OutputValue'] for v in details['Outputs']}
    bucket=outputs['EvidenceBucketName']
    key='verification/'+uuid4().hex+'.txt'
    results=[]
    with tempfile.TemporaryDirectory(prefix='aws-lab-check-') as directory:
        body=Path(directory)/'marker.txt'
        body.write_text('Harmless AWS security lab verification marker. No personal or secret data.\n',encoding='utf-8')
        call('s3api','put-object','--bucket',bucket,'--key',key,'--body',str(body))
        head=call('s3api','head-object','--bucket',bucket,'--key',key)
        results.append({'check':'Default upload stored with lab SSE-KMS key','status':'PASS' if
                        head.get('ServerSideEncryption')=='aws:kms' and head.get('SSEKMSKeyId')==outputs['KeyArn'] else 'FAIL'})
        cases=[('Explicit AES256 rejected',['--server-side-encryption','AES256']),
               ('Explicit other KMS key rejected',['--server-side-encryption','aws:kms','--ssekms-key-id','alias/aws/s3']),
               ('Explicit KMS without key rejected',['--server-side-encryption','aws:kms'])]
        for name,args in cases:
            try:
                call('s3api','put-object','--bucket',bucket,'--key',key+'-denied','--body',str(body),*args)
                results.append({'check':name,'status':'FAIL','detail':'Unexpectedly accepted; retain and investigate test object'})
            except CheckError as error:
                results.append({'check':name,'status':'PASS' if str(error)=='AWS CLI error: AccessDenied' else 'ERROR'})
    url='https://'+bucket+'.s3.'+region+'.amazonaws.com/'+key
    try:
        with urlopen(url,timeout=15):
            results.append({'check':'Anonymous object read denied','status':'FAIL'})
    except HTTPError as error:
        results.append({'check':'Anonymous object read denied','status':'PASS' if error.code==403 else 'ERROR'})
    secret=call('secretsmanager','get-secret-value','--secret-id',outputs['SecretArn'])
    results.append({'check':'Current administrator can retrieve generated demo secret','status':'PASS' if bool(secret.get('SecretString')) else 'FAIL'})
    del secret
    return {'checked_at_utc':datetime.now(timezone.utc).isoformat(),'scope':'Deployed exercise bucket and demo secret only',
            'checks':results,'result':'PASS' if all(r['status']=='PASS' for r in results) else 'FAIL',
            'limits':['Retrieval was tested as current administrator; restricted identity not tested',
                      'No MFA enforcement test','Harmless test object retained under verification/ and subject to bucket lifecycle']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-account',required=True)
    parser.add_argument('--region',required=True)
    parser.add_argument('--stack',required=True)
    parser.add_argument('--profile')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    # Reuse the read-only verifier's input rules and preserve prior evidence.
    import re
    if not re.fullmatch(r'\d{12}',args.expected_account) or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d',args.region):
        parser.error('Invalid account or Region')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,79}',args.stack):
        parser.error('Invalid stack name')
    if args.output.exists():
        parser.error('Choose a new output filename')
    report=run(lambda *command:aws_call(args.region,args.profile,*command),args.expected_account,args.stack,args.region)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,indent=2);stream.write('\n')
    print(report['result']+': '+str(len(report['checks']))+' behavior checks; no secret values written')
    return 0 if report['result']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
