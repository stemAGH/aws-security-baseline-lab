"""One synthetic GoPhish recipient, captured by Mailpit. No real mail delivery."""
from datetime import datetime, timezone
from contextlib import closing
import html
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker','compose','-p','aws-security-lab-local','-f',str(ROOT/'local/compose.yml')]


def docker(*args):
    result = subprocess.run(list(args),capture_output=True,text=True,timeout=120)
    if result.returncode:
        raise RuntimeError('Docker operation failed; inspect the named local lab containers privately')
    return result.stdout.strip()


def request(url,data=None,token=None):
    if urlsplit(url).netloc not in {'gophish:3333','gophish:8080','mailpit:8025'} or urlsplit(url).scheme!='http':
        raise ValueError('Request outside the internal simulation network')
    headers={'Content-Type':'application/json'}
    if token:
        headers['Authorization']='Bearer '+token
    runner = """let input=''; process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end', async()=>{try {const p=JSON.parse(input);
const r=await fetch(p.url,{method:p.data===null?'GET':'POST',headers:p.headers,
body:p.data===null?undefined:JSON.stringify(p.data),redirect:'error',signal:AbortSignal.timeout(5000)});
const text=await r.text(); if(!r.ok) {let message=''; try {message=JSON.parse(text).message||'';} catch {}
throw Error('HTTP '+r.status+' '+message.slice(0,160));} process.stdout.write(text);
} catch(e) {process.stderr.write(e.message); process.exitCode=1;}});"""
    try:
        result=subprocess.run([*COMPOSE,'exec','-T','runner','node','-e',runner],
            input=json.dumps({'url':url,'data':data,'headers':headers}),capture_output=True,text=True,timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Internal lab request timed out') from exc
    if result.returncode:
        raise RuntimeError('Internal lab HTTP request failed: '+result.stderr[:200])
    return result.stdout.encode()


def safe_click(url):
    parsed=urlsplit(html.unescape(url))
    if (parsed.scheme!='http' or parsed.netloc!='gophish:8080' or parsed.path not in ('','/')
        or not re.fullmatch(r'rid=[A-Za-z0-9_-]+',parsed.query)):
        raise ValueError('Refused a tracking link outside this local campaign')
    return parsed.geturl()


def wait_for(action,description,attempts=45):
    for _ in range(attempts):
        try:
            result=action()
            if result:
                return result
        except (OSError,ValueError,RuntimeError):
            pass
        time.sleep(1)
    raise RuntimeError('Timed out waiting for '+description)


def main():
    started=datetime.now(timezone.utc)
    stamp=started.strftime('%Y%m%dT%H%M%SZ')
    destination=ROOT/'evidence'/('local-simulation-'+stamp+'.json')
    if destination.exists():
        raise RuntimeError('Evidence filename exists; do not overwrite an earlier run')
    # HTTP stays inside an internal Docker network with no published host ports. Never reuse for hosting.
    try:
        docker(*COMPOSE,'up','-d')
        wait_for(lambda:request('http://gophish:3333/login'),'GoPhish startup')
        wait_for(lambda:request('http://mailpit:8025/api/v1/messages'),'Mailpit startup')
        container=docker(*COMPOSE,'ps','-q','gophish')
        with tempfile.TemporaryDirectory(prefix='aws-lab-') as directory:
            database=Path(directory)/'gophish.db'
            docker('docker','cp',container+':/tmp/gophish.db',str(database))
            with closing(sqlite3.connect(database)) as connection:
                row=connection.execute('SELECT api_key FROM users WHERE username = ?',('admin',)).fetchone()
                if not row or not row[0]:
                    raise RuntimeError('Local API credential was not initialized')
                token=row[0]
        def api(path,data=None):
            return json.loads(request('http://gophish:3333/api/'+path,data,token))
        name='Local security lab '+stamp
        group=api('groups/',{'name':name,'targets':[{'email':'learner@example.test','first_name':'Lab','last_name':'Recipient','position':'Synthetic'}]})
        page=api('pages/',{'name':name,'html':'<html><body><h1>Security lab exercise</h1><p>This was a local training simulation. No passwords are requested or collected.</p></body></html>',
                           'capture_credentials':False,'capture_passwords':False,'redirect_url':''})
        template=api('templates/',{'name':name,'subject':name,'text':'Local lab message. Open the training page: {{.URL}}',
                                  'html':'<html><body><p>Local lab message.</p><a href="{{.URL}}">Open training page</a></body></html>'})
        smtp=api('smtp/',{'name':name,'host':'mailpit:1025','from_address':'training@example.test',
                         'interface_type':'SMTP','ignore_cert_errors':False})
        campaign=api('campaigns/',{'name':name,'template':{'name':template['name']},'page':{'name':page['name']},
            'smtp':{'name':smtp['name']},'groups':[{'name':group['name']}],'url':'http://gophish:8080'})
        def find_message():
            messages=json.loads(request('http://mailpit:8025/api/v1/messages'))
            return next((m for m in messages.get('messages',[]) if m.get('Subject')==name),None)
        message=wait_for(find_message,'captured local email')
        content=json.loads(request('http://mailpit:8025/api/v1/message/'+message['ID']))
        links=re.findall(r'href=[\"\x27]([^\"\x27]+)',content.get('HTML',''))
        link=next((safe_click(v) for v in links if 'gophish:8080' in v),None)
        if not link:
            raise RuntimeError('No local campaign link found in captured message')
        request(link)
        def clicked():
            observed=api('campaigns/'+str(campaign['id']))
            return observed if len(observed.get('results',[]))==1 and observed['results'][0].get('status')=='Clicked Link' else None
        observed=wait_for(clicked,'GoPhish click event')
        settings=api('pages/'+str(page['id']))
        if settings.get('capture_credentials') is not False or settings.get('capture_passwords') is not False:
            raise RuntimeError('Credential capture unexpectedly enabled')
        report={'started_at_utc':started.isoformat(),'finished_at_utc':datetime.now(timezone.utc).isoformat(),
            'scope':'Local Docker lab only; synthetic .test recipient; automated click',
            'result':'PASS','recipients':1,'messages_captured_by_mailpit':1,'clicked_results':1,
            'capture_credentials':False,'capture_passwords':False,
            'event_types':sorted({event['message'] for event in observed.get('timeline',[])}),
            'network':'Internal Docker network; no published ports; no SMTP relay configured',
            'limits':['No real person received mail','Automated click does not measure human susceptibility',
                      'Not an AWS deployment or OpenVAS scan'],
            'images':{'gophish':'sha256:8a57cd171999dcd1fa33f346d6898440913ae14be114ffc850cc678354672d29',
                      'mailpit':'sha256:0790692be935ea4420d085694f7985b1f692ca6a8771ab0e0bd8ba75ac180498'}}
        destination.parent.mkdir(exist_ok=True)
        with destination.open('x',encoding='utf-8') as stream:
            json.dump(report,stream,indent=2)
            stream.write('\n')
        print('PASS: mail captured locally and automated click recorded; credential capture disabled')
        print(destination)
    finally:
        # Only this script's disposable synthetic campaign containers are removed.
        docker(*COMPOSE,'down')


if __name__=='__main__':
    main()
