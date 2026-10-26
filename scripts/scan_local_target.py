"""Targeted nginx checks through local OSP. Only lab-target:TCP80 can be scanned."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
from datetime import datetime, timezone
from uuid import UUID, uuid4
from lxml import etree
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Osp
from gvm.transforms import EtreeCheckCommandTransform

mode=sys.argv[1]
if mode not in {'ready','start','status','report'}:
    raise ValueError('Use ready, start, status or report')
with Osp(UnixSocketConnection(path='/run/ospd/ospd-openvas.sock',timeout=120),
         transform=EtreeCheckCommandTransform()) as osp:
    if mode in {'ready','start'}:
        feed=etree.fromstring(osp.send_command('<get_vts version_only="1" details="0"/>').encode())
        if feed.get('status')!='200' or feed.find('vts') is None:
            raise RuntimeError('Scanner cache not ready')
        metadata=feed.find('vts')
        version=metadata.get('vts_version')
        raw_total=metadata.get('total')
        total=int(raw_total) if raw_total else None
        cache_hash=metadata.get('sha256_hash','')
        if not version or version=='0' or not re.fullmatch(r'[a-f0-9]{64}',cache_hash):
            raise RuntimeError('Scanner cache empty or uninitialized')
        anchor=etree.fromstring(osp.send_command('<get_vts vt_id="1.3.6.1.4.1.25623.1.0.100274" details="0"/>').encode())
        if anchor.get('status')!='200' or anchor.find('vts/vt') is None:
            raise RuntimeError('Required nginx detection test is not loaded')
        if mode=='ready':
            print(json.dumps({'scanner_cache_ready':True,'feed_version':version,'available_vts':total,
                              'cache_sha256':cache_hash,'nginx_detection_test_loaded':True}))
        else:
            selection=json.loads(os.environ['LAB_VT_SELECTION'])
            ids=[item['oid'] for item in selection['tests']]
            if (selection['feed_version']!=version or len(ids)!=88 or len(set(ids))!=88
                    or not all(re.fullmatch(r'1\.3\.6\.1\.4\.1\.25623\.1\.0\.\d+',oid) for oid in ids)):
                raise ValueError('Expected the pinned 88-test selection and matching loaded feed')
            address=socket.gethostbyname('lab-target')
            if not ipaddress.ip_address(address).is_private:
                raise ValueError('Only the owned internal target is allowed')
            with socket.create_connection((address,80),timeout=5):
                pass
            scan_id=str(uuid4())
            params={'safe_checks':'1','auto_enable_dependencies':'1','optimize_test':'1',
                    'expand_vhosts':'0','report_host_details':'1','unscanned_closed':'1'}
            osp.start_scan(scan_id=scan_id,parallel=1,targets=[{'hosts':address,'ports':'T:80'}],
                           scanner_params=params,vt_selection={oid:{} for oid in ids})
            print(json.dumps({'scan_id':scan_id,'started_at_utc':datetime.now(timezone.utc).isoformat(),
               'feed_version':version,'explicit_vts':len(ids),'dependencies_enabled':True,
               'selection_sha256':hashlib.sha256('\n'.join(sorted(ids)).encode()).hexdigest(),
               'port_scope':'TCP80','configuration':'Targeted nginx VTs and SYN discovery; safe checks enabled',
               'authentication':'Unauthenticated network scan; no full-host or manager-CVE-catalog claim'}))
    else:
        scan_id=str(UUID(sys.argv[2]))
        response=osp.get_scans(scan_id=scan_id,details=mode=='report',pop_results=False)
        print(etree.tostring(response,encoding='unicode'))
