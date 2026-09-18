"""Validate design files. Does not implement or test a production gateway."""
from pathlib import Path
import json, hashlib, copy
from jsonschema import Draft202012Validator, FormatChecker
import rfc8785

ROOT=Path(__file__).resolve().parents[1]
def load(p): return json.loads((ROOT/p).read_text())
def sha(b): return hashlib.sha256(b).hexdigest()
def canon_hash(obj,domain): return sha(domain.encode()+b'\0'+rfc8785.dumps(obj))
checks=[]
def check(name,condition):
    if not condition: raise AssertionError(name)
    checks.append({'check':name,'result':'PASS'})
validators={}
for name in ['decision','approval','evidence','audit-event']:
    s=load('schemas/'+name+'.schema.json')
    Draft202012Validator.check_schema(s)
    v=Draft202012Validator(s,format_checker=FormatChecker()); validators[name]=v
    v.validate(load('examples/'+name+'.example.json'))
    check(name+' schema and illustrative instance',True)
d=load('examples/decision.example.json');a=load('examples/approval.example.json');e=load('examples/evidence.example.json');ev=load('examples/audit-event.example.json')
raw=(ROOT/'examples/synthetic-evidence.json').read_bytes()
check('raw evidence hash and length',sha(raw)==e['sha256'] and len(raw)==e['byte_length'])
check('decision canonical digest',canon_hash(d['body'],'TFIR-DECISION-v1')==d['decision_sha256'])
check('approval bound to example decision',a['body']['decision_sha256']==d['decision_sha256'] and a['body']['decision_id']==d['body']['decision_id'])
check('decision resolves included evidence',d['body']['evidence_refs'][0]['sha256']==e['sha256'])
check('audit canonical digest',canon_hash(ev['body'],'TFIR-EVENT-v1')==ev['event_sha256'])
check('audit payload hash matches approval bytes',ev['body']['payload_ref']['sha256']==sha((ROOT/'examples/approval.example.json').read_bytes()))
check('all illustrative records explicitly marked as examples',all(x['example_only'] for x in [d,a,e,ev]))
check('example approval explicitly unsigned',a['attestation']['state']=='unsigned_design_example' and a['attestation']['signature_base64url'] is None)
bad=copy.deepcopy(a);bad['body']['approver']['kind']='agent'
check('schema rejects agent approver',not validators['approval'].is_valid(bad))
bad=copy.deepcopy(a);bad['example_only']=False
check('schema rejects unsigned nonexample approval',not validators['approval'].is_valid(bad))
bad=copy.deepcopy(d);bad['body']['required_approvals']['human_required']=False
check('schema rejects disabled human requirement',not validators['decision'].is_valid(bad))
bad=copy.deepcopy(d);bad['body']['action']['targets']=['OTHER-TARGET']
check('target mutation changes canonical digest',canon_hash(bad['body'],'TFIR-DECISION-v1')!=d['decision_sha256'])
bad=copy.deepcopy(ev);bad['body']['outcome']='auto_approved'
check('schema rejects unsupported outcome',not validators['audit-event'].is_valid(bad))
catalog=load('verification/acceptance_catalog.json')
check('acceptance identifiers unique',len({t['id'] for t in catalog['tests']})==len(catalog['tests']))
check('acceptance catalog labeled unexecuted',catalog['status']=='implementation_tests_not_executed')
report={'scope':'Design schema shape, example hashing, selected references and negative fixtures only','checks':checks,'passed':len(checks),'failed':0,'future_implementation_tests':len(catalog['tests']),'limitations':['No live connector, identity, policy, signing or retention enforcement tested.','Examples are an incomplete illustrative subset, not a verifiable case export.','No complete Mermaid renderer acceptance claimed.']}
(ROOT/'verification/validation_report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'design_checks_passed':len(checks),'future_implementation_tests_not_run':len(catalog['tests'])}))
