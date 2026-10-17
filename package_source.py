"""Prepare a reviewed source release and optionally sync an existing Git checkout.

This script never commits, tags or pushes. Review the checkout, then publish the
version commit and annotated tag. Raw evidence, credentials and input APKs stay local.
"""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,xml.etree.ElementTree as ET,zipfile

ROOT=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--checkout',type=Path,help='Existing clean clone of the PrismDetector GitHub repository')
args=parser.parse_args()
manifest=json.loads((ROOT/'dist/build-manifest.json').read_text('utf-8'))
version=manifest['version'];evidence=ROOT/'evidence'/('v'+version)
apk=ROOT/'dist'/f'PrismDetector-{version}.apk'

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

assert sha(apk)==manifest['sha256']
for relative,digest in manifest['sources'].items():assert sha(ROOT/relative)==digest,relative
verification=json.loads((evidence/'verification.json').read_text('utf-8'))
assert verification['apk_sha256']==manifest['sha256']
issues=ET.parse(ROOT/'app/build/reports/lint-results-release.xml').getroot().findall('issue')
assert not any(i.get('severity') in ('Error','Fatal') for i in issues)
release=ROOT/'releases';release.mkdir(exist_ok=True)
summary={k:manifest[k] for k in ['name','package','version','versionCode','minSdk','targetSdk','abis','bytes','sha256']}
summary.update({'verification':verification,'lint_errors':0,'lint_warnings':sum(i.get('severity')=='Warning' for i in issues),'sources':manifest['sources']})
(release/f'v{version}.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')

files=[]
for base in ['app/src','gradle','vendor-ui','releases']:
    files.extend(p for p in (ROOT/base).rglob('*') if p.is_file() and not any(part in p.parts for part in ['.git','.gradle','build','.cxx','__pycache__']))
files.extend(ROOT/p for p in ['app/build.gradle','app/proguard-rules.pro','build.gradle','settings.gradle','gradle.properties','gradlew','gradlew.bat','build.py','package_source.py','README.md','CHANGELOG.md','LICENSE-Ruru.md','NOTICE.md','AGENTS.md','.gitignore','.gitattributes','tests/rules_test.cpp','tests/ui_1_2_validation.py'])
files=sorted(set(files))
for file in files:
    assert file.exists(),file
    assert file.suffix.lower() not in ['.apk','.p12','.jks','.keystore','.dex','.id0','.id1','.i64'],file

if args.checkout:
    target=args.checkout.resolve()
    assert target!=ROOT and (target/'.git').is_dir(),'Use a separate existing Git clone'
    remote=subprocess.check_output(['git','-C',str(target),'remote','get-url','origin'],text=True).strip()
    assert remote=='https://github.com/BestPVPNa1Xue/PrismDetector.git',remote
    assert not subprocess.check_output(['git','-C',str(target),'status','--porcelain'],text=True).strip(),'Review existing changes before syncing'
    for file in files:
        out=target/file.relative_to(ROOT);out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,out)
        assert sha(file)==sha(out)
    print('Synchronized source to',target)

out=ROOT/'dist'/f'PrismDetector-{version}-source.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for file in files:z.write(file,'PrismDetector/'+file.relative_to(ROOT).as_posix())
with zipfile.ZipFile(out) as z:
    assert z.testzip() is None
    for file in files:assert hashlib.sha256(z.read('PrismDetector/'+file.relative_to(ROOT).as_posix())).hexdigest()==sha(file)
(ROOT/'dist/SHA256SUMS.txt').write_text(f'{sha(apk)}  {apk.name}\n{sha(out)}  {out.name}\n',encoding='utf-8')
print(json.dumps({'version':version,'files':len(files),'source_zip_bytes':out.stat().st_size,'apk_sha256':sha(apk),'source_sha256':sha(out)},indent=2))
