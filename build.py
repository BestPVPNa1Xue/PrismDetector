"""Build the Ruru Compose UI + Prism C++ release using Gradle 8.13."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess
ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--sdk',default=os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'AppData/Local/Android/Sdk')))
p.add_argument('--jdk',default=os.environ.get('JAVA_HOME',r'C:\Program Files\Android\Android Studio\jbr'))
p.add_argument('--offline',action='store_true',help='Use cached Gradle/Maven dependencies')
p.add_argument('--abis',default='arm64-v8a,x86_64')
a=p.parse_args();sdk=Path(a.sdk);jdk=Path(a.jdk)
if any(abi not in ['arm64-v8a','x86_64'] for abi in a.abis.split(',')):raise SystemExit('Unsupported ABI')
env=os.environ.copy();env['JAVA_HOME']=str(jdk);env['ANDROID_SDK_ROOT']=str(sdk);env['PATH']=str(jdk/'bin')+os.pathsep+env['PATH']
def run(*cmd):subprocess.run([str(x) for x in cmd],cwd=ROOT,env=env,check=True)
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
(ROOT/'local.properties').write_text('sdk.dir='+sdk.as_posix().replace(':',r'\:')+'\n',encoding='utf-8')
signing=ROOT/'.signing';signing.mkdir(exist_ok=True);key=signing/'prismdetector-dev.p12'
if not key.exists():
    run(jdk/'bin/keytool.exe','-genkeypair','-keystore',key,'-storetype','PKCS12','-storepass','android','-keypass','android','-alias','prismdetector','-keyalg','RSA','-keysize','3072','-validity','10000','-dname','CN=PrismDetector Local Development,O=PrismDetector,C=CN')
installed=sorted((Path.home()/'.gradle/wrapper/dists/gradle-8.13-bin').glob('*/gradle-8.13/bin/gradle.bat'))
gradle=installed[0] if installed else ROOT/'gradlew.bat'
cmd=[gradle,':app:assembleRelease',':app:lintRelease','--console=plain',f'-PprismAbis={a.abis}']
if a.offline:cmd.append('--offline')
run(*cmd)
dist=ROOT/'dist';dist.mkdir(exist_ok=True);apk=dist/'PrismDetector-1.2.0.apk'
shutil.copy2(ROOT/'app/build/outputs/apk/release/app-release.apk',apk)
bt=sdk/'build-tools/36.1.0'
verification=subprocess.check_output([str(bt/'apksigner.bat'),'verify','--verbose','--print-certs',str(apk)],env=env,text=True)
run(bt/'zipalign.exe','-c','-P','16','4',apk)
evidence=ROOT/'evidence/v1.2.0';evidence.mkdir(parents=True,exist_ok=True)
(evidence/'apksigner.txt').write_text(verification,encoding='utf-8')
manifest={'name':'PrismDetector','package':'na1xue.prism.detector','version':'1.2.0','versionCode':3,'minSdk':24,'targetSdk':35,'abis':a.abis.split(','),'bytes':apk.stat().st_size,'sha256':sha(apk),'ui':'Direct source reuse: supplied Ruru-1.1.1','signing':'same local development key as 1.0.0','sources':{x.relative_to(ROOT).as_posix():sha(x) for x in (ROOT/'app/src/main').rglob('*') if x.is_file()}}
(dist/'build-manifest-1.2.0.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding='utf-8')
(dist/'build-manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps({k:v for k,v in manifest.items() if k!='sources'},indent=2,ensure_ascii=False))
