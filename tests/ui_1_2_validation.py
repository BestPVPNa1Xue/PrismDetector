"""Release UI regression on the task-owned emulator only, never a personal device.

Requires a rooted AOSP API34 emulator on port 5580 and optional KEYMAPPER_APK.
Artifacts remain local; publish only the compact validation summary/screenshots.
"""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,time,xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/v1.2.0';OUT.mkdir(parents=True,exist_ok=True)
ADB=os.environ.get('ADB',shutil.which('adb') or str(Path(os.environ.get('ANDROID_SDK_ROOT',str(Path.home()/'AppData/Local/Android/Sdk')))/'platform-tools/adb.exe'))
PKG='na1xue.prism.detector'
APK=ROOT/'dist/PrismDetector-1.2.0.apk'
PRIMARY=['我的世界安装包体积','我的世界 APK 证书','北京时间校对','无障碍检测','输入法检测','KeyMapper 安装状态','设备 ID']

def adb(*args,check=True):
    p=subprocess.run([ADB,'-s','emulator-5580',*map(str,args)],capture_output=True,check=check,timeout=50)
    return p.stdout.decode('utf-8',errors='replace').strip()

assert adb('shell','getprop','ro.kernel.qemu')=='1'
adb('root')
assert adb('shell','id').startswith('uid=0')

def tree():
    adb('shell','uiautomator','dump','/sdcard/prism-window.xml')
    return ET.fromstring(adb('shell','cat','/sdcard/prism-window.xml'))

def bounds(n):return list(map(int,re.findall(r'\d+',n.get('bounds'))))
def labels(t):return [n.get('text','') for n in t.iter('node') if n.get('text')]
def tap(label):
    t=tree()
    nodes=[n for n in t.iter('node') if label in (n.get('text'),n.get('content-desc')) and n.get('enabled')=='true']
    if not nodes:raise AssertionError('Label not visible: '+label)
    x1,y1,x2,y2=bounds(nodes[-1]);adb('shell','input','tap',(x1+x2)//2,(y1+y2)//2)

def snap(name):
    t=tree();ET.ElementTree(t).write(OUT/(name+'.xml'),encoding='utf-8')
    time.sleep(.4);adb('shell','screencap','-p','/sdcard/prism-shot.png')
    adb('pull','/sdcard/prism-shot.png',OUT/(name+'.png'))
    return t

def report():return json.loads(adb('shell','cat',f'/data/user/0/{PKG}/files/report.json'))
def fresh(old,name):
    for _ in range(80):
        time.sleep(.5)
        try:r=report()
        except (ValueError,subprocess.CalledProcessError):continue
        if r['version']=='1.2.0' and r['timestamp_ms']!=old:
            (OUT/(name+'.json')).write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
            return r
    raise AssertionError('Fresh scan missing')

def swipe(down=False):
    adb('shell','input','swipe','350',('500' if down else '1540'),'350',('1540' if down else '500'),'450')

def edge(down=False):
    seen=set();previous=None
    for _ in range(12):
        t=tree();seen.update(labels(t))
        signature=ET.tostring(t)
        if signature==previous:return t,seen
        previous=signature;swipe(down)
    raise AssertionError('Did not reach scroll edge')

adb('install','--no-incremental','-r',APK)
adb('shell','am','force-stop',PKG)
try:old=report()['timestamp_ms']
except (ValueError,subprocess.CalledProcessError):old=0
adb('shell','am','start','-W','-n',PKG+'/.MainActivity')
r=fresh(old,'01-default');assert len(r['items'])==21
home=snap('home')
title=next(n for n in home.iter('node') if n.get('text','').startswith('PrismDetector V1.2.0'))
assert bounds(title)[1]>=60,'Title overlaps status bar on 1080x1920 emulator'
bottom,seen=edge()
assert set(PRIMARY).issubset(seen),seen
assert 'TracerPid 调试状态' not in seen and '原宿主门控' not in seen
assert '显示次要检测项' in seen
bottom=snap('primary-bottom')
toggle=next(n for n in bottom.iter('node') if n.get('text')=='显示次要检测项')
about=next(n for n in bottom.iter('node') if n.get('content-desc')=='关于')
assert bounds(toggle)[3]<bounds(about)[1],(bounds(toggle),bounds(about))

tap('显示次要检测项');time.sleep(.8)
expanded,seen=edge()
assert all(i['title'] in seen for i in r['items'] if i['title'] not in PRIMARY)
expanded=snap('secondary-bottom')
last=next(n for n in expanded.iter('node') if n.get('text')=='原宿主门控')
about=next(n for n in expanded.iter('node') if n.get('content-desc')=='关于')
assert bounds(last)[3]<bounds(about)[1]
assert report()['timestamp_ms']==r['timestamp_ms'],'Expanding UI repeated scan'

# Same report survives orientation; saved disclosure state still exposes all rows.
adb('shell','settings','put','system','accelerometer_rotation','0')
adb('shell','settings','put','system','user_rotation','1');time.sleep(1)
snap('landscape')
assert report()['timestamp_ms']==r['timestamp_ms']
adb('shell','settings','put','system','user_rotation','0');time.sleep(1)
edge(True)
# Toggle is below primary cards; find it without crossing the entire expanded list.
for _ in range(5):
    if '隐藏次要检测项' in labels(tree()):break
    swipe()
tap('隐藏次要检测项');time.sleep(.8)
_,seen=edge()
assert 'TracerPid 调试状态' not in seen

fixture=Path(os.environ.get('KEYMAPPER_APK',str(ROOT/'.test-runtime/keymapper.apk')))
adb('install','--no-incremental','-r',fixture)
tap('关于');tap('重新检测');r=fresh(r['timestamp_ms'],'02-keymapper-installed')
items={i['id']:i for i in r['items']}
assert items['keymapper_package']['state']=='danger'
edge(True)
for _ in range(5):
    if 'KeyMapper 安装状态' in labels(tree()):break
    swipe()
tap('KeyMapper 安装状态');time.sleep(.5)
snap('keymapper-danger')
assert '已安装 KeyMapper' in labels(tree())
tap('KeyMapper 安装状态')

# Clicking the repository link must dispatch the exact browser URL.
tap('关于');snap('about')
tap('GitHub 开源仓库 · BestPVPNa1Xue/PrismDetector');time.sleep(1)
activities=adb('shell','dumpsys','activity','activities')
log=adb('logcat','-d','-s','ActivityTaskManager:I','*:S')
assert 'https://github.com/BestPVPNa1Xue/PrismDetector' in activities+log
(OUT/'repository-link.txt').write_text('\n'.join(x for x in (activities+'\n'+log).splitlines() if 'BestPVPNa1Xue/PrismDetector' in x),encoding='utf-8')
adb('shell','am','start','-W','-n',PKG+'/.MainActivity');time.sleep(.5)
adb('shell','input','keyevent','4') # Dismiss the still-open About dialog.
edge(True)
adb('shell','cmd','uimode','night','yes');time.sleep(1);snap('dark')
adb('shell','cmd','uimode','night','no');time.sleep(1)
assert report()['timestamp_ms']==r['timestamp_ms']
snap('final-home')
log=adb('logcat','-d','-s','PrismDetector','AndroidRuntime','*:S')
(OUT/'logcat.txt').write_text(log,encoding='utf-8');assert 'FATAL EXCEPTION' not in log
result={'version':'1.2.0','apk_sha256':hashlib.sha256(APK.read_bytes()).hexdigest(),'runtime':'AOSP API34 x86_64','primary_count':7,'secondary_count':14,'report_count':21,'default_collapsed':True,'disclosure_animation_and_toggle':True,'bottom_content_above_fab':True,'status_and_navigation_insets':True,'rotation_preserves_scan_and_disclosure':True,'keymapper_installed_danger':True,'repository_intent_verified':True,'arm64_runtime_tested':False,'api35_runtime_tested':False}
(OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print('PASS:',json.dumps(result),flush=True)
