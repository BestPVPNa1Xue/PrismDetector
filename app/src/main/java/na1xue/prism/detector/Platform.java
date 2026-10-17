package na1xue.prism.detector;

import android.content.Context;
import android.content.pm.*;
import android.os.Build;
import android.provider.Settings;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;
import java.util.ArrayList;

/** Android API bridge only. All classification, hashes and thresholds live in C++. */
public final class Platform {
    public static final class PackageData {
        public int status; // 1 installed, 0 absent for current user, -1 API failure
        public String error="", version="", source="";
        public String[] splits=new String[0], activities=new String[0];
        public byte[][] certificates=new byte[0][], history=new byte[0][];
    }
    @SuppressWarnings("deprecation")
    public static PackageData packageData(Context context, String name) {
        PackageData d=new PackageData();
        try {
            PackageManager pm=context.getPackageManager();
            PackageInfo info=pm.getPackageInfo(name,PackageManager.GET_ACTIVITIES);
            d.status=1; d.version=String.valueOf(info.versionName)+" ("+(Build.VERSION.SDK_INT>=28?info.getLongVersionCode():info.versionCode)+")";
            if(info.applicationInfo!=null) {
                d.source=info.applicationInfo.sourceDir;
                if(info.applicationInfo.splitSourceDirs!=null)d.splits=info.applicationInfo.splitSourceDirs;
            }
            if(info.activities!=null){d.activities=new String[info.activities.length];for(int i=0;i<d.activities.length;i++)d.activities[i]=info.activities[i].name;}
            try {
                PackageInfo signed=pm.getPackageInfo(name,Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES);
                Signature[] current;
                if(Build.VERSION.SDK_INT>=28 && signed.signingInfo!=null){
                    current=signed.signingInfo.getApkContentsSigners();
                    if(!signed.signingInfo.hasMultipleSigners())d.history=bytes(signed.signingInfo.getSigningCertificateHistory());
                }else current=signed.signatures;
                d.certificates=bytes(current);
            }catch(Exception ex){d.error="Certificate API: "+ex.getClass().getSimpleName()+": "+ex.getMessage();}
        } catch(PackageManager.NameNotFoundException ex) {d.status=0;}
          catch(Exception ex){d.status=-1;d.error=ex.getClass().getSimpleName()+": "+ex.getMessage();}
        return d;
    }
    private static byte[][] bytes(Signature[] signatures){
        if(signatures==null)return new byte[0][];
        byte[][] result=new byte[signatures.length][];for(int i=0;i<result.length;i++)result[i]=signatures[i].toByteArray();return result;
    }
    public static String inputMethodSettings(Context c){
        try {
            StringBuilder s=new StringBuilder("当前默认输入法：").append(Settings.Secure.getString(c.getContentResolver(),Settings.Secure.DEFAULT_INPUT_METHOD)).append("\n已启用输入法：\n");
            InputMethodManager m=(InputMethodManager)c.getSystemService(Context.INPUT_METHOD_SERVICE);
            if(m==null)return "InputMethodManager unavailable";
            for(InputMethodInfo i:m.getEnabledInputMethodList())s.append(i.getId()).append('\n');
            return s.toString();
        }catch(Exception e){return "读取启用/默认输入法失败："+e;}
    }
}
