package na1xue.prism.detector;
import android.content.Context;
/** Fixed JNI boundary; rules and classifications are native. */
public final class NativeBridge {
    static { System.loadLibrary("prismdetector"); }
    public static native String nativeScan(Context context,String classes,boolean activeProbe,boolean networkTime);
    private NativeBridge() {}
}
