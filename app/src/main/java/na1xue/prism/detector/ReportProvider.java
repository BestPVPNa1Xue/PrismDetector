package na1xue.prism.detector;
import android.content.*;
import android.database.*;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.*;
/** A single, read-only report. No path forwarding or directory access. */
public final class ReportProvider extends ContentProvider {
    @Override public boolean onCreate(){return true;}
    private File report(Uri uri)throws FileNotFoundException{if(!"/report.json".equals(uri.getPath()))throw new FileNotFoundException();return new File(getContext().getFilesDir(),"report.json");}
    @Override public String getType(Uri uri){return "application/json";}
    @Override public ParcelFileDescriptor openFile(Uri uri,String mode)throws FileNotFoundException{if(!"r".equals(mode))throw new FileNotFoundException("read only");return ParcelFileDescriptor.open(report(uri),ParcelFileDescriptor.MODE_READ_ONLY);}
    @Override public Cursor query(Uri uri,String[] projection,String selection,String[] args,String sort){try{File f=report(uri);String[] columns=projection!=null?projection:new String[]{OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE};MatrixCursor c=new MatrixCursor(columns);Object[] values=new Object[columns.length];for(int i=0;i<columns.length;i++)values[i]=OpenableColumns.DISPLAY_NAME.equals(columns[i])?"PrismDetector-report.json":OpenableColumns.SIZE.equals(columns[i])?f.length():null;c.addRow(values);return c;}catch(FileNotFoundException e){return null;}}
    @Override public Uri insert(Uri u,ContentValues v){throw new UnsupportedOperationException();}
    @Override public int delete(Uri u,String s,String[] a){throw new UnsupportedOperationException();}
    @Override public int update(Uri u,ContentValues v,String s,String[] a){throw new UnsupportedOperationException();}
}
