package com.example.cmkcppapp;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.BreakIterator;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }
    private static final int CREATE_FILE = 1;
    private Uri documentUri;
    private int keyIdx = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
    }

    public void sendMessage(View view){
        TextView tv = findViewById(R.id.sample_text);
        tv.setText(keyExchangeJNI());
        //@SuppressLint("WrongViewCast") EditText editText = (EditText) findViewById(R.id.textView);
        //String message = editText.getText().toString();
        //writeAppSpecificExternalFile(getApplicationContext(), false);
        writeStorageAccessFrameworkFile(getApplicationContext());
        keyIdx ++;
    }

    public void loadMessage(View view){
        readStorageAccessFrameworkFile(getApplicationContext());
    }

    private void writeStorageAccessFrameworkFile(Context context) {
        String fileName = "QS_Encryption_key";
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, fileName);
        startActivityForResult(intent, CREATE_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        String fileName = "QS_Encryption_key";
        String testKeyStr = "biXhp3Ha1fgxVEp48zHrvVoXMStmxPuAPHo3TVz5lHU=";
        TextView tv = findViewById(R.id.sample_text);

        if (requestCode == CREATE_FILE && data != null) {
            tv.setText("Created key file " + fileName + "successfully.");
            try {
                documentUri = data.getData();
                ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(data.getData(), "wa");

                FileOutputStream fileOutputStream = new FileOutputStream(pfd.getFileDescriptor());
                fileOutputStream.write(("key Idx: 00000"+keyIdx+"\n").getBytes());
                fileOutputStream.write(("Load key time:"+ System.currentTimeMillis() + "\n").getBytes());
                fileOutputStream.write(("QS Encrypt Key:"+ testKeyStr+"\n").getBytes());

                fileOutputStream.close();
                pfd.close();
                fileOutputStream.close();
            } catch (Exception e) {
                e.printStackTrace();
                tv.setText("Created key file " + fileName + "successfully.");
            }
        }
    }

    private void readStorageAccessFrameworkFile(Context context) {
        TextView tv = findViewById(R.id.sample_text);
        try {
            InputStream inputStream = getContentResolver().openInputStream(documentUri);
            List<String> lines = new ArrayList<String>();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line = reader.readLine();
            while (line != null) {
                lines.add(line);
                line = reader.readLine();
            }
            tv.setText("Key file:\n" + TextUtils.join("\n", lines));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //---------------------------------------------------------------------------------

    private void writeAppSpecificExternalFile(Context context, boolean isPersistent) {

        File file;
        String fileName = "QS_Encryption_key";
        String testKeyStr = "biXhp3Ha1fgxVEp48zHrvVoXMStmxPuAPHo3TVz5lHU=";
        if (isPersistent) {
            file = new File(context.getExternalFilesDir(null), fileName);
        } else {
            file = new File(context.getExternalCacheDir(), fileName);
        }
        TextView tv = findViewById(R.id.sample_text);

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(testKeyStr.getBytes(Charset.forName("UTF-8")));
            //Toast.makeText(context, String.format("Write to %s successful", fileName.getText().toString()), Toast.LENGTH_SHORT).show();
            tv.setText("Created key file " + fileName + "successfully.");
        } catch (Exception e) {
            e.printStackTrace();
            tv.setText("Created key file " + fileName + "error");
            //Toast.makeText(context, String.format("Write to file %s failed", fileName.getText().toString()), Toast.LENGTH_SHORT).show();
        }
    }



    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public native String keyExchangeJNI();
}
