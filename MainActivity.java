package com.example.cmkcppapp;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;


import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
    private static final int RESULT_ENABLE = 11;
    private Uri documentUri;
    private int keyIdx = 0;
    private boolean visibleF = false;   // function visiable flag
    private String fileFdPath = "/storage/emulated/0/Download/"; // shared data storage folder path.
    private DevicePolicyManager devicePolicyManager;
    private ActivityManager activityManager;
    private ComponentName compName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Init the phone control admin setup.
        devicePolicyManager = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        activityManager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        compName = new ComponentName(this, MyAdmin.class);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
    }

    public void toggleVisiable(View view){
        // Check the user's input password and enable the funcitons.
        boolean active = devicePolicyManager.isAdminActive(compName);
        if (active) {
            // Lock the main window if the device admin permission has been setup
            devicePolicyManager.lockNow();
        } else {
            Toast.makeText(this, "You need to enable the Admin Device Features", Toast.LENGTH_SHORT).show();
            Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, compName);
            intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Additional text explaining why we need this permission");
            startActivityForResult(intent, RESULT_ENABLE);
        }
        // Enable the function.
        EditText pwdTxt = (EditText)findViewById(R.id.editTextTextPassword2);
        visibleF = pwdTxt.getText().toString().equalsIgnoreCase("123");
        if(visibleF) {
            Toast toast=Toast.makeText(getApplicationContext(),"Authorization Success! Unlocal Key Exchange Function.",Toast.LENGTH_SHORT);
            toast.setMargin(50,50);
            toast.show();
            // Active visibility for the shared storage place:
            findViewById(R.id.textView3).setVisibility(View.VISIBLE);
            findViewById(R.id.keyExchangeServerIP).setVisibility(View.VISIBLE);
            findViewById(R.id.pathAutoSetBt).setVisibility(View.VISIBLE);
            SystemClock.sleep(500);
            // Active visibility config loading section:
            findViewById(R.id.LoadIPTableConfig).setVisibility(View.VISIBLE);
            findViewById(R.id.progressBar00).setVisibility(View.VISIBLE);
            SystemClock.sleep(500);
            // Active key exchange button.
            findViewById(R.id.button2).setVisibility(View.VISIBLE);
            SystemClock.sleep(500);
            // Active result showing section.
            findViewById(R.id.TestLb_00).setVisibility(View.VISIBLE);
            findViewById(R.id.button3).setVisibility(View.VISIBLE);
            findViewById(R.id.sample_text).setVisibility(View.VISIBLE);
            // disable the check button.
            findViewById(R.id.imageView2).setVisibility(View.INVISIBLE);
            visibleF = false;
        }
        else{
            Toast toast=Toast.makeText(getApplicationContext(),"Authorization Fail! Please use other password.",Toast.LENGTH_SHORT);
            toast.setMargin(50,50);
            toast.show();
        }
    }

    public void fillStoragePath(View view)throws FileNotFoundException {
        // File the shared storage path.
        fileFdPath = ""+Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)+"/";
        TextView pathV = findViewById(R.id.keyExchangeServerIP);
        pathV.setText(fileFdPath);
    }

    public void loadConfigFiles(View view) throws FileNotFoundException {
        // Load/check the config files.
        int progressStatus = 0;
        ProgressBar progressBar = (ProgressBar) findViewById(R.id.progressBar00);
        // Check IPconfig file.
        File iptable = new File(fileFdPath+"/"+"IPTable.cfg");
        if(iptable.exists()){
            progressStatus += 30;
            progressBar.setProgress(progressStatus*10);
        }else{
            Toast toast=Toast.makeText(getApplicationContext(),"Config File Missing: IPTable.cfg",Toast.LENGTH_SHORT);
            toast.setMargin(50,50);
            toast.show();
        }
        // Check Client config file
        File clientcfg = new File(fileFdPath+"/"+"gw_App.cfg");
        if(clientcfg.exists()){
            progressStatus += 30;
            progressBar.setProgress(progressStatus*10);
        }else{
            Toast toast=Toast.makeText(getApplicationContext(),"Config File Missing: gw_App.cfg",Toast.LENGTH_SHORT);
            toast.setMargin(50,50);
            toast.show();
        }
        // Check wireguard public key file
        File pubkeyfile = new File(fileFdPath+"/"+"QS_Encryption_key.txt");
        if(pubkeyfile.exists()){
            progressStatus += 40;
            progressBar.setProgress(progressStatus*10);
        }else{
            Toast toast=Toast.makeText(getApplicationContext(),"Config File Missing: gw_App.cfg",Toast.LENGTH_SHORT);
            toast.setMargin(50,50);
            toast.show();
        }

    }

    public void loadGwConfig(View view){
        System.out.println("Load IP config table...");
        int progressStatus = 0;
        ProgressBar progressBar = (ProgressBar) findViewById(R.id.progressBar00);
        try {
            FileInputStream Fin=new FileInputStream(new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "gw_cli_Abe.cfg"));
            List<String> lines = new ArrayList<String>();
            BufferedReader reader = new BufferedReader(new InputStreamReader(Fin));
            String line = reader.readLine();
            while (line != null) {
                lines.add(line);
                line = reader.readLine();
                //SystemClock.sleep(2000);
                System.out.println(">");
                String[] parts = line.split("/");
                if(parts.length > 1){
                    progressStatus +=1;
                    progressBar.setProgress(progressStatus);
                    Toast toast=Toast.makeText(getApplicationContext(),parts[parts.length-1],Toast.LENGTH_SHORT);
                    toast.setMargin(50,50);
                    toast.show();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendKexMessage(View view) {
        // Do Key exchagne.
        InitKeyExchange();
        // Start the key exchange:

        TextView tv = findViewById(R.id.sample_text);
        tv.setText(keyExchangeJNI(fileFdPath));

        Toast toast=Toast.makeText(getApplicationContext(),"Key Exchange finished",Toast.LENGTH_SHORT);
        toast.setMargin(50,50);
        toast.show();

        writeStorageAccessFrameworkFile(getApplicationContext());
    }



    public void loadMessage(View view) {
        readStorageAccessFrameworkFile(getApplicationContext());
    }

    private void writeStorageAccessFrameworkFile(Context context) {
        //String fileName = "QS_Encryption_key";
        String fileName = stringFromJNI();
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, fileName);
        startActivityForResult(intent, CREATE_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {

        if(requestCode ==RESULT_ENABLE) {
            super.onActivityResult(requestCode, resultCode, data);
        }
        else {
            super.onActivityResult(requestCode, resultCode, data);
            //String fileName = "QS_Encryption_key";
            String fileName = stringFromJNI();
            //String testKeyStr = "biXhp3Ha1fgxVEp48zHrvVoXMStmxPuAPHo3TVz5lHU=";
            //String testKeyStr = keyExchangeJNI();
            TextView tv = findViewById(R.id.sample_text);

            if (requestCode == CREATE_FILE && data != null) {
                tv.setText("Created key file " + fileName + "successfully.");
                try {
                    documentUri = data.getData();
                    ParcelFileDescriptor pfd = getContentResolver().openFileDescriptor(data.getData(), "wa");

                    FileOutputStream fileOutputStream = new FileOutputStream(pfd.getFileDescriptor());
                    fileOutputStream.write(("key Idx: 00000" + keyIdx + "\n").getBytes());
                    fileOutputStream.write(("Load key time:" + System.currentTimeMillis() + "\n").getBytes());
                    //fileOutputStream.write(("QS Encrypt Key:" + testKeyStr + "\n").getBytes());

                    fileOutputStream.close();
                    pfd.close();
                    fileOutputStream.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    tv.setText("Error: Created key file " + fileName + "fail.");
                }
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
    public native  String InitKeyExchange();

    public native String stringFromJNI();

    public native String keyExchangeJNI(String filename);

    public native String loadConfigfileJNI(String filename);
}
