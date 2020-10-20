package com.example.my1stapplication;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.widget.Toast;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    public  static  final String EXTRA_MESSAGE = "com.example.myfirstapp.MESSAGE";
    Boolean isConnected = false,
            isWiFi = false,
            isMobile = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // ping
        ConnectivityManager cm = (ConnectivityManager) this.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        if (activeNetwork != null) {
            isWiFi = activeNetwork.getType() ==
                    ConnectivityManager.TYPE_WIFI;
            isMobile = activeNetwork.getType() ==
                    ConnectivityManager.TYPE_MOBILE;
            isConnected =
                    activeNetwork.isConnectedOrConnecting();
        }
        if (isConnected) {
            if (isWiFi) {
                Toast.makeText(this, "Yes, WiF",
                        Toast.LENGTH_SHORT)
                        .show();
                if(isConnectedToThisServer("https://www.google.com/")) {
                    Toast.makeText(this, "Yes, Connected to Google", Toast.LENGTH_SHORT)
                                    .show();
                } else {
                    Toast.makeText(this, "No Google Connection", Toast.LENGTH_SHORT).show();
                }
            }
            if (isMobile) {
                Toast.makeText(this, "Yes, Mobile",
                        Toast.LENGTH_SHORT)
                        .show();
                if(isConnectedToThisServer("https://www.google.com/")) {
                    Toast.makeText(this, "Yes, Connected to Google", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "No Google Connection", Toast.LENGTH_SHORT).show();
                }
            }
        } else {
            Toast.makeText(this, "No Network",
                    Toast.LENGTH_SHORT).show();
        }


    }

    public void sendMessage(View view){
        Intent intent = new Intent(this,DisplayMessageActivity.class);
        EditText editText = (EditText) findViewById(R.id.editText);
        String message = editText.getText().toString();
        intent.putExtra(EXTRA_MESSAGE, message);
        startActivity(intent);
    }

    public boolean isConnectedToThisServer(String host) {
        Runtime runtime = Runtime.getRuntime();
        try {
            Process ipProcess = runtime.exec("/system/bin/ping -c 1 8.8.8.8" + host);
            int exitValue = ipProcess.waitFor();
            return (exitValue == 0);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }

}