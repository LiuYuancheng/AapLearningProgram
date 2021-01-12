package com.example.ktfilereader

import android.content.ClipData
import android.content.ClipboardManager

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat.getSystemService
import androidx.navigation.fragment.findNavController
import com.android.samples.filemanager.getFilesList
import com.android.samples.filemanager.getMimeType
import java.io.File
import java.io.FileInputStream


/**
 * A simple [Fragment] subclass as the default destination in the navigation.
 * https://developer.android.com/codelabs/build-your-first-android-app-kotlin#7
 */
class FirstFragment : Fragment() {


    private val CREATE_REQUEST_CODE = 40
    private val OPEN_REQUEST_CODE = 41
    private val SAVE_REQUEST_CODE = 42

    override fun onCreateView(
            inflater: LayoutInflater, container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_first, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val clipboard = activity?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager


        view.findViewById<Button>(R.id.random_button).setOnClickListener {
            findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
        }

        // find the toast_button by its ID and set a click listener

        Log.d("TAG", ">>" + Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString())
        view.findViewById<Button>(R.id.toast_button).setOnClickListener {
            // create a Toast with some text, to appear for a short time
            Log.d("TAG", ">>>>>>>>>>>>>>>>>>>>1")
            // openDirectory()
            var keyStr = ""
            val file = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString(), "QS_Encryption_key.txt")
            FileInputStream(file).use { stream ->
                val text = stream.bufferedReader().use {
                    it.readText()
                }
                keyStr = "$text"
                Log.d("TAG", "LOADED: $text")
                view.findViewById<TextView>(R.id.textview_first).text = "$text"
            }


            keyStr = "uEe3T2YLQN3hf9lcYR5/BySWkCA7NOisoHTYPwL2dnl="
            val myToast = Toast.makeText(context, keyStr, Toast.LENGTH_SHORT)
            // show the Toast
            myToast.show()
        }

    }

    fun isExternalStorageReadable(): Boolean {
        return Environment.getExternalStorageState() in
                setOf(Environment.MEDIA_MOUNTED, Environment.MEDIA_MOUNTED_READ_ONLY)
    }

//    fun openFile(activity: AppCompatActivity, selectedItem: File) {
//        // Get URI and MIME type of file
//        val uri = Uri.fromFile(selectedItem).normalizeScheme()
//        val mime: String = getMimeType(uri.toString())
//
//        // Open file with user selected app
//        val intent = Intent()
//        intent.action = Intent.ACTION_VIEW
//        intent.data = uri
//        intent.type = mime
//        return activity.startActivity(intent)
//    }
//
//
//    fun getFilesList(selectedItem: File): List<File> {
//        val rawFilesList = selectedItem.listFiles()?.filter { !it.isHidden }
//
//        return if (selectedItem == Environment.getExternalStorageDirectory()) {
//            rawFilesList?.toList() ?: listOf()
//        } else {
//            listOf(selectedItem.parentFile) + (rawFilesList?.toList() ?: listOf())
//        }
//    }
//

    fun openFile(activity: FirstFragment, selectedItem: File) {
        // Get URI and MIME type of file
        val uri = Uri.fromFile(selectedItem).normalizeScheme()
        val mime: String = getMimeType(uri.toString())

        // Open file with user selected app
        val intent = Intent()
        intent.action = Intent.ACTION_VIEW
        intent.data = uri
        intent.type = mime
        return activity.startActivity(intent)
    }


    private fun open(selectedItem: File) {

        if (selectedItem.isFile) {
            return openFile(this, selectedItem)
        }

        var currentDirectory: File
        var filesList: List<File>
        currentDirectory = selectedItem
        filesList = getFilesList(currentDirectory)

        filesList.map {
            Log.d("TAG", ">>" +it.path)
        }

        return
        Log.d("TAG", ">>>>>>>>>>>>>>>>>>>>2.0" + Environment.DIRECTORY_DOWNLOADS)
        val numbersIterator = filesList.iterator()
        while (numbersIterator.hasNext()) {

            var currentFile: File
            currentFile = numbersIterator.next()
            Log.d("TAG", ">>" + currentFile.toString())
            //open(currentFile)
            Log.d("TAG", ">>>>>>>>>>>>>>>>>>>>3.0")
        }
    }



    fun openDirectory() {
        // Choose a directory using the system's file picker.
        //Environment.getExternalStorageDirectory()
        open(Environment.getExternalStorageDirectory())
        //Environment.getDataDirectory()
        //Environment.getStorageDirectory()
        //Environment.getDownloadCacheDirectory()
        //open(Environment.getDataDirectory())
        //Environment.getRootDirectory()
        //open(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS))
        //open(Environment.getRootDirectory())
        //open(Environment.getDownloadCacheDirectory())
        //listFiles(Environment.getDownloadCacheDirectory())
    }






       // val path = context?.getFilesDir()
       //val letDirectory = File(path, "Download")
        //val file = File(letDirectory, "QS_Encryption_key.txt")

        //val fileName = "/Download/QS_Encryption_key.txt"
        //if (isExternalStorageReadable()) {
        //    FileInputStream(file).use { stream ->
        //        val text = stream.bufferedReader().use {
        //            it.readText()
        //       }
        //        Log.d("TAG", "LOADED: $text")
        //    }













    override fun onActivityResult(
        requestCode: Int, resultCode: Int, resultData: Intent?) {
        super.onActivityResult(requestCode, resultCode, resultData)
        Log.d("TAG", ">>>>>>>>>>>>>>>>>>>>4")
        // The result data contains a URI for the document or directory that
        // the user selected.
        resultData?.data?.also { uri ->
            // Perform operations on the document using its URI.

            Log.d("TAG", ">>>>>>>>>>>>>>>>>>>>5")
            //Log.d("TAG", readTextFromUri(uri))

        }
    }

}


