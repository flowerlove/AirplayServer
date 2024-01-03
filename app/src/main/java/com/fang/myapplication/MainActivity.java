package com.fang.myapplication;

import android.app.Activity;
import android.content.Context;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.os.Bundle;
import android.os.Environment;
import android.os.storage.StorageManager;
import android.util.Log;
import android.view.SurfaceView;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class MainActivity extends Activity implements View.OnClickListener {

	public static String TAG = "AIS-RAOP-Main";

	private AirPlayServer mAirPlayServer;
	private RaopServer mRaopServer;
	private DNSNotify mDNSNotify;

	private ResizeAbleSurfaceView mSurfaceView;
	private Button mBtnControl;
	private TextView mTxtDevice;
	private boolean mIsStart = false;
	private StorageManager mStorageManager;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		getSystemService(Context.NSD_SERVICE);
		mBtnControl = findViewById(R.id.btn_control);
		mTxtDevice = findViewById(R.id.txt_device);
		mBtnControl.setOnClickListener(this);
		mSurfaceView = findViewById(R.id.surface);
		mAirPlayServer = new AirPlayServer();
		mRaopServer = new RaopServer(mSurfaceView);
		mDNSNotify = new DNSNotify();

//		MediaCodecList mediaCodecList = new MediaCodecList(MediaCodecList.ALL_CODECS);
//		MediaCodecInfo[] mediaCodecInfos = mediaCodecList.getCodecInfos();
//		for (int i = 0; i < mediaCodecInfos.length; i++) {
//			if (mediaCodecInfos[i].isEncoder()) {
//				continue;
//			}
//			Log.d(TAG, "codec= " + mediaCodecInfos[i].getName() +
//					"\nis_encoder=" + mediaCodecInfos[i].isEncoder() +
//					"\nis_vendor=" + mediaCodecInfos[i].isVendor() +
//					"\nhw_acc=" + mediaCodecInfos[i].isHardwareAccelerated() +
//					"\nsw_acc=" + mediaCodecInfos[i].isSoftwareOnly());
//			String[] types = mediaCodecInfos[i].getSupportedTypes();
//			Log.d(TAG, "supported codec = " + String.join(", ", types));
//
////			mediaCodecInfos[i].VideoCapabilities.getSupportedPerformancePoints();
//			// for (int j = 0; j < types.length; j++) {
//			// Log.d(TAG, "supported codec = " + types[j]);
//			// }
//		}
//		checkUdisk();
	}

	private void checkUdisk(){
		//udisk_insert = false;
//		Class volumeInfoClazz = null;
//		Method getVolumes = null;
//		Method getPath = null;
//		Method getUserLabel = null;
//		Object[] volumes = null;
//		try {
//			volumeInfoClazz = Class.forName("android.os.storage.StorageVolume");
//			getVolumes = StorageManager.class.getMethod("getVolumeList");
//			getPath = volumeInfoClazz.getMethod("getPath");
//			getUserLabel = volumeInfoClazz.getMethod("getUserLabel");
//			volumes = (Object[])getVolumes.invoke(mStorageManager);
//			for (Object vol : volumes) {
//				String path = (String) getPath.invoke(vol);
//				if (path.indexOf("udisk0")!=-1){
//					String userLabel = (String) getUserLabel.invoke(vol);
//				}else if (path.indexOf("udisk1")!=-1){
//					String userLabel = (String) getUserLabel.invoke(vol);
//				}
//			}
//		}catch (Exception ex) {
//			ex.printStackTrace();
//		}

//		Class<?> volumeInfoClazz = null;
//		Method getBestVolumeDescription = null;
//		Method getVolumes = null;
//		Method isMountedReadable = null;
//		Method getType = null;
//		Method getPath = null;
//		List<?> volumes = null;
//		try {
//			volumeInfoClazz = Class.forName("android.os.storage.VolumeInfo");
//			getBestVolumeDescription = StorageManager.class.getMethod("getBestVolumeDescription", volumeInfoClazz);
//			getVolumes = StorageManager.class.getMethod("getVolumes");
//			isMountedReadable = volumeInfoClazz.getMethod("isMountedReadable");
//			getType = volumeInfoClazz.getMethod("getType");
//			getPath = volumeInfoClazz.getMethod("getPath");
//			mStorageManager = (StorageManager)getSystemService(Context.STORAGE_SERVICE);
//			volumes = (List<?>)getVolumes.invoke(mStorageManager);
//
//			for (Object vol : volumes) {
//				if (vol != null && (boolean)isMountedReadable.invoke(vol) && (int)getType.invoke(vol) == 0) {
//					File path2 = (File)getPath.invoke(vol);
//					String p1 = (String)getBestVolumeDescription.invoke(mStorageManager, vol);
//					String p2 = path2.getPath();
//					Log.d(TAG,"-----------path2-----------------"+p1);                             //打印U盘卷标名称
//					Log.d(TAG,"-----------path2 @@@@@-----------------"+p2);         //打印U盘路径
//				}
//			}
//		}catch (Exception ex) {
//			ex.printStackTrace();
//		}
	}
	@Override
	public void onClick(View v) {
		switch (v.getId()) {
			case R.id.btn_control: {
				if (!mIsStart) {
					startServer();
					mTxtDevice.setText("Device name:" + mDNSNotify.getDeviceName());
				} else {
					stopServer();
					mTxtDevice.setText("have not started");
				}
				mIsStart = !mIsStart;
				mBtnControl.setText(mIsStart ? "End" : "Start");
				break;
			}
		}
	}

	private void startServer() {
		mDNSNotify.changeDeviceName();
		Log.d("AirPlay", "airplayPort1 = ");
		mAirPlayServer.startServer();
		Log.d("AirPlay", "airplayPort2 = ");
		int airplayPort = mAirPlayServer.getPort();
		Log.d("AirPlay", "airplayPort3 = ");
		mDNSNotify.registerAirplay(airplayPort);
		Log.d("AirPlay", "airplayPort4 = " );
		mRaopServer.startServer();
		Log.d("AirPlay", "airplayPort5 = " + airplayPort);
		int raopPort = mRaopServer.getPort();
		Log.d("AirPlay", "airplayPort6 = " + airplayPort + ", raopPort = " + raopPort);
		mDNSNotify.registerRaop(raopPort);
		Log.d("AirPlay", "airplayPort7 = " + airplayPort + ", raopPort = " + raopPort);
//		mDNSNotify.changeDeviceName();
//		mAirPlayServer.startServer();
//		int airplayPort = mAirPlayServer.getPort();
//		if (airplayPort == 0) {
//			Toast.makeText(this.getApplicationContext(), "Start the AirPlay service failed", Toast.LENGTH_SHORT).show();
//		} else {
//			mDNSNotify.registerAirplay(airplayPort);
//		}
//		mRaopServer.startServer();
//		int raopPort = mRaopServer.getPort();
//		if (raopPort == 0) {
//			Toast.makeText(this.getApplicationContext(), "Start the RAOP service failed", Toast.LENGTH_SHORT).show();
//		} else {
//			mDNSNotify.registerRaop(raopPort);
//		}
//		Log.d(TAG, "airplayPort = " + airplayPort + ", raopPort = " + raopPort);
	}

	private void stopServer() {
		mDNSNotify.stop();
		mAirPlayServer.stopServer();
		mRaopServer.stopServer();
	}

}
