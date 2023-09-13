package com.fang.myapplication;

import android.content.Context;
import android.graphics.Color;
import android.util.AttributeSet;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.ViewGroup;

import com.fang.myapplication.model.NALPacket;
import com.fang.myapplication.model.PCMPacket;
import com.fang.myapplication.player.AudioPlayer;
import com.fang.myapplication.player.VideoPlayer;

import org.greenrobot.eventbus.EventBus;
import org.greenrobot.eventbus.Subscribe;
import org.greenrobot.eventbus.ThreadMode;

import java.io.IOException;

public class RaopServer implements SurfaceHolder.Callback {

    static {
        System.loadLibrary("raop_server");
        System.loadLibrary("play-lib");
    }
    private static final String TAG = "AIS-RaopServer";
    private VideoPlayer mVideoPlayer;
    private AudioPlayer mAudioPlayer;
    private ResizeAbleSurfaceView mSurfaceView;
    private SurfaceHolder mSurfaceHolder;
    private int mSurfaceWidth = 1920;
    private int mSurfaceHeight = 1080;
    private long mServerId = 0;

    public RaopServer(ResizeAbleSurfaceView surfaceView) {
        mSurfaceView = surfaceView;
        mSurfaceView.getHolder().addCallback(this);
        mAudioPlayer = new AudioPlayer();
        mAudioPlayer.start();
        EventBus.getDefault().register(this);
    }

    public void onRecvVideoData(byte[] nal, int nalType, long dts, long pts, int width, int height) {
        NALPacket nalPacket = new NALPacket();
        nalPacket.nalData = nal;
        nalPacket.nalType = nalType;
        nalPacket.pts = pts;
		nalPacket.dts = pts;
        nalPacket.srcWidth = width;
        nalPacket.srcHeight = height;
        mVideoPlayer.addPacker(nalPacket);
        Log.d(TAG, "@@@@@@@@@@@@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$onRecvVideoData width = " + width + ", height = " + height);
        if(width <= 0 || height <= 0)
            return;
        //Log.d(TAG, "onRecvVideoData dts = " + dts + ", pts = " + pts + ", nalType = " + nalType + ", nal length = " + nal.length + "width=" + width + ", height =" + height);
        if(mSurfaceWidth != width || mSurfaceHeight != height)
        {
            mSurfaceWidth = width;
            mSurfaceHeight = height;
            EventBus.getDefault().post(new SurfaceResizeEvent(mSurfaceWidth, mSurfaceHeight));
        }
    }

    public void onRecvAudioData(short[] pcm, long pts) {
        //Log.d(TAG, "onRecvAudioData pcm length = " + pcm.length + ", pts = " + pts);
        PCMPacket pcmPacket = new PCMPacket();
        pcmPacket.data = pcm;
        pcmPacket.pts = pts;
        mAudioPlayer.addPacker(pcmPacket);
    }

    @Subscribe(threadMode = ThreadMode.MAIN,sticky = true)
    public void onSurfaceResizeEvent(SurfaceResizeEvent eventData) throws IOException {
        Log.d(TAG, "@@@@@@@@@@@@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$onSurfaceResizeEvent width = " + eventData.Width + ", height = " + eventData.Height);
        ViewGroup.LayoutParams lp = mSurfaceView.getLayoutParams();
        lp.width = eventData.Width;
        lp.height =eventData.Height;
        mSurfaceView.setLayoutParams(lp);
        int x = (1920 - eventData.Width) / 2;
        mSurfaceView.setX(x);

        mVideoPlayer.setDecoderSize(eventData.Width, eventData.Height);
    }


    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        Log.d(TAG, "@@@surfaceCreated");
        mSurfaceHolder = holder;
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        Log.d(TAG, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@surfaceChanged width = " + width + ", height = " + height);
        if (mVideoPlayer == null) {
            mVideoPlayer = new VideoPlayer(holder.getSurface());
            mVideoPlayer.start();
        }
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {

    }

    public void startServer() {
        if (mServerId == 0) {
            mServerId = start();
        }
    }

    public void stopServer() {
        if (mServerId != 0) {
            stop(mServerId);
        }
        mServerId = 0;

    }

    public int getPort() {
        if (mServerId != 0) {
            return getPort(mServerId);
        }
        return 0;
    }

    private native long start();
    private native void stop(long serverId);
    private native int getPort(long serverId);
}
