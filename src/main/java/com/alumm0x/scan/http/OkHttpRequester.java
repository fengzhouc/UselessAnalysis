package com.alumm0x.scan.http;

import com.alumm0x.util.CommonStore;
import okhttp3.*;

import java.io.IOException;
import java.util.List;


public class OkHttpRequester {

    //单例模式
    private static OkHttpRequester okHttpRequester = null;
    private final OkHttpClient client; //全局只有一个实例，利用okhttp的内置并发机制

    private OkHttpRequester(){
        this.client = new OkHttpClient.Builder()
                .followRedirects(false) //不跳转
                .followSslRedirects(false) //不跳转
                .sslSocketFactory(SSLSocketClient.getSSLSocketFactory(), SSLSocketClient.getX509TrustManager()) // 忽略https证书
                .hostnameVerifier(SSLSocketClient.getHostnameVerifier()) // 忽略https证书
                .build();
    }

    public static OkHttpRequester getInstance(){
        if (okHttpRequester == null){
            okHttpRequester = new OkHttpRequester();
        }
        return okHttpRequester;
    }

    private Headers SetHeaders(List<String> headerList){
        Headers.Builder headers = new Headers.Builder();
        for (String header :
                headerList) {
            //处理okhttp响应乱码的问题，删除Accept-Encoding请求头
            if (!header.toLowerCase().contains("accept-encoding")) {
                headers.add(header);
            }
        }
        return headers.build();
    }

    // 改用第三方的发包器-okhttp3
    // 并发说明 https://juejin.cn/post/6949527136088621070
    // 基本使用 https://mp.weixin.qq.com/s?__biz=MzU2NjgwNjc0NQ==&mid=2247483867&idx=1&sn=fda05eb481bd1d2c7a52b8e41c01de8c&chksm=fca7906dcbd0197b2c6af55af2843edf7db987ca19659ea72119563100f2c59976e657fa7a6b&scene=21#wechat_redirect
    // 工作流 https://cloud.tencent.com/developer/article/1667339
    // 根据method进行选择不同的发送函数，也可以直接调用对应的
    public void send(String url, String method, List<String> headerList, String query, byte[] bodyParam, String contentType, Callback callback){
//        CommonStore.callbacks.printError(url);
//        CommonStore.callbacks.printError(method);
//        CommonStore.callbacks.printError(Arrays.toString(headerList.toArray()));
//        CommonStore.callbacks.printError(query);
//        CommonStore.callbacks.printError(new String(bodyParam));
//        CommonStore.callbacks.printError(contentType);
        // 根据query的情况进行组装url
        url = query == null || query.equals("") ? url : url + "?" + query;
        switch (method){
            case "GET":
                get(url, headerList, callback);
                break;
            case  "HEAD": //不发包检测
                break;
            default:
                defSend(url, method, headerList, bodyParam, contentType, callback);
        }
    }

    public void defSend(String url, String method, List<String> headerList, byte[] bodyParam, String contentType, Callback callback){
        MediaType content_Type = MediaType.parse(contentType);
        RequestBody body = RequestBody.Companion.create(bodyParam, content_Type);
        Request request = null;
        try {
            request = new Request.Builder()
                    .url(url)
                    .method(method, body)
                    .headers(SetHeaders(headerList))
                    .header("Content-Length", String.valueOf(body.contentLength()))
                    .build();
        } catch (IOException e) {
            CommonStore.callbacks.printError(e.getMessage());
            e.printStackTrace();
        }
        //返回响应
        assert request != null;
        Call call = this.client.newCall(request);
        call.enqueue(callback);
    }

    public void get(String url, List<String> headerList, Callback callback){
        //新的请求包
        Request request = new Request.Builder()
                .url(url)
                .get()
                .headers(SetHeaders(headerList))
                .build();
        Call call = this.client.newCall(request);
        call.enqueue(callback);
    }

    public void get(String url, Callback callback){
        //新的请求包
        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();
        Call call = this.client.newCall(request);
        call.enqueue(callback);
    }

//    public IHttpRequestResponse postForm(IHttpService iHttpService, Headers headers, String param,Callback callback){
//        //新的请求包
//        OkHttpClient client = new OkHttpClient();
//        MediaType contentType = MediaType.parse("application/x-www-form-urlencoded; charset=utf-8");
//        RequestBody body = RequestBody.create(contentType, param);
//        Request request = new Request.Builder()
//                .url()
//                .post()
//                .headers(headers)
//                .build();
//        //返回响应
//        return this.callbacks.makeHttpRequest(iHttpService, req);
//    }
//
//    public IHttpRequestResponse postJson(IHttpService iHttpService, Headers headers, String param){
//        //新的请求包
//        OkHttpClient client = new OkHttpClient();
//        MediaType contentType = MediaType.parse("application/json; charset=utf-8");
//        RequestBody body = RequestBody.create()
//        Request request = new Request.Builder()
//                .url()
//                .post()
//                .headers(headers)
//                .build();
//        //返回响应
//        return this.callbacks.makeHttpRequest(iHttpService, req);
//    }
//
//    public IHttpRequestResponse postXml(IHttpService iHttpService, Headers headers, String param){
//        //新的请求包
//        OkHttpClient client = new OkHttpClient();
//        MediaType contentType = MediaType.parse("application/xml; charset=utf-8");
//        RequestBody body = RequestBody.create()
//        Request request = new Request.Builder()
//                .url()
//                .post()
//                .headers(headers)
//                .build();
//        //返回响应
//        return this.callbacks.makeHttpRequest(iHttpService, req);
//    }
//
//    public IHttpRequestResponse postUpload(IHttpService iHttpService, Headers headers, String param){
//        //新的请求包
//        OkHttpClient client = new OkHttpClient();
//        MediaType contentType = MediaType.parse("multipart/form-data; charset=utf-8");
//        RequestBody body = RequestBody.create()
//        Request request = new Request.Builder()
//                .url()
//                .post()
//                .headers(headers)
//                .build();
//        //返回响应
//        return this.callbacks.makeHttpRequest(iHttpService, req);
//    }
}
