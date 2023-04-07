package com.alumm0x.scan;

import burp.IHttpRequestResponse;

public class LogEntry {
    public final int id;
    public  IHttpRequestResponse requestResponse;
    public  String Url;
    public  short Status;
    public  String Poc;
    private String Scanning; //根据这里的值设置底色（verifying/默认色，has vuln!!!/red，Reuqest failed./yellow，Done/默认色）
    public String Comments;


    public LogEntry(int id, IHttpRequestResponse requestResponse, String url, String poc)
    {
        this.id = id;
        this.requestResponse = requestResponse;
        this.Url = url;
        this.Status = -1;
        this.Poc = poc;
        this.Scanning = "verifying";
        this.Comments = "";
    }

    public String getScanning() {
        return this.Scanning;
    }

    /**
     * 存在漏洞调用
     */
    public void hasVuln() {
        this.Scanning = "has vuln!!!";
    }

    /**
     * 检查结果是否存在漏洞
     * @return
     */
    public boolean isVuln() {
        return this.Scanning.equals("has vuln!!!");
    }

    /**
     * 回调onFailure的时候设置
     */
    public void onFailure(){
        this.Scanning = "Reuqest failed.";
    }

    /**
     * 没有漏洞的时候调用
     */
    public void onResponse(){
        this.Scanning = "Done";
    }

}
