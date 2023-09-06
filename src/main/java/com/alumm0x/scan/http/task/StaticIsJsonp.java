package com.alumm0x.scan.http.task;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticIsJsonp extends StaticTaskImpl {

    public static String name = "IsJsonp";
    public static String comments = "识别jsonp场景,可以测试json漏洞";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticIsJsonp(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 检测jsonp
        if (isJsonp(entity.getRequestResponse())){
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 静态检测jsonp
     * @return
     */
    public static boolean isJsonp(IHttpRequestResponse requestResponse){
        // 1.响应content-type需要是js
        if (ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "content-type") != null
                && ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "content-type").contains("/javascript")) {
            String resp = new String(BurpReqRespTools.getRespBody(requestResponse));
            for (Object queryvalue : BurpReqRespTools.getQueryMap(requestResponse).values()) {
                // fix: 现在返回的不一定是函数名开头了
                if (resp.contains(queryvalue + "(")){
                    return true;
                }
            }
        }
        return false;
    }
}

