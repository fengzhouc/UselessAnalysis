package com.alumm0x.scan.http.task;


import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticLoginApi extends StaticTaskImpl {

    public static String name = "LoginApi";
    public static String comments = "识别登录的接口";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticLoginApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        if (isLoginApi(entity.getRequestResponse())) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 判断该该请求是否为登录接口
     * @param requestResponse
     * @return
     */
    public static boolean isLoginApi(IHttpRequestResponse requestResponse) {
        // 1.必须有参数
        if (BurpReqRespTools.getQueryMap(requestResponse).size() > 0 || BurpReqRespTools.getReqBody(requestResponse).length > 0) {
            //识别参数特征，这个准确性高，登陆的参数类型有哪些
            // - header（basic认证）authorization
            if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "authorization") != null) {
                return true;
            }
            // - query（username：passwod）不安全设计
            if (BurpReqRespTools.getQueryMap(requestResponse).containsKey("password") 
                || BurpReqRespTools.getQueryMap(requestResponse).containsKey("passwd")){
                return true;
            }
            // - body（username：passwod）最传统的
            if (new String(BurpReqRespTools.getReqBody(requestResponse)).contains("password")
                || new String(BurpReqRespTools.getReqBody(requestResponse)).contains("passwd")){
                return true;
            }
            // //识别url特征，如login, username参数（这个比较弱，容易误报，放到最后）
            // String url = BurpReqRespTools.getUrl(requestResponse);
            // if (url.contains("login")){
            //     return true;
            // }
        }
        return false;
    }
}

