package com.alumm0x.scan.http.task;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticLoginOutApi extends StaticTaskImpl {

    public static String name = "LoginOutApi";
    public static String comments = "识别登录登出的接口";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticLoginOutApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        if (isLoginOutApi(entity.getRequestResponse())) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 判断该该请求是否为登录登出接口
     * @param url
     * @return
     */
    public static boolean isLoginOutApi(IHttpRequestResponse requestResponse) {
        //1.识别url特征，如login/logout
        String url = BurpReqRespTools.getUrl(requestResponse);
        if (url.contains("login") || url.contains("logout")) {
            return true;
        }
        //2.识别响应头Set-Cookie，一般是登录登出的时候会有这类操作，当然排除不使用cookie作会话凭证的
        String setCookie = ToolsUtil.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null) {
            return true;
        }
        return false;
    }
}

