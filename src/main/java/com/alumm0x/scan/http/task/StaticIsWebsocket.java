package com.alumm0x.scan.http.task;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticIsWebsocket extends StaticTaskImpl {

    public static String name = "IsWebsocket";
    public static String comments = "识别使用Websocket的场景";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticIsWebsocket(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        // 是否websocket
        if (isWebsocket(entity.getRequestResponse())){
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 静态检测websocket,检查是否包含相关请求头
     * @return
     */
    public static boolean isWebsocket(IHttpRequestResponse requestResponse){
        // 头部信息包含Upgrade
        return ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(requestResponse), "Sec-WebSocket-Key") != null;
    }
}

