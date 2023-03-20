package com.alumm0x.scan.http.task;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.HeaderTools;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.risk.SecStaticCheck;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class WebSocketHijacking extends TaskImpl {

    public static String name = "WebSocketHijacking";
    public static String comments = "WebSocket的跨站请求检测。通过修改Origin，验证是否可以跨域连接。";
    public static String fix = "后端需要校验请求来源。";

    public UselessTreeNodeEntity entity;
    public WebSocketHijacking(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * websocket的csrf，类似jsonp，是不受cors限制的
         *   1.使用cookie
         *   2.修改/添加请求头Origin为http://evil.com，看是否能连接成功
         * */
        //利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (SecStaticCheck.hasHdeader(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Cookie") != null){
            /*
             * websocket请求跨域连接
             * 修改origin
             */
            if (SecStaticCheck.hasHdeader(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Sec-WebSocket-Key") != null){
                List<String> new_headers = new ArrayList<>();
                String evilOrigin = "http://evil.com";
                //新请求修改origin
                for (String header :
                        BurpReqRespTools.getReqHeaders(entity.getRequestResponse())) {
                    // 剔除掉csrf头部
                    if (HeaderTools.inNormal(header.split(":")[0].toLowerCase(Locale.ROOT))) {
                        if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                            new_headers.add(header);
                        }
                    }
                }
                new_headers.add("Origin: " + evilOrigin);
                CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getMethod(entity.getRequestResponse()),
                        new_headers,
                        BurpReqRespTools.getQuery(entity.getRequestResponse()),
                        BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                        BurpReqRespTools.getContentType(entity.getRequestResponse()),
                        new WebSocketHijackingCallback(this));
            }else{
                CommonStore.callbacks.printError("[WebSocketHijacking] 不满足前置条件2: 必须要有'Sec-WebSocket-Key'请求头\n" +
                        "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
            }
        }else{
            CommonStore.callbacks.printError("[WebSocketHijacking] 不满足前置条件1: 必须要有Cookie\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }
}

class WebSocketHijackingCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public WebSocketHijackingCallback(TaskImpl task){
        this.task = task;
        this.entity = ((IDOR)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "WebSocketHijacking");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (BurpReqRespTools.getStatus(requestResponse) == 101){
            logEntry.hasVuln();
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}