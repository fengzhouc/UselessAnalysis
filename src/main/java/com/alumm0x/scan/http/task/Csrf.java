package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.HeaderTools;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.ToolsUtil;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class Csrf extends TaskImpl {
    public static String name = "CSRF";
    public static String comments = "表单的跨站请求伪造检测。删除所有csrftoken的信息，重访请求，若响应一样则存在问题。";
    public static String fix = "需要增加来源验证的功能，比如token令牌/校验referer等方式。";

    public UselessTreeNodeEntity entity;

    public Csrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、Csrf-form表单
         *   （1）检查content为form表单
         *   （2）删除token请求头重放，看是否响应跟原响应一致
         * */
        //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (ToolsUtil.hasHeader(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Cookie") != null){
            List<String> new_headers = new ArrayList<>();
            //新请求修改origin
            for (String header : BurpReqRespTools.getReqHeaders(entity.getRequestResponse())) {
                // 剔除掉csrf头部
                if (HeaderTools.inNormal(header.split(":")[0])) {
                    if (!header.toLowerCase(Locale.ROOT).contains("Origin".toLowerCase(Locale.ROOT))) {
                        new_headers.add(header);
                    }
                }
            }
            CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                    BurpReqRespTools.getMethod(entity.getRequestResponse()),
                    new_headers,
                    BurpReqRespTools.getQuery(entity.getRequestResponse()),
                    BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                    BurpReqRespTools.getContentType(entity.getRequestResponse()),
                    new CsrfCallback(this));
        }else{
            CommonStore.callbacks.printError("[Csrf] 不满足前置条件1: 必须要有'Cookie'\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }
}

class CsrfCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public CsrfCallback(TaskImpl task){
        this.task = task;
        this.entity = ((Csrf)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "Csrf");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[CsrfCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (response.isSuccessful()){
            //如果状态码相同及响应内容一样，则可能存在问题
            if (BurpReqRespTools.getStatus(entity.getRequestResponse()) == BurpReqRespTools.getStatus(requestResponse)
                    && Arrays.equals(BurpReqRespTools.getRespBody(entity.getRequestResponse()), BurpReqRespTools.getRespBody(requestResponse))) {
                logEntry.hasVuln();
                entity.color = "red";
            } else {
                logEntry.onResponse();
            }
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}