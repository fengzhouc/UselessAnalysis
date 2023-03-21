package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.header.HeaderTools;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class JsonpCors extends TaskImpl {

    public static String name = "JsonpCors";
    public static String comments = "Jsonp的跨域请求检测。验证是否允许跨域请求，允许则存在Jsonp风险。";
    public static String fix = "限制请求来源，设置来源白名单，也就是referer（如果没有referer也不允许，有些场景是不带referer的）。";

    public UselessTreeNodeEntity entity;

    public JsonpCors(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 修改请求头referer/origin为恶意的
        HeaderTools header = new HeaderTools();
        header.headerHandler(BurpReqRespTools.getReqHeadersToMap(entity.getRequestResponse()), new ParamHandlerImpl() {
            @Override
            public List<ParamKeyValue> handler(Object key, Object value) {
                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                if (key.toString().equalsIgnoreCase("referer")) {
                    paramKeyValues.add(new ParamKeyValue(key, "http://evil.com"));
                } else if (key.toString().equalsIgnoreCase("origin")) {
                    paramKeyValues.add(new ParamKeyValue(key, "http://evil.com"));
                } else {
                    paramKeyValues.add(new ParamKeyValue(key, value));
                }
                return paramKeyValues;
            }
        });

        //新的请求包
        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                header.NEW_HEADER,
                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                new JsonpCallback(this));
    }
}

class JsonpCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public JsonpCallback(TaskImpl task){
        this.task = task;
        this.entity = ((JsonpCors)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "JsonpCors");
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
        if (response.isSuccessful()){
            // 响应体与原来相同，则存在问题
            if (Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(entity.getRequestResponse()))) {
                logEntry.hasVuln();
            } else {
                logEntry.onResponse();
            }
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}