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
import com.alumm0x.util.risk.SecStaticCheck;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Cors extends TaskImpl {

    public static String name = "Cors";
    public static String comments = "跨域策略检测。验证是否允许跨域请求。";
    public static String fix = "禁止允许任意跨域，根据业务场景限制跨域范围，通过cors配置进行限制";

    public UselessTreeNodeEntity entity;

    public Cors(UselessTreeNodeEntity entity) {
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
        // 检查是否存在origin,不存在就添加一个
        if (SecStaticCheck.hasHdeader(header.NEW_HEADER, "Origin") == null) {
            header.NEW_HEADER.add("Origin: http://evil.com");
        }
        //新的请求包
        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                header.NEW_HEADER,
                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                new CorsCallback(this));
    }
}

class CorsCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public CorsCallback(TaskImpl task){
        this.task = task;
        this.entity = ((JsonpCors)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "Cors");
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
        // 这两个头必须要存在，不存在浏览器默认不允许跨域
        String origin = SecStaticCheck.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Access-Control-Allow-Origin");
        String credentials = SecStaticCheck.hasHdeader(BurpReqRespTools.getRespHeaders(requestResponse), "Access-Control-Allow-Credentials");
        if (response.isSuccessful() &&
                origin != null && origin.contains("http://evil.com") &&
                credentials != null && origin.contains("true")
        ){
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