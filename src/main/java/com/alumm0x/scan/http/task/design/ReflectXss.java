package com.alumm0x.scan.http.task.design;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ReflectXss extends TaskImpl {

    public static String name = "ReflectXss";
    public static String comments = "反射型XSS，检查查询参数是否出现在响应中";
    public static String fix = "根据数据输出的位置进行输出编码。可用业内成熟框架: esapi";

    public UselessTreeNodeEntity entity;

    public ReflectXss(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        String querystring = BurpReqRespTools.getQuery(entity.getRequestResponse());
        if (querystring != null) {
            for (Map.Entry<String, StaticCheckResult> entry :
                            entity.risks.entrySet()) {
                if (entry.getKey().startsWith("反射型XSS")) {
                    // 加载payload的模版
                    List<String> payloads = SourceLoader.loadSources("/payloads/ReflectXss.bbm");
                    for (String paylaod : payloads) {
                        FormTools tools = new FormTools();
                        tools.formHandler(BurpReqRespTools.getQueryMap(entity.getRequestResponse()), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                    if (entry.getValue().risk_param.equals(key)) {
                                        paramKeyValues.add(new ParamKeyValue(key, paylaod));
                                    } else {
                                        paramKeyValues.add(new ParamKeyValue(key, value));
                                    }
                                return paramKeyValues;
                            }
                        });
                        //新的请求包
                        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                                BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                                tools.toString(),
                                BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                                new ReflectXssCallback(this, paylaod));
                    }
                }
            }
        } else {
            CommonStore.callbacks.printError("[ReflectXss] 不满足前置条件1: 必须要有查询参数\n" +
                    "##url: " + BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }
}

class ReflectXssCallback implements Callback {
    UselessTreeNodeEntity entity;
    LogEntry logEntry;
    TaskImpl task;
    String payload;

    public ReflectXssCallback(TaskImpl task, String payload){
        this.task = task;
        this.entity = ((ReflectXss)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "ReflectXss");
        this.logEntry.Comments = payload;
        this.payload = payload;
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[ReflectXssCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = requestResponse;
        logEntry.Status = (short) response.code();
        if (response.isSuccessful()) {
            //检查验证数据是否原样在响应中出现
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains(this.payload)) {
                logEntry.hasVuln();
                entity.color = "red";
            } else {
                // 更新本次验证的结果
                logEntry.onResponse();
            }
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}