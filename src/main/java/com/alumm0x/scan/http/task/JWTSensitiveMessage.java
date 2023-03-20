package com.alumm0x.scan.http.task;

import burp.IParameter;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.json.ParamHandlerImpl;
import com.alumm0x.util.param.json.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;


public class JWTSensitiveMessage extends TaskImpl {

    public static String name = "JWTSensitiveMessage";
    public static String comments = "JWT敏感信息检测。是否在JWT中传输敏感信息，这里主要检测账号密码/token。";
    public static String fix = "禁止在JWT中传输敏感信息，JWT使用base64加密，无法保证信息的机密性。";

    public UselessTreeNodeEntity entity;

    public JWTSensitiveMessage(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        LogEntry logEntry = logAddToScanLogger(entity.getCurrent(), "JWTSensitiveMessage");
        // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
        for (IParameter parameter : CommonStore.helpers.analyzeRequest(entity.getRequestResponse()).getParameters()) {
            byte[] decode = CommonStore.helpers.base64Decode(parameter.getValue());
            if (new String(decode).contains("\"alg\"")) {
                if (new String(decode).contains("password")) {
                    logEntry.hasVuln();
                    logEntry.Comments = new String(decode);
                }
            }
        }
        // 检查请求头
        for (String value : BurpReqRespTools.getReqHeadersToMap(entity.getRequestResponse()).values()) {
            byte[] decode = CommonStore.helpers.base64Decode(value);
            if (new String(decode).contains("\"alg\"")) {
                if (new String(decode).contains("password")) {
                    logEntry.hasVuln();
                    logEntry.Comments = new String(decode);
                }
            }
        }
        // 检查json数据
        if (BurpReqRespTools.getContentType(entity.getRequestResponse()).contains("application/json")
                && BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0
                && new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("{")){
            JsonTools tools = new JsonTools();
            try {
                tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse()))), new ParamHandlerImpl() {
                    @Override
                    public ParamKeyValue handler(Object key, Object value) {
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"")) {
                            if (new String(decode).contains("password")) {
                                logEntry.hasVuln();
                                logEntry.Comments = new String(decode);
                            }
                        }
                        return new ParamKeyValue(key, value);
                    }
                });
            } catch (Exception e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }
    }
}
