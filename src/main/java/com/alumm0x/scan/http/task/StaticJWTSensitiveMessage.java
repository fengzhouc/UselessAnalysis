package com.alumm0x.scan.http.task;

import burp.IParameter;
import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;

import java.util.ArrayList;
import java.util.List;


public class StaticJWTSensitiveMessage extends StaticTaskImpl {

    public static String name = "JWTSensitiveMessage";
    public static String comments = "JWT敏感信息检测。是否在JWT中传输敏感信息，这里主要检测账号密码/token。";
    public static String fix = "禁止在JWT中传输敏感信息，JWT使用base64加密，无法保证信息的机密性。";

    public UselessTreeNodeEntity entity;

    public StaticJWTSensitiveMessage(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        List<StaticCheckResult> results = new ArrayList<>();
        // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
        for (IParameter parameter : CommonStore.helpers.analyzeRequest(entity.getRequestResponse()).getParameters()) {
            byte[] decode = CommonStore.helpers.base64Decode(parameter.getValue());
            if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "参数:JWT中存在敏感信息";
                result.risk_param = new String(decode);
                result.fix = "JWT禁止传递敏感信息";
                results.add(result);
                entity.addTag(this.getClass().getSimpleName());
            }
        }
        // 检查请求头
        for (Object value : BurpReqRespTools.getReqHeadersToMap(entity.getRequestResponse()).values()) {
            byte[] decode = CommonStore.helpers.base64Decode(value.toString());
            if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "请求头:JWT中存在敏感信息";
                result.risk_param = new String(decode);
                result.fix = "JWT禁止传递敏感信息";
                results.add(result);
                entity.addTag(this.getClass().getSimpleName());
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
                    public List<ParamKeyValue> handler(Object key, Object value) {
                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"") && isSensitiveKey(new String(decode))) {
                            StaticCheckResult result = new StaticCheckResult();
                            result.desc = "Json参数:JWT中存在敏感信息";
                            result.risk_param = new String(decode);
                            result.fix = "JWT禁止传递敏感信息";
                            results.add(result);
                            entity.addTag(this.getClass().getSimpleName());
                        }
                        paramKeyValues.add(new ParamKeyValue(key, value));
                        return paramKeyValues;
                    }
                });
            } catch (Exception e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }
        if (results.size() > 0) {
            entity.addMap(results);
        }
    }

    /**
     * 判断是否敏感信息的key
     * @param key
     * @return
     */
    public boolean isSensitiveKey(String key){
        if (key.contains("password")
                || key.contains("token")
                || key.contains("phone")) {
            return true;
        }
        return false;
    }
}
