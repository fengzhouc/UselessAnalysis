package com.alumm0x.scan.http.task.passive;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;

import burp.IHttpRequestResponse;
import burp.IParameter;



public class StaticIsJWT extends StaticTaskImpl {

    public static String name = "IsJWT";
    public static String comments = "识别使用JWT的接口";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticIsJWT(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 是否使用jwt
        if (isJWT(entity.getRequestResponse())){
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 检测是否使用jwt
     */
    public static boolean isJWT(IHttpRequestResponse requestResponse) {
        // 检查请求的参数，使用burp解析的，包含如下:查询参数/cookie/form参数
        for (IParameter parameter : CommonStore.helpers.analyzeRequest(requestResponse).getParameters()) {
            byte[] decode = CommonStore.helpers.base64Decode(parameter.getValue());
            if (new String(decode).contains("\"alg\"")) {
                return true;
            }
        }
        // 检查请求头
        for (Object value : BurpReqRespTools.getReqHeadersToMap(requestResponse).values()) {
            byte[] decode = CommonStore.helpers.base64Decode(value.toString());
            if (new String(decode).contains("\"alg\"")) {
                return true;
            }
        }
        // 检查json数据
        if (BurpReqRespTools.getContentType(requestResponse).contains("application/json")
                && BurpReqRespTools.getReqBody(requestResponse).length > 0
                && new String(BurpReqRespTools.getReqBody(requestResponse)).startsWith("{")){
            JsonTools tools = new JsonTools();
            try {
                tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(requestResponse))), new ParamHandlerImpl() {
                    @Override
                    public List<ParamKeyValue> handler(Object key, Object value) {
                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"")) {
                            paramKeyValues.add(null); //匹配条件则返回bull，触发上层函数的空指针异常已反馈结果
                        } else {
                            paramKeyValues.add(new ParamKeyValue(key, value));
                        }
                        return paramKeyValues;
                    }
                });
            } catch (NullPointerException e) {
                // 出现空指针则说明匹配到条件
                return true;
            }
        }
        return false;
    }
}

