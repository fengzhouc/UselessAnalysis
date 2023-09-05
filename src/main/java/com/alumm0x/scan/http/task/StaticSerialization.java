package com.alumm0x.scan.http.task;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;


public class StaticSerialization extends StaticTaskImpl {

    public static String name = "Serialization";
    public static String comments = "识别反序列化数据,识别可能的反序列化场景";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticSerialization(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        //看请求的contenttype，常规业务请求的返回数据类型json/xml，对应contenttype
        // json/xml可能存在反序列化，需要重点关注
        // 所以打个标签，后续好验证
        if (BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0) {
            // 检查请求体的内容
            if (new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("{") 
            || new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("[")) {
                entity.addTag("json");
            }
            String ct = BurpReqRespTools.getContentType(entity.getRequestResponse());
            if (ct != null && ct.contains("xml")) {
                entity.addTag("xml");
            }
        }
    }
}

