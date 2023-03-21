package com.alumm0x.util.param.header;

import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * 用于遍历请求头，并进行一些修改或判断是否存在某数据
 * 返回符合burp的请求头List<String>
 */
public class HeaderTools {

    // 保存篡改的json串
    public final List<String> NEW_HEADER; //新的json串

    public HeaderTools(){
        this.NEW_HEADER = new ArrayList<>();
    }

    //修改后还原json字符串
    private void write(String hash){
        this.NEW_HEADER.add(hash);
    }
    /**
     * 遍历query对象，每个值中插入标记
     * @niject 注入的参数
     * */
    public void headerHandler(Map<String, Object> headerMap, ParamHandlerImpl handler) {
        Iterator<Map.Entry<String, Object>> iterator = headerMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Object> entry = iterator.next();
            List<ParamKeyValue> paramKeyValues = handler.handler(entry.getKey(), entry.getValue());
            for (ParamKeyValue paramKeyValue :
                    paramKeyValues) {
                if (!paramKeyValue.isDelete()) {
                    write(String.format("%s:%s", paramKeyValue.getKey(), paramKeyValue.getValue()));
                }
            }
        }
    }

}
