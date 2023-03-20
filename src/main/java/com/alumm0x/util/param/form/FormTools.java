package com.alumm0x.util.param.form;

import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;

import java.util.Iterator;
import java.util.Map;

/**
 * 用于遍历form表单参数，并进行一些修改或判断是否存在某数据
 */
public class FormTools {

    // 保存篡改的json串
    public final StringBuilder NEW_FORM; //新的json串

    public FormTools(){
        this.NEW_FORM = new StringBuilder();
    }

    //修改后还原json字符串
    private void write(String hash, boolean add){
        if (!add) {
            NEW_FORM.append(hash);
        }else {
            NEW_FORM.append(hash).append("&");
        }
    }
    /**
     * 遍历query对象，每个值中插入标记
     * @niject 注入的参数
     * */
    public void formHandler(Map<String, Object> formMap, ParamHandlerImpl handler) {
        Iterator<Map.Entry<String, Object>> iterator = formMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Object> entry = iterator.next();
            ParamKeyValue paramKeyValue = handler.handler(entry.getKey(), entry.getValue());
            write(String.format("\"%s\"=\"%s\"", paramKeyValue.getKey(), paramKeyValue.getValue()), iterator.hasNext());
        }
    }

}
