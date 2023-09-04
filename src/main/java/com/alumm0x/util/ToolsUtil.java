package com.alumm0x.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ToolsUtil {

     /**
     * 检查头部是否包含某信息
     * @return 返回找到的头信息
     */
    public static String hasHdeader(List<String> headers, String header) {
        if (null == headers) {
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).startsWith(header.toLowerCase(Locale.ROOT))) {
                return s;
            }
        }
        return null;
    }

    /**
     * 将原本为list的object转回list
     * @param obj 原本为list的object
     * @param clazz list的存储元素类型
     */
    public static <T> List<T> castList(Object obj, Class<T> clazz){
        List<T> result = new ArrayList<T>();
        if(obj instanceof List<?>){
            for (Object o : (List<?>) obj){
                result.add(clazz.cast(o));
            }
            return result;
        }
        return null;
    }

    /**
     * 检查是否存在，不存在再添加（泛型方法，兼容任何类型）
     * @param list 待添加数据的集合
     * @param add 添加的数据
     */
    public static <T> void notInsideAdd(List<T> list, T add){
        if (!list.contains(add)){
            list.add(add);
        }
    }
}
