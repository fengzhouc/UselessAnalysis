package com.alumm0x.util;

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
    
}
