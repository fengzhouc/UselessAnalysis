package com.alumm0x.util;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class SourceLoader {

    /**
     * 从classpath下获取文件内容
     * @param filepath 文件路径，相对classpath根目录，如根目录直接文件名即可，如果/api/test.txt则api/test.txt
     * @return List
     */
    public static List<String> loadSources(String filepath){
        List<String> payloads = new ArrayList<>();
        InputStream inStream = SourceLoader.class.getResourceAsStream(filepath);
        assert inStream != null;
        try(Scanner scanner = new Scanner(inStream)){
            while (scanner.hasNextLine()){
                payloads.add(scanner.nextLine());
            }
        }
        return payloads;
    }

    //从resource中加载payloa文件
    //filepath:/com/sss/sss.bb
    public static String loadPayloads(String filepath){
        StringBuilder payloads = new StringBuilder();
        InputStream inStream = SourceLoader.class.getResourceAsStream(filepath);
        assert inStream != null;
        try(Scanner scanner = new Scanner(inStream)){
            while (scanner.hasNextLine()){
                payloads.append(scanner.nextLine()).append("\n");
            }
        }
        return payloads.toString();
    }

    /**
     * 获取resource下的文件，返回其URL对象
     * @param filepath 文件名，相对classpath根目录，如根目录直接文件名即可，如果/api/test.txt则api/test.txt
     * @return URL
     */
    public static URL loadSourceToUrl(String filepath){
        return SourceLoader.class.getClassLoader().getResource(filepath);
    }
}