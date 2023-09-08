package com.alumm0x.scan.http.task.passive;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;



public class StaticIDOR extends StaticTaskImpl {

    public static String name = "IDOR";
    public static String comments = "识别需测试未授权的场景,一般是检测是否包含会话凭证,测试则是删除会话凭证";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticIDOR(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        //查看是否有会话凭证
        if (entity.credentials.size() != 0) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }
}

