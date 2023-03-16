package com.alumm0x.scan;

import com.alumm0x.util.CommonStore;

public class PocEntry {
    public final int id;
    public final String Name;
    public final String Comments;


    public PocEntry(String name, String comments)
    {
        this.id = CommonStore.pocs.size();
        this.Name = name;
        this.Comments = comments;
    }

}
