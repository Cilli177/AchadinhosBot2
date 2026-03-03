using System;
using TL;
public class Test {
    public static void CheckOut(Message msg) {
        bool isOut = msg.flags.HasFlag(Message.Flags.out_);
    }
}
