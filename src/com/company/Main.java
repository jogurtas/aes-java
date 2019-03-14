package com.company;

public class Main {
    public static void main(String[] args) {
        String key = "Thats my Kung Fu";
        String text = "Two One Nine Two";

        System.out.println(Aes.encrypt(key, text));
        System.out.println(Aes.decrypt(key, "29 c3 50 5f 57 14 20 f6 40 22 99 b3 1a 02 d7 3a"));
    }
}
