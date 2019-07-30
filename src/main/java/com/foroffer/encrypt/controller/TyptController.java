package com.foroffer.encrypt.controller;

import com.foroffer.encrypt.until.CryptUtil;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TyptController {

    @RequestMapping("/test")
    public String test(String data, String sign) throws Exception{
        //data:ede5ffe4724bfd02815e147bcb8578ec19542f1b3fa88a258d0649f3b3a4bd270439dcad2096a203fbb730671aa0afaa02f8185628ed39eb8bb264cd93f77e60c95d2d104bc410a2a8f5bec8f9e5b47fc68c01e68539afc2c32300a6a129e9c9b7fa2d943f423ef9382dc381a4748903b046aae589aced7c235f9cb5f78be482696ae2d03d5c9468addf3c63329cc3a89cc2314751a43c4872b0815afff6c9b11f79c388ad7fcd7d2d750446e46aaae8234235744ae4f79850870a0f085b7883d713c16908e82becaa09ed89b7ecfe70
        //sign:219967020030181a57fb68fc49bae4bf
        System.out.println("data:"+data);
        System.out.println("sign:"+sign);
       return CryptUtil.validMd5(data,"123456",sign)+"";
    }
}
