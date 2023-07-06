package com.moaydogdu.ssrefreshtokenexample.security.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/stock")
public class StockController {

    @GetMapping
    public String get(){
        return "GET:: stock controller";
    }

    @PostMapping
    public String post(){
        return "POST:: stock controller";
    }

    @PutMapping
    public String put(){
        return "PUT:: stock controller";
    }

    @DeleteMapping
    public String delete(){
        return "DELETE:: stock controller";
    }
}
