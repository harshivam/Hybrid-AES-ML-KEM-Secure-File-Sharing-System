package com.project.fileshare.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Spring MVC View Controller mapping frontend routes to static HTML views.
 */
@Controller
public class ViewController {

    @GetMapping("/")
    public String index() {
        return "forward:/index.html";
    }

    @GetMapping("/upload")
    public String uploadPage() {
        return "forward:/index.html";
    }

    @GetMapping("/download")
    public String downloadPage() {
        return "forward:/download.html";
    }
}
