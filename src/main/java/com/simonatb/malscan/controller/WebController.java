package com.simonatb.malscan.controller;

import com.simonatb.malscan.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;

@Controller
@RequiredArgsConstructor
public class WebController {

    private final UserRepository userRepository;

}
