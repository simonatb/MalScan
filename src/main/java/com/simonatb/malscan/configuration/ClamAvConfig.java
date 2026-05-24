package com.simonatb.malscan.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "clamav")
@Data
public class ClamAvConfig {
    private String host;
    private int port;
    private int timeout;
}
