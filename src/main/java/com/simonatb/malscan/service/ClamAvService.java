package com.simonatb.malscan.service;

import com.simonatb.malscan.configuration.ClamAvConfig;
import com.simonatb.malscan.entity.ScanStatus;
import com.simonatb.malscan.repository.ScanResultRepository;
import fi.solita.clamav.ClamAVClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class ClamAvService {

    private final ClamAvConfig config;
    private final ScanResultRepository scanResultRepository;

    public ScanStatus scan(File file, Long recordId) {
        log.info("Sending to ClamAV: {}", file.getName());

        if (!isPingSuccessful()) {
            log.error("ClamAV is not reachable at {}:{}", config.getHost(), config.getPort());
            updateRecord(recordId, ScanStatus.UNKNOWN, "ClamAV unreachable");
            return ScanStatus.UNKNOWN;
        }

        try {
            ClamAVClient client = new ClamAVClient(
                config.getHost(),
                config.getPort(),
                config.getTimeout()
            );

            byte[] response;
            try (InputStream is = new FileInputStream(file)) {
                response = client.scan(is);
            }

            return interpretResult(response, file.getName(), recordId);

        } catch (Exception e) {
            log.error("ClamAV scan failed for {}: {}", file.getName(), e.getMessage(), e);
            updateRecord(recordId, ScanStatus.UNKNOWN, "ClamAV error: " + e.getMessage());
            return ScanStatus.UNKNOWN;
        }
    }

    public boolean isPingSuccessful() {
        try {
            ClamAVClient client = new ClamAVClient(
                config.getHost(),
                config.getPort(),
                config.getTimeout()
            );
            return client.ping();
        } catch (Exception e) {
            log.warn("ClamAV ping failed: {}", e.getMessage());
            return false;
        }
    }

    private ScanStatus interpretResult(byte[] response, String filename, Long recordId) {
        if (ClamAVClient.isCleanReply(response)) {
            log.info("ClamAV: CLEAN — {}", filename);
            updateRecord(recordId, ScanStatus.CLEAN, "ClamAV: OK");
            return ScanStatus.CLEAN;
        }

        String responseText = new String(response).trim();
        log.warn("ClamAV: MALICIOUS — {} — {}", filename, responseText);
        updateRecord(recordId, ScanStatus.MALICIOUS, "ClamAV: " + responseText);
        return ScanStatus.MALICIOUS;
    }

    private void updateRecord(Long recordId, ScanStatus status, String details) {
        scanResultRepository.findById(recordId).ifPresent(record -> {
            record.setStatus(status);
            record.setScanEngine("CLAMAV");
            record.setDetails(details);
            record.setScannedAt(LocalDateTime.now());
            scanResultRepository.save(record);
        });
    }

}
