package com.simonatb.malscan.service;

import com.simonatb.malscan.entity.ScanStatus;
import com.simonatb.malscan.repository.ScanResultRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Service
@Slf4j
@RequiredArgsConstructor
public class VirusTotalService {

    @Value("${virustotal.api.key}")
    private String apiKey;

    @Value("${virustotal.api.url}")
    private String apiUrl;

    private final WebClient webClient;
    private final ClamAvService clamAvService;
    private final ScanResultRepository scanResultRepository;

    private final int ATTEMPTS = 10;
    private final int SECONDS = 15;
    private final int BUFFER_SIZE = 8192;

    @Async
    public void scan(File file, Long recordId) {
        try {
            String sha256 = hashFile(file);
            log.info("SHA256 for {}: {}", file.getName(), sha256);

            ScanStatus result = checkByHash(sha256);

            if (result == ScanStatus.UNKNOWN) {
                log.info("Still unknown after VT upload, forwarding to ClamAV: {}", file.getName());
                result = uploadAndWait(file);
            }

            if (result == ScanStatus.UNKNOWN) {
                log.info("Still unknown after VT upload, forwarding to ClamAV: {}", file.getName());
                result = clamAvService.scan(file, recordId);
            }

            updateRecord(recordId, sha256, result, determineEngine(result));
        } catch (Exception e) {
            log.error("Scan failed for {}: {}", file.getName(), e.getMessage(), e);
            updateRecord(recordId, null, ScanStatus.UNKNOWN, "ERROR");
        }
    }

    private ScanStatus checkByHash(String sha256) {
        try {
            String response = webClient.get()
                .uri(apiUrl + "/files/" + sha256)
                .header("x-apikey", apiKey)
                .retrieve()
                .bodyToMono(String.class)
                .block();

            return parseAnalysisResult(response);
        } catch (WebClientResponseException.NotFound e) {
            return ScanStatus.UNKNOWN;
        }
    }

    private ScanStatus uploadAndWait(File file) throws Exception {
        String uploadResponse = webClient.post()
            .uri(apiUrl + "/files")
            .header("x-apikey", apiKey)
            .contentType(MediaType.MULTIPART_FORM_DATA)
            .body(BodyInserters.fromMultipartData(buildMultiPart(file)))
            .retrieve()
            .bodyToMono(String.class)
            .block();

        String analysisId = extractAnalysisId(uploadResponse);

        return pollForResult(analysisId, 0);
    }

    private ScanStatus pollForResult(String analysisId, int attempt) {
        if (attempt >= ATTEMPTS) {
            log.warn("VT analysis timed out after 10 attempts for ID: {}", analysisId);
            return ScanStatus.UNKNOWN;
        }

        return Mono.delay(Duration.ofSeconds(SECONDS))
            .flatMap(tick -> webClient.get()
                .uri(apiUrl + "/analyses/" + analysisId)
                .header("x-apikey", apiKey)
                .retrieve()
                .bodyToMono(String.class))
            .flatMap(response -> {
                if (isAnalysisComplete(response)) {
                    log.debug("VT analysis complete on attempt {}", attempt + 1);
                    return Mono.just(parseAnalysisResult(response));
                }
                log.debug("VT still analyzing... attempt {}/10", attempt + 1);
                return Mono.delay(Duration.ofSeconds(SECONDS))
                    .flatMap(tick -> Mono.just(pollForResult(analysisId, attempt + 1)));
            })
            .block();
    }

    private String hashFile(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream is = new FileInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private MultiValueMap<String, HttpEntity<?>> buildMultiPart(File file) {
        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("file", new FileSystemResource(file));
        return builder.build();
    }

    private String extractAnalysisId(String json) {
        JsonNode root = parseJson(json);
        JsonNode idNode = root.path("data").path("id");

        if (idNode.isMissingNode() || idNode.isNull()) {
            throw new RuntimeException("Analysis ID is missing in VT response: " + json);
        }

        if (!idNode.isString()) {
            throw new RuntimeException("Analysis ID is not a string, got: "
                + idNode.getNodeType() + " in response: " + json);
        }

        String id = idNode.asString();

        if (id == null || id.isBlank()) {
            throw new RuntimeException("Analysis ID is empty in VT response: " + json);
        }

        return id;
    }

    private boolean isAnalysisComplete(String json) {
        JsonNode status = parseJson(json)
            .path("data")
            .path("attributes")
            .path("status");

        if (status.isMissingNode() || !status.isString()) {
            return false;
        }

        return "completed".equals(status.asString());
    }

    private ScanStatus parseAnalysisResult(String json) {
        JsonNode stats = parseJson(json)
            .path("data")
            .path("attributes")
            .path("last_analysis_stats");

        int malicious = stats.path("malicious").asInt(0);
        int suspicious = stats.path("suspicious").asInt(0);
        int undetected = stats.path("undetected").asInt(0);

        if (malicious > 0 || suspicious > 2) return ScanStatus.MALICIOUS;
        if (undetected > 0) return ScanStatus.CLEAN;
        return ScanStatus.UNKNOWN;
    }

    private JsonNode parseJson(String json) {
        try {
            return new ObjectMapper().readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse VT response", e);
        }
    }

    private String determineEngine(ScanStatus status) {
        return status == ScanStatus.CLEAN || status == ScanStatus.MALICIOUS
            ? "VIRUSTOTAL" : "CLAMAV";
    }

    private void updateRecord(Long id, String sha256, ScanStatus status, String engine) {
        scanResultRepository.findById(id).ifPresent(record -> {
            record.setSha256Hash(sha256);
            record.setStatus(status);
            record.setScanEngine(engine);
            record.setScannedAt(LocalDateTime.now());
            scanResultRepository.save(record);
            log.info("Scan complete — file: {}, result: {}", record.getFileName(), status);
        });
    }

}
