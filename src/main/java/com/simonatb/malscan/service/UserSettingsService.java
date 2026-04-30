package com.simonatb.malscan.service;

import com.simonatb.malscan.entity.UserSettings;
import com.simonatb.malscan.repository.UserSettingsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserSettingsService {

    private final UserSettingsRepository repository;

    public Optional<String> getDownloadDirectory() {
        return repository.findTopByOrderByUpdatedAtDesc()
            .map(UserSettings::getDownloadDirectory);
    }

    public void saveDownloadDirectory(String path) {
        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            throw new IllegalArgumentException("Path doesn't exist or it's not a dir");
        }

        UserSettings settings = repository.findTopByOrderByUpdatedAtDesc()
            .orElse(new UserSettings());

        settings.setDownloadDirectory(path);
        settings.setUpdatedAt(LocalDateTime.now());
        repository.save(settings);

        log.info("Download directory saved: {}", path);
    }

}
