package com.simonatb.malscan.service;

import com.simonatb.malscan.entity.ScanResult;
import com.simonatb.malscan.entity.ScanStatus;
import com.simonatb.malscan.repository.ScanResultRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.LocalDateTime;

@Service
@Slf4j
@RequiredArgsConstructor
public class FileWatcherService implements InitializingBean, DisposableBean {

    private final UserSettingsService userSettingsService;
    private final ScanResultRepository scanResultRepository;

    private WatchService watchService;
    private Thread watchThread;

    @Getter
    private String currentWatchPath;

    @Override
    public void afterPropertiesSet() throws Exception {
        userSettingsService.getDownloadDirectory().ifPresentOrElse(
            path -> {
                try {
                    startWatching(path);
                } catch (Exception e) {
                    log.warn("Could not start watcher on startup: {}", e.getMessage());
                }
            },
            () -> log.info("No download directory set yet — waiting for user to configure.")
        );
    }

    public void stopWatching() {
        if (watchThread != null) {
            watchThread.interrupt();
            watchThread = null;
        }
        if (watchService != null) {
            try {
                watchService.close();
            } catch (Exception ignored) {
                //
            }
            watchService = null;
        }
    }

    public void startWatching(String path) throws Exception {
        stopWatching();

        watchService = FileSystems.getDefault().newWatchService();
        Paths.get(path).register(watchService,
            StandardWatchEventKinds.ENTRY_CREATE,
            StandardWatchEventKinds.ENTRY_MODIFY);

        currentWatchPath = path;
        watchThread = new Thread(() -> runWatcher(path), "file-watcher-thread");
        watchThread.setDaemon(true);
        watchThread.start();

        log.info("Now watching: {}", path);
    }

    private void runWatcher(String watchPath) {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;

                    Path filePath = Paths.get(watchPath).resolve((Path) event.context());

                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                        waitForFileReady(filePath);
                        handleNewFile(filePath);
                    }
                }
                key.reset();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.info("File watcher stopped.");
            }
        }
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private void waitForFileReady(Path filePath) throws InterruptedException {
        long previousSize = -1;
        while (true) {
            Thread.sleep(1000);
            long currentSize = filePath.toFile().length();
            if (currentSize == previousSize && currentSize > 0) break;
            previousSize = currentSize;
        }
    }

    private void handleNewFile(Path filePath) {
        File file = filePath.toFile();
        String name = file.getName();

        if (name.endsWith(".crdownload") || name.endsWith(".part") || name.endsWith(".tmp")) {
            log.debug("Skipping temp file: {}", name);
            return;
        }

        log.info("New file detected: {}", filePath);

        ScanResult pending = new ScanResult();
        pending.setFileName(name);
        pending.setFilePath(filePath.toString());
        pending.setStatus(ScanStatus.PENDING);
        pending.setScannedAt(LocalDateTime.now());
        scanResultRepository.save(pending);

        //virusTotalService.scan(file, pending.getId());
    }

    @Override
    public void destroy() throws Exception {
        stopWatching();
    }

}
